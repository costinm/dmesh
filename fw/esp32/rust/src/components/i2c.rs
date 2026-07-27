use anyhow::{anyhow, bail, Result};
use esp_idf_sys as sys;

use crate::commands::{CommandHandler, CommandRegistry, CommandRequest, CommandResponse};

use super::settings::{parse_i32, SharedSettings};

#[derive(Clone, Debug)]
struct I2cState {
    port: i32,
    sda: i32,
    scl: i32,
    frequency: i32,
}

impl Default for I2cState {
    fn default() -> Self {
        Self {
            port: 0,
            sda: 21,
            scl: 22,
            frequency: 100_000,
        }
    }
}

impl I2cState {
    fn load(settings: &SharedSettings) -> Result<Self> {
        let defaults = Self::default();
        let settings = settings.borrow();
        Ok(Self {
            port: settings.get_i32("i2c.port", defaults.port)?,
            sda: settings.get_i32("i2c.sda", defaults.sda)?,
            scl: settings.get_i32("i2c.scl", defaults.scl)?,
            frequency: settings.get_i32("i2c.freq", defaults.frequency)?,
        })
    }

    fn port_id(&self) -> Result<sys::i2c_port_t> {
        match self.port {
            0 => Ok(sys::i2c_port_t_I2C_NUM_0),
            1 => Ok(sys::i2c_port_t_I2C_NUM_1),
            _ => bail!("invalid I2C port {}", self.port),
        }
    }
}

struct I2cCommand {
    name: &'static str,
    settings: SharedSettings,
}

impl I2cCommand {
    fn new(name: &'static str, settings: SharedSettings) -> Self {
        Self { name, settings }
    }
}

pub fn register_commands(registry: &mut CommandRegistry, settings: SharedSettings) {
    registry.register(I2cCommand::new("i2cconfig", settings.clone()));
    registry.register(I2cCommand::new("i2cprobe", settings.clone()));
    registry.register(I2cCommand::new("i2cdetect", settings.clone()));
    registry.register(I2cCommand::new("i2cget", settings.clone()));
    registry.register(I2cCommand::new("i2cset", settings.clone()));
    registry.register(I2cCommand::new("i2cdump", settings));
}

impl CommandHandler for I2cCommand {
    fn name(&self) -> &'static str {
        self.name
    }

    fn handle(&mut self, request: &CommandRequest) -> Result<CommandResponse> {
        match self.name {
            "i2cconfig" => self.configure(request),
            "i2cprobe" => self.probe(request),
            "i2cdetect" => self.detect(),
            "i2cget" => self.get(request),
            "i2cset" => self.set(request),
            "i2cdump" => self.dump(request),
            _ => Ok(CommandResponse::error("invalid i2c command")),
        }
    }
}

impl I2cCommand {
    fn configure(&mut self, request: &CommandRequest) -> Result<CommandResponse> {
        let mut state = I2cState::load(&self.settings)?;
        if let Some(port) = request.arg_i32("port")? {
            state.port = port;
            self.settings.borrow_mut().set_i32("i2c.port", port)?;
        }
        if let Some(sda) = request.arg_i32("sda")? {
            validate_pin(sda)?;
            state.sda = sda;
            self.settings.borrow_mut().set_i32("i2c.sda", sda)?;
        }
        if let Some(scl) = request.arg_i32("scl")? {
            validate_pin(scl)?;
            state.scl = scl;
            self.settings.borrow_mut().set_i32("i2c.scl", scl)?;
        }
        if let Some(freq) = request.arg_i32("freq")? {
            state.frequency = freq;
            self.settings.borrow_mut().set_i32("i2c.freq", freq)?;
        }

        Ok(CommandResponse::ok(format!(
            "i2c port={} sda={} scl={} freq={}",
            state.port, state.sda, state.scl, state.frequency
        )))
    }

    fn probe(&mut self, request: &CommandRequest) -> Result<CommandResponse> {
        let state = I2cState::load(&self.settings)?;
        let sda_candidates = parse_pin_list(request.arg("sda"), state.sda)?;
        let scl_candidates = parse_pin_list(request.arg("scl"), state.scl)?;
        let addr = parse_arg_or(request, "addr", 0x3c)?;
        let save = request
            .arg("save")
            .map(super::settings::parse_bool)
            .transpose()?
            .unwrap_or(false);

        let mut attempts = Vec::new();
        for sda in &sda_candidates {
            for scl in &scl_candidates {
                if sda == scl {
                    continue;
                }
                let candidate = I2cState {
                    sda: *sda,
                    scl: *scl,
                    ..state.clone()
                };
                let result =
                    match with_i2c(&candidate, || i2c_ack(candidate.port_id()?, addr as u8)) {
                        Ok(true) => "ready".to_string(),
                        Ok(false) => "no-ack".to_string(),
                        Err(err) => format!("err:{err}"),
                    };
                attempts.push(format!("sda={sda},scl={scl}:{result}"));
                if result == "ready" && save {
                    self.settings.borrow_mut().set_i32("i2c.sda", *sda)?;
                    self.settings.borrow_mut().set_i32("i2c.scl", *scl)?;
                    return Ok(CommandResponse::ok(format!(
                        "i2c probe matched addr=0x{addr:02x} sda={sda} scl={scl} saved=true"
                    )));
                }
            }
        }

        Ok(CommandResponse::ok(format!(
            "i2c probe addr=0x{addr:02x} {}",
            attempts.join(" ")
        )))
    }

    fn detect(&mut self) -> Result<CommandResponse> {
        let state = I2cState::load(&self.settings)?;
        let mut found = Vec::new();
        with_i2c(&state, || {
            let port = state.port_id()?;
            for addr in 0x03_u8..=0x77 {
                if i2c_ack(port, addr)? {
                    found.push(format!("0x{addr:02x}"));
                }
            }
            Ok(())
        })?;
        Ok(CommandResponse::ok(format!(
            "i2cdetect port={} sda={} scl={} found={}",
            state.port,
            state.sda,
            state.scl,
            if found.is_empty() {
                "none".to_string()
            } else {
                found.join(",")
            }
        )))
    }

    fn get(&mut self, request: &CommandRequest) -> Result<CommandResponse> {
        let state = I2cState::load(&self.settings)?;
        let chip = parse_arg_or(request, "chip", parse_arg_or(request, "c", 0x3c)?)? as u8;
        let register = request
            .arg("register")
            .or_else(|| request.arg("r"))
            .map(parse_i32)
            .transpose()?;
        let len = parse_arg_or(request, "length", parse_arg_or(request, "l", 1)?)?.clamp(1, 128);
        let mut data = vec![0_u8; len as usize];
        with_i2c(&state, || {
            let port = state.port_id()?;
            let ret = unsafe {
                match register {
                    Some(reg) => {
                        let reg = reg as u8;
                        sys::i2c_master_write_read_device(
                            port,
                            chip,
                            &reg,
                            1,
                            data.as_mut_ptr(),
                            data.len(),
                            ticks(1000),
                        )
                    }
                    None => sys::i2c_master_read_from_device(
                        port,
                        chip,
                        data.as_mut_ptr(),
                        data.len(),
                        ticks(1000),
                    ),
                }
            };
            esp_ok(ret)
        })?;
        Ok(CommandResponse::ok(format!("i2cget {}", hex_bytes(&data))))
    }

    fn set(&mut self, request: &CommandRequest) -> Result<CommandResponse> {
        let state = I2cState::load(&self.settings)?;
        let chip = parse_arg_or(request, "chip", parse_arg_or(request, "c", 0x3c)?)? as u8;
        let mut bytes = Vec::new();
        if let Some(reg) = request.arg("register").or_else(|| request.arg("r")) {
            bytes.push(parse_i32(reg)? as u8);
        }
        if let Some(data) = request.arg("data").or_else(|| request.arg("d")) {
            bytes.extend(parse_bytes(data)?);
        }
        if let Some(payload) = request.arg("payload") {
            bytes.extend(parse_bytes(payload)?);
        }
        if bytes.is_empty() {
            bail!("i2cset requires data=hex:... or payload=hex:...");
        }
        with_i2c(&state, || {
            let ret = unsafe {
                sys::i2c_master_write_to_device(
                    state.port_id()?,
                    chip,
                    bytes.as_ptr(),
                    bytes.len(),
                    ticks(1000),
                )
            };
            esp_ok(ret)
        })?;
        Ok(CommandResponse::ok(format!("i2cset wrote={}", bytes.len())))
    }

    fn dump(&mut self, request: &CommandRequest) -> Result<CommandResponse> {
        let chip = parse_arg_or(request, "chip", parse_arg_or(request, "c", 0x3c)?)?;
        let mut rows = Vec::new();
        for base in (0..=0x70).step_by(0x10) {
            let req = CommandRequest::new("i2cget")
                .arg_pair("chip", chip.to_string())
                .arg_pair("register", base.to_string())
                .arg_pair("length", "16");
            rows.push(self.get(&req)?.message);
        }
        Ok(CommandResponse::ok(rows.join(" | ")))
    }
}

fn with_i2c<T>(state: &I2cState, f: impl FnOnce() -> Result<T>) -> Result<T> {
    let port = state.port_id()?;
    let mut conf = sys::i2c_config_t::default();
    conf.mode = sys::i2c_mode_t_I2C_MODE_MASTER;
    conf.sda_io_num = state.sda;
    conf.scl_io_num = state.scl;
    conf.sda_pullup_en = true;
    conf.scl_pullup_en = true;
    conf.__bindgen_anon_1.master.clk_speed = state.frequency.max(10_000) as u32;
    unsafe {
        let _ = sys::i2c_driver_delete(port);
        esp_ok(sys::i2c_param_config(port, &conf))?;
        esp_ok(sys::i2c_driver_install(port, conf.mode, 0, 0, 0))?;
    }
    let result = f();
    unsafe {
        let _ = sys::i2c_driver_delete(port);
    }
    result
}

fn i2c_ack(port: sys::i2c_port_t, addr: u8) -> Result<bool> {
    let cmd = unsafe { sys::i2c_cmd_link_create() };
    if cmd.is_null() {
        bail!("i2c command allocation failed");
    }
    let ret = unsafe {
        sys::i2c_master_start(cmd);
        sys::i2c_master_write_byte(cmd, addr << 1, true);
        sys::i2c_master_stop(cmd);
        let ret = sys::i2c_master_cmd_begin(port, cmd, ticks(50));
        sys::i2c_cmd_link_delete(cmd);
        ret
    };
    Ok(ret == sys::ESP_OK)
}

fn parse_pin_list(value: Option<&str>, default: i32) -> Result<Vec<i32>> {
    match value {
        Some(value) => value
            .split(',')
            .map(|pin| {
                let pin = parse_i32(pin.trim())?;
                validate_pin(pin)?;
                Ok(pin)
            })
            .collect(),
        None => Ok(vec![default]),
    }
}

fn parse_arg_or(request: &CommandRequest, key: &str, default: i32) -> Result<i32> {
    request
        .arg(key)
        .map(parse_i32)
        .transpose()
        .map(|v| v.unwrap_or(default))
}

fn parse_bytes(value: &str) -> Result<Vec<u8>> {
    let value = value.strip_prefix("hex:").unwrap_or(value);
    if value.contains(',') {
        return value
            .split(',')
            .map(|v| Ok(parse_i32(v.trim())? as u8))
            .collect();
    }
    if value.len() % 2 != 0 {
        bail!("hex byte string must have even length");
    }
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).map_err(Into::into))
        .collect()
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join("")
}

fn validate_pin(pin: i32) -> Result<()> {
    if !(0..=39).contains(&pin) {
        return Err(anyhow!("invalid ESP32 GPIO pin {pin}"));
    }
    Ok(())
}

fn ticks(ms: u32) -> sys::TickType_t {
    (ms / 10).max(1) as sys::TickType_t
}

fn esp_ok(ret: sys::esp_err_t) -> Result<()> {
    if ret == sys::ESP_OK {
        Ok(())
    } else {
        bail!("esp_err=0x{ret:x}")
    }
}
