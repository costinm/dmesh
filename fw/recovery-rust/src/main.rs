use std::ffi::{c_char, CStr, CString};
use std::net::Ipv4Addr;
use std::os::raw::{c_int, c_void};
use std::ptr;
use std::time::{Duration, Instant};

use esp_idf_sys as sys;

const TAG: &[u8] = b"dmesh-recovery-rs\0";
const NVS_NAMESPACE: &str = "recovery";
const DEFAULT_PORT: u16 = 3333;
const MAX_IMAGE_SIZE: u32 = 3 * 1024 * 1024;
const STREAM_MAGIC: u32 = 0x4452_5331; // DRS1
const BUFFER_SIZE: usize = 4096;

#[derive(Default)]
struct Config {
    ssid: String,
    password: String,
    server: String,
    local_ip: String,
    port: u16,
}

fn log(message: &str) {
    if let Ok(message) = CString::new(message) {
        unsafe {
            sys::esp_log_write(
                sys::esp_log_level_t_ESP_LOG_INFO,
                TAG.as_ptr().cast(),
                message.as_ptr(),
            )
        };
    }
}

fn error_name(error: sys::esp_err_t) -> String {
    unsafe {
        let ptr = sys::esp_err_to_name(error);
        if ptr.is_null() {
            format!("0x{error:x}")
        } else {
            CStr::from_ptr(ptr).to_string_lossy().into_owned()
        }
    }
}

fn esp_ok(error: sys::esp_err_t, operation: &str) -> Result<(), String> {
    if error == sys::ESP_OK {
        Ok(())
    } else {
        Err(format!("{operation} failed: {}", error_name(error)))
    }
}

fn copy_c_string<const N: usize>(destination: &mut [c_char; N], value: &str) {
    destination.fill(0);
    for (slot, byte) in destination.iter_mut().zip(value.as_bytes().iter().copied()) {
        if byte == 0 {
            break;
        }
        *slot = byte as c_char;
    }
}

unsafe fn nvs_open_readonly() -> Result<sys::nvs_handle_t, String> {
    let namespace = CString::new(NVS_NAMESPACE).unwrap();
    let mut handle = 0;
    esp_ok(
        sys::nvs_open(
            namespace.as_ptr(),
            sys::nvs_open_mode_t_NVS_READONLY,
            &mut handle,
        ),
        "nvs_open",
    )?;
    Ok(handle)
}

unsafe fn nvs_string(handle: sys::nvs_handle_t, key: &str, max: usize) -> Option<String> {
    let key = CString::new(key).ok()?;
    let mut buffer = vec![0u8; max];
    let mut length = buffer.len();
    if sys::nvs_get_str(
        handle,
        key.as_ptr(),
        buffer.as_mut_ptr() as *mut c_char,
        &mut length,
    ) != sys::ESP_OK
    {
        return None;
    }
    buffer.truncate(length.saturating_sub(1));
    String::from_utf8(buffer).ok()
}

unsafe fn trust_key_present() -> bool {
    let Ok(handle) = nvs_open_readonly() else {
        return false;
    };
    let key = CString::new("trust_key").unwrap();
    let mut length = 0usize;
    let present = sys::nvs_get_blob(handle, key.as_ptr(), ptr::null_mut(), &mut length)
        == sys::ESP_OK
        && length != 0;
    sys::nvs_close(handle);
    present
}

fn load_config() -> Config {
    let mut config = Config {
        port: DEFAULT_PORT,
        ..Config::default()
    };
    unsafe {
        let Ok(handle) = nvs_open_readonly() else {
            log("NVS namespace unavailable");
            return config;
        };
        config.ssid = nvs_string(handle, "ssid", 33).unwrap_or_default();
        config.password = nvs_string(handle, "password", 65).unwrap_or_default();
        config.server = nvs_string(handle, "server", 128).unwrap_or_default();
        config.local_ip = nvs_string(handle, "ip", 32).unwrap_or_default();
        let mut port = 0u16;
        let key = CString::new("port").unwrap();
        if sys::nvs_get_u16(handle, key.as_ptr(), &mut port) == sys::ESP_OK && port != 0 {
            config.port = port;
        }
        sys::nvs_close(handle);
    }
    log(&format!(
        "nvs ssid={} server={} ip={} port={}",
        config.ssid, config.server, config.local_ip, config.port
    ));
    config
}

fn read_uart_override(config: &mut Config) {
    unsafe {
        if sys::uart_is_driver_installed(sys::uart_port_t_UART_NUM_0) {
            return;
        }
        let uart_config = sys::uart_config_t {
            baud_rate: 115200,
            data_bits: sys::uart_word_length_t_UART_DATA_8_BITS,
            parity: sys::uart_parity_t_UART_PARITY_DISABLE,
            stop_bits: sys::uart_stop_bits_t_UART_STOP_BITS_1,
            flow_ctrl: sys::uart_hw_flowcontrol_t_UART_HW_FLOWCTRL_DISABLE,
            rx_flow_ctrl_thresh: 0,
            __bindgen_anon_1: sys::uart_config_t__bindgen_ty_1::default(),
            flags: sys::uart_config_t__bindgen_ty_2::default(),
        };
        if sys::uart_param_config(sys::uart_port_t_UART_NUM_0, &uart_config) != sys::ESP_OK
            || sys::uart_driver_install(sys::uart_port_t_UART_NUM_0, 512, 0, 0, ptr::null_mut(), 0)
                != sys::ESP_OK
        {
            return;
        }
        let mut input = [0u8; 256];
        let length = sys::uart_read_bytes(
            sys::uart_port_t_UART_NUM_0,
            input.as_mut_ptr().cast(),
            (input.len() - 1) as u32,
            500,
        );
        if length <= 0 {
            return;
        }
        let input = String::from_utf8_lossy(&input[..length as usize]);
        let mut fields = input.split_whitespace();
        if fields.next() != Some("RECOVER") {
            return;
        }
        let Some(endpoint) = fields.next() else {
            return;
        };
        let Some(local_ip) = fields.next() else {
            return;
        };
        let Some(ssid) = fields.next() else { return };
        let (server, port) = endpoint
            .rsplit_once(':')
            .and_then(|(host, port)| port.parse::<u16>().ok().map(|port| (host, port)))
            .unwrap_or((endpoint, DEFAULT_PORT));
        config.server = server.to_owned();
        config.port = port;
        config.local_ip = local_ip.to_owned();
        config.ssid = ssid.to_owned();
        config.password = fields.next().unwrap_or_default().to_owned();
        log(&format!(
            "UART override server={} port={} ssid={}",
            server, port, ssid
        ));
    }
}

fn start_network(config: &Config) -> Result<(), String> {
    unsafe {
        esp_ok(sys::esp_netif_init(), "esp_netif_init")?;
        let event_loop = sys::esp_event_loop_create_default();
        if event_loop != sys::ESP_OK && event_loop != sys::ESP_ERR_INVALID_STATE {
            return Err(format!("event loop failed: {}", error_name(event_loop)));
        }
        let mut wifi_init = wifi_init_config_default();
        esp_ok(sys::esp_wifi_init(&mut wifi_init), "esp_wifi_init")?;
        esp_ok(
            sys::esp_wifi_set_storage(sys::wifi_storage_t_WIFI_STORAGE_RAM),
            "esp_wifi_set_storage",
        )?;

        if config.ssid.is_empty() {
            let netif = sys::esp_netif_create_default_wifi_ap();
            if netif.is_null() {
                return Err("AP netif creation failed".into());
            }
            let mut mac = [0u8; 6];
            esp_ok(
                sys::esp_read_mac(mac.as_mut_ptr(), sys::esp_mac_type_t_ESP_MAC_WIFI_SOFTAP),
                "esp_read_mac",
            )?;
            let ssid = format!("ESP32S3_8_BOOT_{:02X}{:02X}", mac[4], mac[5]);
            let mut ap = sys::wifi_ap_config_t::default();
            copy_c_string(&mut ap.ssid, &ssid);
            ap.ssid_len = ssid.len().min(ap.ssid.len()) as u8;
            ap.channel = 6;
            ap.max_connection = 1;
            ap.authmode = sys::wifi_auth_mode_t_WIFI_AUTH_OPEN;
            let mut wifi = sys::wifi_config_t { ap };
            esp_ok(
                sys::esp_wifi_set_mode(sys::wifi_mode_t_WIFI_MODE_AP),
                "esp_wifi_set_mode(AP)",
            )?;
            esp_ok(
                sys::esp_wifi_set_config(sys::wifi_interface_t_WIFI_IF_AP, &mut wifi),
                "esp_wifi_set_config(AP)",
            )?;
            esp_ok(sys::esp_wifi_start(), "esp_wifi_start(AP)")?;
            log(&format!("network AP ssid={} ip=192.168.4.1", ssid));
        } else {
            let netif = sys::esp_netif_create_default_wifi_sta();
            if netif.is_null() {
                return Err("STA netif creation failed".into());
            }
            let mut sta = sys::wifi_sta_config_t::default();
            copy_c_string(&mut sta.ssid, &config.ssid);
            copy_c_string(&mut sta.password, &config.password);
            sta.channel = 0;
            sta.threshold.authmode = if config.password.is_empty() {
                sys::wifi_auth_mode_t_WIFI_AUTH_OPEN
            } else {
                sys::wifi_auth_mode_t_WIFI_AUTH_WPA2_PSK
            };
            let mut wifi = sys::wifi_config_t { sta };
            esp_ok(
                sys::esp_wifi_set_mode(sys::wifi_mode_t_WIFI_MODE_STA),
                "esp_wifi_set_mode(STA)",
            )?;
            esp_ok(
                sys::esp_wifi_set_config(sys::wifi_interface_t_WIFI_IF_STA, &mut wifi),
                "esp_wifi_set_config(STA)",
            )?;
            if !config.local_ip.is_empty() {
                let ip = parse_ipv4(&config.local_ip)?;
                let mut info = sys::esp_netif_ip_info_t::default();
                info.ip.addr = ip;
                info.gw.addr = parse_ipv4("10.78.0.1")?;
                info.netmask.addr = parse_ipv4("255.255.255.0")?;
                esp_ok(sys::esp_netif_dhcpc_stop(netif), "esp_netif_dhcpc_stop")?;
                esp_ok(
                    sys::esp_netif_set_ip_info(netif, &info),
                    "esp_netif_set_ip_info",
                )?;
            }
            esp_ok(sys::esp_wifi_start(), "esp_wifi_start(STA)")?;
            esp_ok(sys::esp_wifi_connect(), "esp_wifi_connect")?;
            let deadline = Instant::now() + Duration::from_secs(15);
            loop {
                let mut ap = sys::wifi_ap_record_t::default();
                let mut ip = sys::esp_netif_ip_info_t::default();
                if sys::esp_wifi_sta_get_ap_info(&mut ap) == sys::ESP_OK
                    && sys::esp_netif_get_ip_info(netif, &mut ip) == sys::ESP_OK
                    && ip.ip.addr != 0
                {
                    log("STA associated and has an IP address");
                    break;
                }
                if Instant::now() >= deadline {
                    return Err("STA association/IP timeout".into());
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
    Ok(())
}

fn wifi_init_config_default() -> sys::wifi_init_config_t {
    sys::wifi_init_config_t {
        osi_funcs: std::ptr::addr_of_mut!(sys::g_wifi_osi_funcs),
        wpa_crypto_funcs: unsafe { sys::g_wifi_default_wpa_crypto_funcs },
        static_rx_buf_num: sys::CONFIG_ESP_WIFI_STATIC_RX_BUFFER_NUM as i32,
        dynamic_rx_buf_num: sys::CONFIG_ESP_WIFI_DYNAMIC_RX_BUFFER_NUM as i32,
        tx_buf_type: sys::CONFIG_ESP_WIFI_TX_BUFFER_TYPE as i32,
        static_tx_buf_num: sys::WIFI_STATIC_TX_BUFFER_NUM as i32,
        dynamic_tx_buf_num: sys::WIFI_DYNAMIC_TX_BUFFER_NUM as i32,
        rx_mgmt_buf_type: sys::CONFIG_ESP_WIFI_DYNAMIC_RX_MGMT_BUF as i32,
        rx_mgmt_buf_num: sys::WIFI_RX_MGMT_BUF_NUM_DEF as i32,
        cache_tx_buf_num: sys::WIFI_CACHE_TX_BUFFER_NUM as i32,
        csi_enable: sys::WIFI_CSI_ENABLED as i32,
        ampdu_rx_enable: sys::WIFI_AMPDU_RX_ENABLED as i32,
        ampdu_tx_enable: sys::WIFI_AMPDU_TX_ENABLED as i32,
        amsdu_tx_enable: sys::WIFI_AMSDU_TX_ENABLED as i32,
        nvs_enable: sys::WIFI_NVS_ENABLED as i32,
        nano_enable: sys::WIFI_NANO_FORMAT_ENABLED as i32,
        rx_ba_win: sys::WIFI_DEFAULT_RX_BA_WIN as i32,
        wifi_task_core_id: sys::WIFI_TASK_CORE_ID as i32,
        beacon_max_len: sys::WIFI_SOFTAP_BEACON_MAX_LEN as i32,
        mgmt_sbuf_num: sys::WIFI_MGMT_SBUF_NUM as i32,
        feature_caps: sys::WIFI_FEATURE_CAPS as u64,
        sta_disconnected_pm: sys::WIFI_STA_DISCONNECTED_PM_ENABLED != 0,
        espnow_max_encrypt_num: sys::CONFIG_ESP_WIFI_ESPNOW_MAX_ENCRYPT_NUM as i32,
        tx_hetb_queue_num: sys::WIFI_TX_HETB_QUEUE_NUM as i32,
        dump_hesigb_enable: sys::WIFI_DUMP_HESIGB_ENABLED != 0,
        magic: sys::WIFI_INIT_CONFIG_MAGIC as i32,
    }
}

fn parse_ipv4(value: &str) -> Result<u32, String> {
    let address = value
        .parse::<Ipv4Addr>()
        .map_err(|error| format!("invalid IPv4 address {value}: {error}"))?;
    // ESP-IDF's esp_ip4_addr_t and lwIP sockaddr fields store the address in
    // network byte order in memory, which is represented as a native-endian
    // integer by these C bindings.
    Ok(u32::from_ne_bytes(address.octets()))
}

fn connect_remote(config: &Config) -> Result<c_int, String> {
    let address = format!("{}:{}", config.server, config.port);
    let ip = config
        .server
        .parse::<Ipv4Addr>()
        .map_err(|error| format!("server must be an IPv4 address: {address}: {error}"))?;
    unsafe {
        let remote = libc::sockaddr_in {
            sin_len: std::mem::size_of::<libc::sockaddr_in>() as u8,
            sin_family: libc::AF_INET as u8,
            sin_port: config.port.to_be(),
            sin_addr: libc::in_addr {
                s_addr: u32::from_ne_bytes(ip.octets()),
            },
            sin_zero: [0; 8],
        };
        let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, libc::IPPROTO_IP);
        let connected = fd >= 0
            && libc::connect(
                fd,
                (&remote as *const libc::sockaddr_in).cast(),
                std::mem::size_of_val(&remote) as libc::socklen_t,
            ) == 0;
        if connected {
            Ok(fd)
        } else {
            if fd >= 0 {
                libc::close(fd);
            }
            Err(format!(
                "connect {address}: {}",
                std::io::Error::last_os_error()
            ))
        }
    }
}

fn accept_client(config: &Config) -> Result<c_int, String> {
    unsafe {
        let listener = libc::socket(libc::AF_INET, libc::SOCK_STREAM, libc::IPPROTO_IP);
        if listener < 0 {
            return Err(format!("socket: {}", std::io::Error::last_os_error()));
        }
        let one: c_int = 1;
        libc::setsockopt(
            listener,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            (&one as *const c_int).cast(),
            std::mem::size_of_val(&one) as libc::socklen_t,
        );
        let address = libc::sockaddr_in {
            sin_len: std::mem::size_of::<libc::sockaddr_in>() as u8,
            sin_family: libc::AF_INET as u8,
            sin_port: config.port.to_be(),
            sin_addr: libc::in_addr { s_addr: 0 },
            sin_zero: [0; 8],
        };
        let listening = libc::bind(
            listener,
            (&address as *const libc::sockaddr_in).cast(),
            std::mem::size_of_val(&address) as libc::socklen_t,
        ) == 0
            && libc::listen(listener, 1) == 0;
        if !listening {
            let error = std::io::Error::last_os_error();
            libc::close(listener);
            return Err(format!("listen on {}: {error}", config.port));
        }
        log(&format!("TCP server listening on port {}", config.port));
        let client = libc::accept(listener, ptr::null_mut(), ptr::null_mut());
        libc::close(listener);
        if client < 0 {
            Err(format!("accept: {}", std::io::Error::last_os_error()))
        } else {
            Ok(client)
        }
    }
}

fn read_exact(fd: c_int, buffer: &mut [u8]) -> Result<(), String> {
    let mut offset = 0;
    while offset < buffer.len() {
        let count = unsafe {
            libc::recv(
                fd,
                buffer[offset..].as_mut_ptr().cast::<c_void>(),
                buffer.len() - offset,
                0,
            )
        };
        if count <= 0 {
            return Err(format!(
                "short TCP stream offset={} want={} error={}",
                offset,
                buffer.len(),
                std::io::Error::last_os_error()
            ));
        }
        offset += count as usize;
    }
    Ok(())
}

fn receive_image(fd: c_int) -> Result<(), String> {
    let mut header = [0u8; 12];
    read_exact(fd, &mut header)?;
    let magic = u32::from_be_bytes(header[0..4].try_into().unwrap());
    let target = u32::from_be_bytes(header[4..8].try_into().unwrap());
    let size = u32::from_be_bytes(header[8..12].try_into().unwrap());
    if magic != STREAM_MAGIC || target != 0 || size == 0 || size > MAX_IMAGE_SIZE {
        return Err(format!(
            "invalid bootstrap header magic={magic:08x} target={target} size={size}"
        ));
    }

    unsafe {
        let label = CString::new("main").unwrap();
        let partition = sys::esp_partition_find_first(
            sys::esp_partition_type_t_ESP_PARTITION_TYPE_APP,
            sys::esp_partition_subtype_t_ESP_PARTITION_SUBTYPE_APP_OTA_0,
            label.as_ptr(),
        );
        if partition.is_null() {
            return Err("main partition not found".into());
        }
        let partition_size = (*partition).size;
        if size > partition_size {
            return Err(format!(
                "image {size} exceeds main partition {partition_size}"
            ));
        }
        let erase_size = (size + 0xfff) & !0xfff;
        esp_ok(
            sys::esp_partition_erase_range(partition, 0, erase_size as usize),
            "erase main partition",
        )?;
        let mut buffer = [0u8; BUFFER_SIZE];
        let mut offset = 0u32;
        while offset < size {
            let length = ((size - offset) as usize).min(buffer.len());
            read_exact(fd, &mut buffer[..length])?;
            esp_ok(
                sys::esp_partition_write(
                    partition,
                    offset as usize,
                    buffer.as_ptr() as *const _,
                    length,
                ),
                "write main partition",
            )?;
            offset += length as u32;
        }
        log(&format!("bootstrap image written bytes={size}"));
    }
    Ok(())
}

fn run() -> Result<(), String> {
    unsafe {
        sys::link_patches();
        esp_ok(sys::nvs_flash_init(), "nvs_flash_init")?;
    }
    let mut config = load_config();
    read_uart_override(&mut config);
    let key_present = unsafe { trust_key_present() };
    log(&format!(
        "boot server={} port={} trust_key={}",
        config.server, config.port, key_present
    ));
    start_network(&config)?;
    if key_present {
        return Err("trust key is present; unsigned bootstrap is disabled".into());
    }
    let stream = if config.server.is_empty() {
        accept_client(&config)?
    } else {
        connect_remote(&config)?
    };
    let result = receive_image(stream);
    unsafe { libc::close(stream) };
    result
}

fn main() {
    if let Err(error) = run() {
        log(&format!("recovery failed: {error}"));
    }
    unsafe { sys::esp_restart() };
}

#[no_mangle]
pub extern "C" fn app_main() {
    main();
}
