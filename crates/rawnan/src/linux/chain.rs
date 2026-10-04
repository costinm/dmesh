//! The raw Wi-Fi bearer's start chain: one interface becomes an open AP on the shared
//! channel plus a monitor VIF, which is what NOW and NAN run on. There is no
//! `wpa_supplicant` and no separate AP API.
//!
//! The sequence is written against [`WlanOps`] so its ordering rules are tested
//! without a radio:
//!
//! * starting is idempotent: an interface already in the target state is not touched
//!   (interface-type churn is what wedges some drivers);
//! * an AP is stopped with an explicit STOP_AP, and read back, before the link goes
//!   down: a link-down is never how an AP is stopped;
//! * the monitor VIF is created only after the AP is running, on the AP's channel;
//! * every step is verified by reading the state back, not by trusting the ack.

use super::*;

/// The shared DMesh channel: NOW, NAN and the AP all live here.
pub const SHARED_CHANNEL: u8 = 6;

/// Interface types the chain distinguishes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IfType {
    Managed,
    Ap,
    Monitor,
    Other(u32),
}

impl IfType {
    pub fn from_nl80211(value: u32) -> Self {
        match value {
            NL80211_IFTYPE_STATION => Self::Managed,
            NL80211_IFTYPE_AP => Self::Ap,
            NL80211_IFTYPE_MONITOR => Self::Monitor,
            other => Self::Other(other),
        }
    }

    pub fn to_nl80211(self) -> u32 {
        match self {
            Self::Managed => NL80211_IFTYPE_STATION,
            Self::Ap => NL80211_IFTYPE_AP,
            Self::Monitor => NL80211_IFTYPE_MONITOR,
            Self::Other(value) => value,
        }
    }
}

/// An interface as the kernel reports it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IfState {
    pub iftype: IfType,
    /// Operating frequency, when it has a channel context.
    pub freq: Option<u32>,
    pub up: bool,
}

/// Outcome of a STOP_AP request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StopAp {
    Stopped,
    /// The kernel had no running AP on the interface.
    NotRunning,
}

/// The system operations the chain needs. [`SysOps`] is the real one.
pub trait WlanOps {
    /// `None` when the interface does not exist.
    fn state(&mut self, iface: &str) -> Result<Option<IfState>>;
    fn stop_ap(&mut self, iface: &str) -> Result<StopAp>;
    fn set_type(&mut self, iface: &str, iftype: IfType) -> Result<()>;
    fn set_channel(&mut self, iface: &str, freq_mhz: u32) -> Result<()>;
    fn set_link(&mut self, iface: &str, up: bool) -> Result<()>;
    fn start_open_ap(&mut self, iface: &str, ssid: &str, channel: u8) -> Result<()>;
    fn delete(&mut self, iface: &str) -> Result<()>;
    fn create_monitor(&mut self, base: &str, monitor: &str, channel: u8) -> Result<()>;
}

/// What to bring up.
#[derive(Clone, Copy, Debug)]
pub struct ChainConfig<'a> {
    pub iface: &'a str,
    pub monitor: &'a str,
    pub ssid: &'a str,
    pub channel: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChainOutcome {
    /// Already in the target state; nothing was changed.
    AlreadyRunning,
    Started,
}

fn step<T>(name: &str, result: Result<T>) -> Result<T> {
    result.with_context(|| format!("start chain step `{name}`"))
}

/// Take an AP down in the only safe order: STOP_AP (an AP that is not running is
/// fine), then the link. Returns whether an AP was actually stopped.
pub fn release_ap<O: WlanOps>(ops: &mut O, iface: &str) -> Result<bool> {
    let stopped = step("stop_ap", ops.stop_ap(iface))? == StopAp::Stopped;
    if ops.state(iface)?.is_some_and(|state| state.up) {
        step("link_down", ops.set_link(iface, false))?;
    }
    Ok(stopped)
}

/// Bring `config.iface` to open AP + monitor on `config.channel`.
pub fn start_chain<O: WlanOps>(ops: &mut O, config: &ChainConfig<'_>) -> Result<ChainOutcome> {
    if !(1..=13).contains(&config.channel) {
        bail!("2.4 GHz AP channel must be in 1..=13, not {}", config.channel);
    }
    let freq = channel_to_freq(config.channel);
    let target = |state: Option<IfState>, iftype: IfType| {
        state.is_some_and(|state| {
            state.iftype == iftype && state.up && state.freq.is_none_or(|current| current == freq)
        })
    };
    let ap = step("read_ap", ops.state(config.iface))?;
    let monitor = step("read_monitor", ops.state(config.monitor))?;
    if target(ap, IfType::Ap) && ap.is_some_and(|state| state.freq == Some(freq)) && target(monitor, IfType::Monitor)
    {
        return Ok(ChainOutcome::AlreadyRunning);
    }
    if ap.is_none() {
        bail!("interface {} does not exist", config.iface);
    }

    // A stale monitor VIF holds the phy's channel context; remove it first.
    if monitor.is_some() {
        step("delete_monitor", ops.delete(config.monitor))?;
    }
    // Release whatever the interface was doing, in the safe order.
    if ap.is_some_and(|state| state.iftype == IfType::Ap) {
        release_ap(ops, config.iface)?;
    } else if ap.is_some_and(|state| state.up) {
        step("link_down", ops.set_link(config.iface, false))?;
    }
    if ap.is_none_or(|state| state.iftype != IfType::Ap) {
        step("set_type_ap", ops.set_type(config.iface, IfType::Ap))?;
    }
    step("set_channel", ops.set_channel(config.iface, freq))?;
    step("link_up", ops.set_link(config.iface, true))?;
    step(
        "start_open_ap",
        ops.start_open_ap(config.iface, config.ssid, config.channel),
    )?;
    // Only now that the AP runs: the monitor on its settled channel.
    step(
        "create_monitor",
        ops.create_monitor(config.iface, config.monitor, config.channel),
    )?;

    // Read everything back.
    let ap = step("verify_ap", ops.state(config.iface))?;
    match ap {
        Some(state) if state.iftype == IfType::Ap && state.up => {
            if let Some(current) = state.freq
                && current != freq
            {
                bail!("AP is on {current} MHz, expected {freq} MHz");
            }
        }
        other => bail!("AP did not come up as expected: {other:?}"),
    }
    if step("verify_monitor", ops.state(config.monitor))?.is_none() {
        bail!("monitor interface {} was not created", config.monitor);
    }
    Ok(ChainOutcome::Started)
}

/// [`start_chain`] with retries: each attempt starts again from the release step.
/// `pause` is called between attempts with the attempt number (1-based).
pub fn start_chain_with_retries<O: WlanOps>(
    ops: &mut O,
    config: &ChainConfig<'_>,
    attempts: usize,
    mut pause: impl FnMut(usize),
) -> Result<ChainOutcome> {
    let mut last = None;
    for attempt in 1..=attempts.max(1) {
        match start_chain(ops, config) {
            Ok(outcome) => return Ok(outcome),
            Err(error) => {
                last = Some(error);
                if attempt < attempts {
                    pause(attempt);
                }
            }
        }
    }
    Err(last.expect("at least one attempt ran"))
}

/// The real operations: nl80211 and rtnetlink.
///
/// START_AP is tied to the netlink socket that issued it (`SOCKET_OWNER`): the kernel
/// stops the AP when that socket closes. `owner` keeps it open for as long as the AP
/// should run, and `mgmt` is the socket that receives the AP's management frames
/// (authentication and association requests), for the caller's SME loop.
#[derive(Default)]
pub struct SysOps {
    pub owner: Option<Nl80211Socket>,
    pub mgmt: Option<Nl80211Socket>,
}

fn is_enoent(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io| io.raw_os_error() == Some(libc::ENOENT))
            || cause.to_string().contains("No such file or directory")
    })
}

impl WlanOps for SysOps {
    fn state(&mut self, iface: &str) -> Result<Option<IfState>> {
        let Ok(index) = ifindex(iface) else {
            return Ok(None);
        };
        let info = Nl80211Socket::open()?.interface_info(index)?;
        let flags = get_link_flags(index as i32).map_err(anyhow::Error::msg)?;
        Ok(Some(IfState {
            iftype: info.iftype.map_or(IfType::Other(0), IfType::from_nl80211),
            freq: info.freq,
            up: flags & IFF_UP != 0,
        }))
    }

    fn stop_ap(&mut self, iface: &str) -> Result<StopAp> {
        let index = ifindex(iface)?;
        match Nl80211Socket::open()?.stop_ap(index) {
            Ok(()) => Ok(StopAp::Stopped),
            Err(error) if is_enoent(&error) => Ok(StopAp::NotRunning),
            Err(error) => Err(error),
        }
    }

    fn set_type(&mut self, iface: &str, iftype: IfType) -> Result<()> {
        Nl80211Socket::open()?.set_interface_type(ifindex(iface)?, iftype.to_nl80211())
    }

    fn set_channel(&mut self, iface: &str, freq_mhz: u32) -> Result<()> {
        Nl80211Socket::open()?.set_channel_ht20(ifindex(iface)?, freq_mhz)
    }

    fn set_link(&mut self, iface: &str, up: bool) -> Result<()> {
        let result = if up {
            link_up_confirmed(iface, 3)
        } else {
            link_state_result(iface, false)
        };
        if result.get("ok").and_then(Value::as_bool) == Some(true) {
            Ok(())
        } else {
            bail!("link {} failed: {result}", if up { "up" } else { "down" })
        }
    }

    fn start_open_ap(&mut self, iface: &str, ssid: &str, channel: u8) -> Result<()> {
        let index = ifindex(iface)?;
        let mac = iface_mac(iface)?;
        let freq = channel_to_freq(channel);
        let owner = Nl80211Socket::open()?;
        let mgmt = Nl80211Socket::open()?;
        // The AP SME answers authentication and association itself, so its frames
        // are registered before the AP starts and stale stations are flushed.
        let registrations = mgmt.register_open_ap_sme_frames(index);
        if !registrations.iter().all(|registration| {
            registration.get("ok").and_then(Value::as_bool) == Some(true)
                || registration.get("required").and_then(Value::as_bool) == Some(false)
        }) {
            bail!("registering the AP management frames failed: {registrations:?}");
        }
        let _ = owner.flush_stations(index);
        // HT20 only: NAN, NOW and the AP share one 20 MHz channel.
        owner
            .start_open_ap(index, mac, ssid, channel, freq, false, 100)
            .map_err(|(error, _attempts)| error)?;
        self.owner = Some(owner);
        self.mgmt = Some(mgmt);
        Ok(())
    }

    fn delete(&mut self, iface: &str) -> Result<()> {
        Nl80211Socket::open()?.delete_interface(ifindex(iface)?)
    }

    fn create_monitor(&mut self, base: &str, monitor: &str, channel: u8) -> Result<()> {
        ensure_monitor_iface(base, monitor, channel, true, true, false).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Fake {
        calls: Vec<String>,
        ap: Option<IfState>,
        monitor: Option<IfState>,
        ap_running: bool,
        fail_at: Option<&'static str>,
    }

    impl Fake {
        fn note(&mut self, call: &str) -> Result<()> {
            self.calls.push(call.to_owned());
            if self.fail_at.is_some_and(|name| call.starts_with(name)) {
                bail!("injected failure at {call}");
            }
            Ok(())
        }
    }

    impl WlanOps for Fake {
        fn state(&mut self, iface: &str) -> Result<Option<IfState>> {
            Ok(if iface == "wlan0" { self.ap } else { self.monitor })
        }
        fn stop_ap(&mut self, _: &str) -> Result<StopAp> {
            self.note("stop_ap")?;
            Ok(if std::mem::take(&mut self.ap_running) {
                StopAp::Stopped
            } else {
                StopAp::NotRunning
            })
        }
        fn set_type(&mut self, _: &str, iftype: IfType) -> Result<()> {
            self.note(&format!("set_type:{iftype:?}"))?;
            if let Some(state) = self.ap.as_mut() {
                state.iftype = iftype;
            }
            Ok(())
        }
        fn set_channel(&mut self, _: &str, freq: u32) -> Result<()> {
            self.note(&format!("set_channel:{freq}"))?;
            if let Some(state) = self.ap.as_mut() {
                state.freq = Some(freq);
            }
            Ok(())
        }
        fn set_link(&mut self, _: &str, up: bool) -> Result<()> {
            self.note(&format!("link:{}", if up { "up" } else { "down" }))?;
            if let Some(state) = self.ap.as_mut() {
                state.up = up;
            }
            Ok(())
        }
        fn start_open_ap(&mut self, _: &str, _: &str, channel: u8) -> Result<()> {
            self.note(&format!("start_open_ap:{channel}"))?;
            self.ap_running = true;
            Ok(())
        }
        fn delete(&mut self, iface: &str) -> Result<()> {
            self.note(&format!("delete:{iface}"))?;
            self.monitor = None;
            Ok(())
        }
        fn create_monitor(&mut self, _: &str, _: &str, channel: u8) -> Result<()> {
            self.note(&format!("create_monitor:{channel}"))?;
            self.monitor = Some(IfState {
                iftype: IfType::Monitor,
                freq: Some(channel_to_freq(channel)),
                up: true,
            });
            Ok(())
        }
    }

    fn config() -> ChainConfig<'static> {
        ChainConfig {
            iface: "wlan0",
            monitor: "wlan0mon",
            ssid: "dmesh",
            channel: SHARED_CHANNEL,
        }
    }

    fn position(calls: &[String], name: &str) -> usize {
        calls.iter().position(|call| call == name).unwrap_or_else(|| panic!("{name} not in {calls:?}"))
    }

    #[test]
    fn a_managed_interface_becomes_an_open_ap_on_channel_6_then_gets_its_monitor() {
        let mut ops = Fake {
            ap: Some(IfState { iftype: IfType::Managed, freq: None, up: true }),
            ..Default::default()
        };
        assert_eq!(start_chain(&mut ops, &config()).unwrap(), ChainOutcome::Started);
        let calls = &ops.calls;
        assert!(calls.contains(&"set_channel:2437".to_owned()), "{calls:?}");
        assert!(calls.contains(&"start_open_ap:6".to_owned()));
        // The monitor exists only after the AP runs, on the same channel.
        assert!(position(calls, "start_open_ap:6") < position(calls, "create_monitor:6"));
        assert!(position(calls, "link:up") < position(calls, "start_open_ap:6"));
        assert!(position(calls, "set_type:Ap") < position(calls, "set_channel:2437"));
    }

    #[test]
    fn a_running_ap_is_stopped_before_the_link_goes_down() {
        let mut ops = Fake {
            ap: Some(IfState { iftype: IfType::Ap, freq: Some(2462), up: true }),
            monitor: Some(IfState { iftype: IfType::Monitor, freq: Some(2462), up: true }),
            ap_running: true,
            ..Default::default()
        };
        start_chain(&mut ops, &config()).unwrap();
        let calls = &ops.calls;
        assert!(position(calls, "stop_ap") < position(calls, "link:down"), "{calls:?}");
        // The old monitor goes before anything changes the AP.
        assert!(position(calls, "delete:wlan0mon") < position(calls, "stop_ap"));
        assert!(position(calls, "set_channel:2437") < position(calls, "start_open_ap:6"));
    }

    #[test]
    fn an_ap_that_is_already_gone_does_not_stop_the_chain() {
        // The kernel stops an AP when its owning socket closes (a process restart),
        // leaving an AP-typed interface with nothing running: STOP_AP says ENOENT.
        let mut ops = Fake {
            ap: Some(IfState { iftype: IfType::Ap, freq: None, up: true }),
            ap_running: false,
            ..Default::default()
        };
        assert_eq!(start_chain(&mut ops, &config()).unwrap(), ChainOutcome::Started);
        assert!(position(&ops.calls, "stop_ap") < position(&ops.calls, "link:down"));
    }

    #[test]
    fn an_interface_already_in_the_target_state_is_not_touched() {
        let mut ops = Fake {
            ap: Some(IfState { iftype: IfType::Ap, freq: Some(2437), up: true }),
            monitor: Some(IfState { iftype: IfType::Monitor, freq: Some(2437), up: true }),
            ap_running: true,
            ..Default::default()
        };
        assert_eq!(start_chain(&mut ops, &config()).unwrap(), ChainOutcome::AlreadyRunning);
        assert!(ops.calls.is_empty(), "no change expected, got {:?}", ops.calls);
    }

    #[test]
    fn an_ap_on_the_wrong_channel_is_restarted_on_channel_6() {
        let mut ops = Fake {
            ap: Some(IfState { iftype: IfType::Ap, freq: Some(2412), up: true }),
            monitor: Some(IfState { iftype: IfType::Monitor, freq: Some(2412), up: true }),
            ap_running: true,
            ..Default::default()
        };
        assert_eq!(start_chain(&mut ops, &config()).unwrap(), ChainOutcome::Started);
        assert!(ops.calls.contains(&"set_channel:2437".to_owned()));
    }

    #[test]
    fn a_failing_step_is_named_and_the_monitor_is_not_created() {
        let mut ops = Fake {
            ap: Some(IfState { iftype: IfType::Managed, freq: None, up: true }),
            fail_at: Some("start_open_ap"),
            ..Default::default()
        };
        let error = format!("{:#}", start_chain(&mut ops, &config()).unwrap_err());
        assert!(error.contains("start_open_ap"), "{error}");
        assert!(!ops.calls.iter().any(|call| call.starts_with("create_monitor")));
    }

    #[test]
    fn retries_start_again_and_pause_between_attempts() {
        let mut ops = Fake {
            ap: Some(IfState { iftype: IfType::Managed, freq: None, up: true }),
            fail_at: Some("set_channel"),
            ..Default::default()
        };
        let mut pauses = Vec::new();
        assert!(start_chain_with_retries(&mut ops, &config(), 3, |attempt| pauses.push(attempt)).is_err());
        assert_eq!(pauses, [1, 2]);
        assert_eq!(ops.calls.iter().filter(|call| call.starts_with("set_channel")).count(), 3);
    }

    #[test]
    fn a_channel_outside_the_band_is_refused_before_any_change() {
        let mut ops = Fake {
            ap: Some(IfState { iftype: IfType::Managed, freq: None, up: true }),
            ..Default::default()
        };
        let mut bad = config();
        bad.channel = 36;
        assert!(start_chain(&mut ops, &bad).is_err());
        assert!(ops.calls.is_empty());
    }
}
