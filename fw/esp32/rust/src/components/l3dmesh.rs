#![allow(dead_code)]

use anyhow::Result;

/// A borrowed or owned mesh frame received from an L2 transport.
///
/// This is the first Rust-side shape for the C `onMessage(char *c, int len,
/// int from)` callback in `components/l3dmesh/dmesh.c`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Frame<'a> {
    payload: &'a [u8],
}

impl<'a> Frame<'a> {
    pub fn borrowed(payload: &'a [u8]) -> Self {
        Self { payload }
    }

    pub fn payload(&self) -> &'a [u8] {
        self.payload
    }

    pub fn is_lora_priority(&self) -> bool {
        self.payload.first() == Some(&b'l')
    }
}

/// Minimal transport boundary for translated L2 components.
///
/// The current C component forwards a received frame to LoRa, BLE, BT, and
/// eventually NAN. New translated components should implement this trait first,
/// then grow hardware-backed implementations behind the same boundary.
pub trait Transport {
    fn name(&self) -> &'static str;
    fn send(&mut self, frame: &Frame<'_>, from_interface: i32) -> Result<()>;
}

/// Initial Rust port of the L3 mesh routing component.
pub struct L3Mesh {
    transports: Vec<Box<dyn Transport>>,
    in_messages: u32,
}

impl L3Mesh {
    pub fn new() -> Self {
        Self {
            transports: Vec::new(),
            in_messages: 0,
        }
    }

    pub fn add_transport<T>(&mut self, transport: T)
    where
        T: Transport + 'static,
    {
        self.transports.push(Box::new(transport));
    }

    pub fn on_message(&mut self, frame: Frame<'_>, from_interface: i32) -> Result<()> {
        self.in_messages = self.in_messages.saturating_add(1);
        log::info!(
            "MSGIN: from={} len={} total={}",
            from_interface,
            frame.payload().len(),
            self.in_messages
        );

        for transport in &mut self.transports {
            if frame.is_lora_priority() && transport.name() != "lora" {
                continue;
            }
            transport.send(&frame, from_interface)?;
        }

        Ok(())
    }

    #[allow(dead_code)]
    pub fn in_messages(&self) -> u32 {
        self.in_messages
    }
}
