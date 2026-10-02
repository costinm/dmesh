//! The one registration and dispatch path for tagged-CBOR handlers.
//!
//! Every platform (Linux, Android, firmware) registers each *implemented*
//! method here, by component and method number plus its names. A method that
//! a platform does not implement, or only stubs, is simply not registered; a
//! request for it receives the shared numeric "unsupported" error. Whether a
//! platform should decline a method it could implement is a handler policy,
//! not a second registration kind.
//!
//! Dispatch uses numbers only. Names exist for presentation: the `services`
//! method reports `[component, method, name]` for exactly what is registered.
//!
//! Every handler is a stream handler. A short request is the same thing as a
//! large one: the first data chunk of an inbound stream carries its tagged
//! envelope, with or without FIN. Large byte-string bodies may continue on the
//! same stream and are dispatched through this same registration table. HTTP
//! and SSH adapters wrap their own framing around the same call.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::ptr;
use core::sync::atomic::{AtomicPtr, Ordering};
use core::task::{Context, Poll, Waker};

use crate::stream::{OpenFuture, Outcome, Request, Response, StreamHandler};
use crate::tagged::{self, Name, Record};

/// Fixed number of registrable methods. It is sized for the largest platform
/// (Main with modules, BLE and provisioning) with headroom; registration
/// fails visibly when the table is full.
pub const CAPACITY: usize = 128;

/// Where a call came from, supplied by the ingress that owns the stream.
///
/// `association` identifies the QUIC peer for handlers that bind follow-on
/// streams or state to it; it is opaque, generation checked, and `None` for
/// non-QUIC callers. `local` is set only by ingress that is already inside
/// the device's trust boundary (the local control socket and HTTP gateway),
/// never by a network bearer.
/// How a request reached the handler. The form is a property of the arrival,
/// not of the handler (see "Delivery forms of one handler" in ssh-mesh
/// `PROTOCOLS.md`): the same registration serves all three.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Delivery {
    /// A bidirectional stream on an association: header, optional body, FIN.
    #[default]
    Stream,
    /// One allow-listed packet sent without an association; at most one
    /// response message.
    Message,
    /// A droppable datagram on an association; the handler returns nothing.
    Datagram,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CallContext {
    pub delivery: Delivery,
    pub association: Option<quic_lite::QuicAssociation>,
    /// The inbound QUIC stream that carries this request, if applicable.
    pub stream_id: Option<u64>,
    pub local: bool,
    /// The request's `timeout` envelope field: milliseconds the caller allows,
    /// counted from receipt. `None` means the handler's own default.
    pub timeout_ms: Option<u64>,
}

impl CallContext {
    /// Context for the device's own control surface.
    pub const fn local() -> Self {
        Self {
            delivery: Delivery::Stream,
            association: None,
            stream_id: None,
            local: true,
            timeout_ms: None,
        }
    }
}

/// Identity of one registered method.
///
/// The wire name is `component_name.method_name`; an empty `component_name`
/// registers a method whose full name is `method_name` (for example the
/// historical `status` and `log-watch`). Component numbers may carry several
/// component names (for example `discovery` and `nan` share one number).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Method {
    pub component: u64,
    pub component_name: &'static str,
    pub method: u64,
    pub method_name: &'static str,
}

impl Method {
    pub const fn new(
        component: u64,
        component_name: &'static str,
        method: u64,
        method_name: &'static str,
    ) -> Self {
        Self {
            component,
            component_name,
            method,
            method_name,
        }
    }

    /// Presentation name used by `services`, HTTP and the CLI.
    pub fn wire_name(&self) -> String {
        if self.component_name.is_empty() {
            String::from(self.method_name)
        } else {
            let mut name = String::from(self.component_name);
            name.push('.');
            name.push_str(self.method_name);
            name
        }
    }
}

/// One inbound stream as seen by a handler: its tagged envelope, the first
/// data chunk it was decoded from, and whether that chunk carried FIN.
#[derive(Clone, Copy, Debug)]
pub struct Call<'a> {
    pub record: Record<'a>,
    pub data: &'a [u8],
    pub fin: bool,
    pub context: CallContext,
}

/// Handler result: the encoded response record, or `None` when the handler
/// has nothing to send (the dispatcher then answers a correlated request
/// with the shared numeric error).
pub type Reply<'a> = Pin<Box<dyn Future<Output = Option<Vec<u8>>> + Send + 'a>>;

/// A stream handler. Registered by value; may hold shared platform state.
pub trait Handler: Send + Sync + 'static {
    fn call<'a>(&'a self, call: Call<'a>) -> Reply<'a>;
}

/// Adapter for a plain function that decodes and answers synchronously.
/// Firmware handlers are of this form.
pub struct SyncFn(pub fn(Record<'_>) -> Option<Vec<u8>>);

impl Handler for SyncFn {
    fn call<'a>(&'a self, call: Call<'a>) -> Reply<'a> {
        let response = (self.0)(call.record);
        Box::pin(core::future::ready(response))
    }
}

/// Adapter for a synchronous function that also needs the association.
pub struct SyncCtxFn(pub fn(Record<'_>, CallContext) -> Option<Vec<u8>>);

impl Handler for SyncCtxFn {
    fn call<'a>(&'a self, call: Call<'a>) -> Reply<'a> {
        let response = (self.0)(call.record, call.context);
        Box::pin(core::future::ready(response))
    }
}

/// Adapter for a synchronous function that decodes the whole request itself.
/// Used by handlers written against the raw first chunk.
pub struct SyncBytesFn(pub fn(&[u8]) -> Option<Vec<u8>>);

impl Handler for SyncBytesFn {
    fn call<'a>(&'a self, call: Call<'a>) -> Reply<'a> {
        let response = (self.0)(call.data);
        Box::pin(core::future::ready(response))
    }
}

impl Clone for SyncBytesFn {
    fn clone(&self) -> Self {
        Self(self.0)
    }
}

/// Policy wrapper: serve the method only to local ingress. A network caller
/// is declined (and so receives the shared numeric error). This is how a
/// platform keeps internal calls private while sharing one registry.
#[derive(Clone)]
pub struct LocalOnly<H>(pub H);

impl<H: Handler> Handler for LocalOnly<H> {
    fn call<'a>(&'a self, call: Call<'a>) -> Reply<'a> {
        if call.context.local {
            self.0.call(call)
        } else {
            Box::pin(core::future::ready(None))
        }
    }
}

/// Adapter for a closure returning a boxed future: the host form, able to
/// capture service state.
pub struct AsyncFn<F>(F);

impl<F> AsyncFn<F>
where
    F: for<'a> Fn(Call<'a>) -> Reply<'a> + Send + Sync + 'static,
{
    /// The bound here (rather than only on `Handler`) lets a closure be
    /// inferred as higher-ranked over the call's lifetime.
    pub fn new(handler: F) -> Self {
        Self(handler)
    }
}

impl<F> Handler for AsyncFn<F>
where
    F: for<'a> Fn(Call<'a>) -> Reply<'a> + Send + Sync + 'static,
{
    fn call<'a>(&'a self, call: Call<'a>) -> Reply<'a> {
        (self.0)(call)
    }
}

/// Runs a plain (header-only) [`Handler`] as a stream handler: it answers at
/// the end of the header and never reads a body.
struct Unary<H>(H);

impl<H: Handler> StreamHandler for Unary<H> {
    fn open<'a>(&'a self, request: Request<'a>) -> OpenFuture<'a> {
        let call = Call {
            record: request.record,
            data: request.header,
            fin: true,
            context: request.context,
        };
        let reply = self.0.call(call);
        Box::pin(async move {
            reply
                .await
                .map(|header| Outcome::Respond(Response::header(header)))
        })
    }
}

struct Entry {
    method: Method,
    handler: Box<dyn StreamHandler>,
}

/// Fixed-capacity method table. Registration is startup-only and lock-free:
/// an entry is published once and never changes or moves.
pub struct Registry {
    table: [AtomicPtr<Entry>; CAPACITY],
}

impl Registry {
    pub const fn new() -> Self {
        Self {
            table: [const { AtomicPtr::new(ptr::null_mut()) }; CAPACITY],
        }
    }

    /// Register one implemented method. Returns `false` for a zero
    /// component, a duplicate `(component, method)`, or a full table.
    pub fn register(&self, method: Method, handler: impl Handler) -> bool {
        self.publish(method, Box::new(Unary(handler)))
    }

    /// Register a method whose handler decides what happens to the request
    /// body. A method with no body uses [`Registry::register`].
    pub fn register_stream(&self, method: Method, handler: impl StreamHandler) -> bool {
        self.publish(method, Box::new(handler))
    }

    fn publish(&self, method: Method, handler: Box<dyn StreamHandler>) -> bool {
        if method.component == 0 || self.lookup(method.component, method.method).is_some() {
            return false;
        }
        let entry = Box::into_raw(Box::new(Entry { method, handler }));
        for slot in &self.table {
            if slot
                .compare_exchange(ptr::null_mut(), entry, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return true;
            }
        }
        // Table full: reclaim the entry that was never published.
        drop(unsafe { Box::from_raw(entry) });
        false
    }

    /// Register several methods that one function serves.
    pub fn register_all<H>(&self, methods: &[Method], handler: H) -> bool
    where
        H: Handler + Clone,
    {
        methods
            .iter()
            .all(|method| self.register(*method, handler.clone()))
    }

    fn entry(&self, index: usize) -> Option<&Entry> {
        let entry = self.table[index].load(Ordering::Acquire);
        // SAFETY: published entries are never freed before the registry drops.
        (!entry.is_null()).then(|| unsafe { &*entry })
    }

    fn lookup(&self, component: u64, method: u64) -> Option<&Entry> {
        (0..CAPACITY)
            .filter_map(|index| self.entry(index))
            .find(|entry| entry.method.component == component && entry.method.method == method)
    }

    /// Every registered method, ordered by component then method number.
    pub fn methods(&self) -> Vec<Method> {
        let mut methods: Vec<Method> = (0..CAPACITY)
            .filter_map(|index| self.entry(index))
            .map(|entry| entry.method)
            .collect();
        methods.sort_by_key(|method| (method.component, method.method));
        methods
    }

    /// `[[component, method, "name"], ...]` for exactly the registered set.
    pub fn encode_service_catalog(&self) -> Vec<u8> {
        let methods = self.methods();
        let names: Vec<String> = methods.iter().map(Method::wire_name).collect();
        // Array header, then per item: array header and two uints (9 bytes
        // each at most) and a text header (9 bytes at most) plus the name.
        let capacity = 9 + names
            .iter()
            .map(|name| 1 + 9 + 9 + 9 + name.len())
            .sum::<usize>();
        let mut output = alloc::vec![0u8; capacity];
        let mut encoder = crate::cbor::Encoder::new(&mut output);
        encoder
            .array(methods.len() as u64)
            .expect("service catalog capacity is computed from its contents");
        for (method, name) in methods.iter().zip(&names) {
            encoder.array(3).expect("service catalog capacity");
            encoder
                .uint(method.component)
                .expect("service catalog capacity");
            encoder
                .uint(method.method)
                .expect("service catalog capacity");
            encoder
                .text_value(name.as_bytes())
                .expect("service catalog capacity");
        }
        let used = encoder.len();
        drop(encoder);
        output.truncate(used);
        output
    }

    /// Open a handler with a complete header. The result says what happens to
    /// the body. A correlated request with no registered method, or whose
    /// handler declines, is answered with the shared numeric error so an
    /// adapter/API mismatch is an ordinary tagged error rather than an
    /// application timeout. Malformed, uncorrelated and directed records are
    /// unhandled (`None`).
    pub async fn open(&self, mut request: Request<'_>) -> Option<Outcome> {
        request.context.timeout_ms = request.record.timeout.or(request.context.timeout_ms);
        let (Name::Tag(component), Name::Tag(method)) =
            (request.record.component?, request.record.method?)
        else {
            return None;
        };
        if let Some(entry) = self.lookup(component, method) {
            if let Some(outcome) = entry.handler.open(request).await {
                return Some(outcome);
            }
        }
        unsupported(&request, component, method)
    }

    /// [`Registry::open`] for callers with no async runtime (firmware
    /// ingress). A handler that does not answer on its first poll cannot run
    /// there and is answered with the numeric error.
    pub fn open_now(&self, mut request: Request<'_>) -> Option<Outcome> {
        request.context.timeout_ms = request.record.timeout.or(request.context.timeout_ms);
        let (Name::Tag(component), Name::Tag(method)) =
            (request.record.component?, request.record.method?)
        else {
            return None;
        };
        if let Some(entry) = self.lookup(component, method) {
            let mut future = entry.handler.open(request);
            let mut cx = Context::from_waker(Waker::noop());
            match future.as_mut().poll(&mut cx) {
                Poll::Ready(Some(outcome)) => return Some(outcome),
                Poll::Ready(None) => {}
                Poll::Pending => {
                    return error_outcome(
                        &request,
                        component,
                        method,
                        b"handler requires an async runtime",
                    );
                }
            }
        }
        unsupported(&request, component, method)
    }

    /// Dispatch a complete request/response pair that has no body in either
    /// direction: the header in `data` (the whole first chunk), the response
    /// header out. A method that takes or returns a body is answered with an
    /// error here; it needs a stream.
    pub async fn dispatch(&self, data: &[u8], _fin: bool, context: CallContext) -> Option<Vec<u8>> {
        let record = tagged::decode(data)?;
        let request = Request {
            record,
            header: data,
            context,
        };
        into_header_only(&request, self.open(request).await)
    }

    /// [`Registry::dispatch`] for callers with no async runtime.
    pub fn dispatch_now(&self, data: &[u8], context: CallContext) -> Option<Vec<u8>> {
        let record = tagged::decode(data)?;
        let request = Request {
            record,
            header: data,
            context,
        };
        into_header_only(&request, self.open_now(request))
    }
}

fn into_header_only(request: &Request<'_>, outcome: Option<Outcome>) -> Option<Vec<u8>> {
    match outcome? {
        Outcome::Respond(Response { header, body: None }) => Some(header),
        Outcome::Respond(_) | Outcome::Receive(_) | Outcome::Defer(_) => {
            let (Name::Tag(component), Name::Tag(method)) =
                (request.record.component?, request.record.method?)
            else {
                return None;
            };
            match error_outcome(request, component, method, b"method requires a stream body")? {
                Outcome::Respond(response) => Some(response.header),
                Outcome::Receive(_) | Outcome::Defer(_) => None,
            }
        }
    }
}

fn unsupported(request: &Request<'_>, component: u64, method: u64) -> Option<Outcome> {
    error_outcome(
        request,
        component,
        method,
        b"unsupported or invalid stream request",
    )
}

/// The numeric error for a request the dispatcher cannot serve. Only a stream
/// has a caller waiting for it: a message or datagram that is declined is
/// dropped silently, so an unauthenticated sender gets no reply to amplify.
fn error_outcome(
    request: &Request<'_>,
    component: u64,
    method: u64,
    message: &[u8],
) -> Option<Outcome> {
    let record = &request.record;
    if record.to.is_some() || request.context.delivery != Delivery::Stream {
        return None;
    }
    let mut response = [0u8; 96];
    let used = tagged::encode_numeric_error(component, method, record.id?, message, &mut response)?;
    Some(Outcome::Respond(Response::header(Vec::from(
        &response[..used],
    ))))
}

impl Default for Registry {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Registry {
    fn drop(&mut self) {
        for slot in &mut self.table {
            let entry = *slot.get_mut();
            if !entry.is_null() {
                drop(unsafe { Box::from_raw(entry) });
            }
        }
    }
}

/// The process-wide registry used by every ingress.
pub static REGISTRY: Registry = Registry::new();

/// Register one implemented method in the process-wide registry.
pub fn register(method: Method, handler: impl Handler) -> bool {
    REGISTRY.register(method, handler)
}

/// Register a method whose handler decides what happens to the request body.
pub fn register_stream(method: Method, handler: impl StreamHandler) -> bool {
    REGISTRY.register_stream(method, handler)
}

/// Register several methods served by one function.
pub fn register_all<H: Handler + Clone>(methods: &[Method], handler: H) -> bool {
    REGISTRY.register_all(methods, handler)
}

/// Dispatch asynchronously through the process-wide registry.
pub async fn dispatch(data: &[u8], fin: bool, context: CallContext) -> Option<Vec<u8>> {
    REGISTRY.dispatch(data, fin, context).await
}

/// Dispatch without an async runtime through the process-wide registry.
pub fn dispatch_now(data: &[u8], context: CallContext) -> Option<Vec<u8>> {
    REGISTRY.dispatch_now(data, context)
}

impl Clone for SyncFn {
    fn clone(&self) -> Self {
        Self(self.0)
    }
}

impl Clone for SyncCtxFn {
    fn clone(&self) -> Self {
        Self(self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GET: Method = Method::new(0x7ffe, "demo", 1, "get");
    const PUT: Method = Method::new(0x7ffe, "demo", 2, "put");
    const LEGACY: Method = Method::new(0x7ffe, "", 3, "log-watch");

    fn answer(record: Record<'_>) -> Option<Vec<u8>> {
        let mut out = [0u8; 32];
        let used = tagged::encode_numeric_response(
            0x7ffe,
            match record.method? {
                Name::Tag(method) => method,
                _ => return None,
            },
            record.id?,
            &[0xa0],
            &mut out,
        )?;
        Some(Vec::from(&out[..used]))
    }

    fn decline(_: Record<'_>) -> Option<Vec<u8>> {
        None
    }

    fn request(method: u64, id: u64) -> Vec<u8> {
        let mut out = [0u8; 32];
        let used = tagged::encode_numeric_empty_request(0x7ffe, method, id, &mut out).unwrap();
        Vec::from(&out[..used])
    }

    #[test]
    fn dispatch_is_by_number_and_registered_methods_are_named() {
        let registry = Registry::new();
        assert!(registry.register_all(&[GET, PUT], SyncFn(answer)));
        assert!(registry.register(LEGACY, SyncFn(decline)));
        // Duplicates, including with another handler, are rejected.
        assert!(!registry.register(GET, SyncFn(decline)));
        assert!(!registry.register(Method::new(0, "x", 1, "y"), SyncFn(answer)));

        let response = registry
            .dispatch_now(&request(2, 9), CallContext::default())
            .unwrap();
        let record = tagged::decode(&response).unwrap();
        assert_eq!(record.method, Some(Name::Tag(2)));
        assert_eq!(record.id, Some(9));
        assert!(record.result.is_some());

        let names: Vec<_> = registry.methods().iter().map(Method::wire_name).collect();
        assert_eq!(names, ["demo.get", "demo.put", "log-watch"]);
    }

    #[test]
    fn a_declined_message_or_datagram_is_dropped_without_a_reply() {
        let registry = Registry::new();
        assert!(registry.register(LEGACY, SyncFn(decline)));
        for delivery in [Delivery::Message, Delivery::Datagram] {
            let context = CallContext {
                delivery,
                ..Default::default()
            };
            // Unregistered and declined requests get no error to amplify.
            assert_eq!(registry.dispatch_now(&request(7, 4), context), None);
            assert_eq!(registry.dispatch_now(&request(3, 4), context), None);
        }
        // A registered handler still answers a message.
        assert!(registry.register(GET, SyncFn(answer)));
        let context = CallContext {
            delivery: Delivery::Message,
            ..Default::default()
        };
        assert!(registry.dispatch_now(&request(1, 5), context).is_some());
    }

    #[test]
    fn unregistered_and_declined_methods_get_the_numeric_error() {
        let registry = Registry::new();
        assert!(registry.register(LEGACY, SyncFn(decline)));
        for method in [7, 3] {
            let response = registry
                .dispatch_now(&request(method, 4), CallContext::default())
                .unwrap();
            let record = tagged::decode(&response).unwrap();
            assert_eq!(record.method, Some(Name::Tag(method)));
            assert_eq!(record.id, Some(4));
            assert!(record.error.is_some());
        }
        // Malformed and uncorrelated records stay unhandled.
        assert_eq!(registry.dispatch_now(&[0xff], CallContext::default()), None);
    }

    #[test]
    fn service_catalog_reports_numbers_and_names_for_the_registered_set() {
        let registry = Registry::new();
        assert!(registry.register(PUT, SyncFn(answer)));
        assert!(registry.register(LEGACY, SyncFn(answer)));
        let catalog = registry.encode_service_catalog();
        let mut decoder = crate::cbor::Decoder::new(&catalog);
        assert_eq!(decoder.head(), Some((4, 2)));
        for (method, name) in [(2u64, "demo.put"), (3, "log-watch")] {
            assert_eq!(decoder.head(), Some((4, 3)));
            assert_eq!(decoder.uint(), Some(0x7ffe));
            assert_eq!(decoder.uint(), Some(method));
            assert_eq!(decoder.text_ref(), Some(name.as_bytes()));
        }
    }

    #[test]
    fn local_only_methods_decline_network_callers() {
        let registry = Registry::new();
        assert!(registry.register(GET, LocalOnly(SyncFn(answer))));
        let network = registry
            .dispatch_now(&request(1, 5), CallContext::default())
            .unwrap();
        assert!(tagged::decode(&network).unwrap().error.is_some());
        let local = registry
            .dispatch_now(&request(1, 5), CallContext::local())
            .unwrap();
        assert!(tagged::decode(&local).unwrap().result.is_some());
    }

    #[test]
    fn handlers_may_be_async_closures_over_shared_state() {
        let registry = Registry::new();
        let state = alloc::sync::Arc::new(5u64);
        let handler = AsyncFn::new(move |call: Call<'_>| -> Reply<'_> {
            let state = state.clone();
            Box::pin(async move {
                let mut out = [0u8; 32];
                let used = tagged::encode_numeric_response(
                    0x7ffe,
                    1,
                    call.record.id?,
                    &[0xa1, 1, *state as u8],
                    &mut out,
                )?;
                Some(Vec::from(&out[..used]))
            })
        });
        assert!(registry.register(GET, handler));
        let response = registry
            .dispatch_now(&request(1, 3), CallContext::default())
            .unwrap();
        assert!(tagged::decode(&response).unwrap().result.is_some());
    }
}

/// Identities of the common methods, built from the component constants each
/// owning module defines. A platform registers the subset it implements.
pub mod methods {
    use super::Method;
    use crate::{announce, control, provision, raw_wifi, services, telemetry, verified_object};

    pub const SETTINGS_GET: Method = Method::new(
        control::CONTROL_COMPONENT,
        "settings",
        control::SETTINGS_GET,
        "get",
    );
    pub const SETTINGS_SET: Method = Method::new(
        control::CONTROL_COMPONENT,
        "settings",
        control::SETTINGS_SET,
        "set",
    );
    pub const SETTINGS_LIST: Method = Method::new(
        control::CONTROL_COMPONENT,
        "settings",
        control::SETTINGS_LIST,
        "list",
    );
    pub const TRANSPORT_SET: Method = Method::new(
        control::CONTROL_COMPONENT,
        "transport",
        control::TRANSPORT_SET,
        "set",
    );

    pub const RADIO_TX: Method = Method::new(
        raw_wifi::RAW_WIFI_COMPONENT,
        "radio",
        raw_wifi::RAW_WIFI_METHOD_TX,
        "tx",
    );
    pub const RADIO_CONTROL: Method = Method::new(
        raw_wifi::RAW_WIFI_COMPONENT,
        "radio",
        raw_wifi::RAW_WIFI_METHOD_CONTROL,
        "control",
    );
    pub const RADIO_SNAPSHOT: Method = Method::new(
        raw_wifi::RAW_WIFI_COMPONENT,
        "radio",
        raw_wifi::RAW_WIFI_METHOD_SNAPSHOT,
        "snapshot",
    );
    pub const RADIO_RESET_COUNTERS: Method = Method::new(
        raw_wifi::RAW_WIFI_COMPONENT,
        "radio",
        raw_wifi::RAW_WIFI_METHOD_RESET_COUNTERS,
        "reset_counters",
    );
    pub const WIFI_SCAN: Method = Method::new(
        raw_wifi::RAW_WIFI_COMPONENT,
        "wifi",
        raw_wifi::RAW_WIFI_METHOD_SCAN,
        "scan",
    );

    pub const DISCOVERY_CHECK: Method = Method::new(
        announce::ANNOUNCE_COMPONENT,
        "discovery",
        announce::ANNOUNCE_DISCOVERY,
        "check",
    );
    pub const DISCOVERY_NODES: Method = Method::new(
        announce::ANNOUNCE_COMPONENT,
        "discovery",
        announce::ANNOUNCE_DEVICES_OBSERVED,
        "nodes",
    );
    pub const DISCOVERY_ACTIVE: Method = Method::new(
        announce::ANNOUNCE_COMPONENT,
        "discovery",
        announce::ANNOUNCE_DISCOVERY_ACTIVE,
        "active",
    );
    pub const NAN_WAKEUP: Method = Method::new(
        announce::ANNOUNCE_COMPONENT,
        "nan",
        announce::ANNOUNCE_NAN_WAKEUP,
        "wakeup",
    );
    pub const NAN_PAIR_WAKEUP: Method = Method::new(
        announce::ANNOUNCE_COMPONENT,
        "nan",
        announce::ANNOUNCE_NAN_PAIR_WAKEUP,
        "pair_wakeup",
    );

    const fn telemetry(method: u64, name: &'static str) -> Method {
        Method::new(telemetry::TELEMETRY_COMPONENT, "telemetry", method, name)
    }
    pub const TELEMETRY_NAN_STATUS: Method = telemetry(telemetry::NAN_STATUS_METHOD, "nan_status");
    pub const TELEMETRY_NOW_METRICS: Method =
        telemetry(telemetry::NOW_METRICS_METHOD, "now");
    pub const TELEMETRY_NAN_METRICS: Method =
        telemetry(telemetry::NAN_METRICS_METHOD, "nan");
    pub const TELEMETRY_UDP6_METRICS: Method =
        telemetry(telemetry::UDP6_METRICS_METHOD, "udp6");
    pub const TELEMETRY_WIFI_LINK_METRICS: Method =
        telemetry(telemetry::WIFI_LINK_METRICS_METHOD, "wifi_link");
    pub const TELEMETRY_BATTERY: Method = telemetry(telemetry::BATTERY_METHOD, "battery");
    pub const TELEMETRY_QUIC_METRICS: Method =
        telemetry(telemetry::QUIC_METRICS_METHOD, "quic");
    pub const TELEMETRY_QUIC_ASSOCIATIONS: Method =
        telemetry(telemetry::QUIC_ASSOCIATIONS_METHOD, "quic_associations");
    pub const TELEMETRY_BEARERS: Method = telemetry(telemetry::BEARERS_METHOD, "bearers");
    pub const TELEMETRY_MEMORY: Method = telemetry(telemetry::MEMORY_METHOD, "memory");
    pub const TELEMETRY_POWER: Method = telemetry(telemetry::POWER_METHOD, "power");
    pub const TELEMETRY_RUNTIME: Method = telemetry(telemetry::RUNTIME_METHOD, "runtime");
    /// `log.watch`: retained log/event records, optionally streamed with
    /// periodic telemetry snapshots. The older `log-watch` (9/5) is
    /// `LOG_WATCH` until platforms migrate.
    pub const LOG_WATCH_RECORDS: Method = Method::new(208, "log", 2, "watch");

    /// The historical un-prefixed names: `status`, `services`, `log-watch`...
    const fn diagnostic(method: u64, name: &'static str) -> Method {
        Method::new(services::DIAGNOSTIC_COMPONENT, "", method, name)
    }
    pub const STATUS: Method = diagnostic(services::DIAGNOSTIC_STATUS_METHOD, "status");
    pub const SERVICES: Method = diagnostic(services::DIAGNOSTIC_SERVICES_METHOD, "services");
    pub const METRICS: Method = diagnostic(services::DIAGNOSTIC_METRICS_METHOD, "metrics");
    pub const EVENTS: Method = diagnostic(services::DIAGNOSTIC_EVENTS_METHOD, "events");
    pub const LOG_WATCH: Method = diagnostic(services::DIAGNOSTIC_LOG_WATCH_METHOD, "log-watch");

    /// `probe.start`: ask a node to run a probe against `peer`. Header only,
    /// in both directions.
    pub const PROBE_START: Method = Method::new(
        crate::probe::PROBE_COMPONENT,
        "probe",
        crate::probe::PROBE_START,
        "start",
    );
    /// `probe.handler`: the probed node's handler; the response body is the
    /// probe payload. More probe handlers (sink, echo, error injection) are
    /// added beside it as tests need them.
    pub const PROBE_HANDLER: Method = Method::new(
        crate::probe::PROBE_COMPONENT,
        "probe",
        crate::probe::PROBE_HANDLER,
        "handler",
    );

    pub const OBJECT_GET: Method = Method::new(
        verified_object::OBJECT_COMPONENT,
        "object",
        verified_object::OBJECT_GET_METHOD,
        "get",
    );
    pub const OBJECT_FLASH: Method = Method::new(
        verified_object::OBJECT_COMPONENT,
        "object",
        verified_object::OBJECT_FLASH_METHOD,
        "flash",
    );

    pub const BOOT_RECOVERY: Method = Method::new(
        services::BOOT_COMPONENT,
        "boot",
        services::BOOT_RECOVERY_METHOD,
        "recovery",
    );
    pub const FIRMWARE_IDENTITY: Method = Method::new(
        services::FIRMWARE_COMPONENT,
        "firmware",
        services::FIRMWARE_IDENTITY_METHOD,
        "identity",
    );

    pub const RUNTIME_SNAPSHOT: Method = Method::new(
        services::RUNTIME_SNAPSHOT_COMPONENT,
        "runtime",
        services::RUNTIME_SNAPSHOT_METHOD,
        "snapshot",
    );
    pub const RUNTIME_RESET: Method = Method::new(
        services::RUNTIME_SNAPSHOT_COMPONENT,
        "runtime",
        services::RUNTIME_RESET_METHOD,
        "reset",
    );
    pub const POWER_SNAPSHOT: Method = Method::new(
        services::POWER_SNAPSHOT_COMPONENT,
        "power",
        services::RUNTIME_SNAPSHOT_METHOD,
        "snapshot",
    );
    pub const MEMORY_SNAPSHOT: Method = Method::new(
        services::MEMORY_SNAPSHOT_COMPONENT,
        "memory",
        services::RUNTIME_SNAPSHOT_METHOD,
        "snapshot",
    );

    const fn ble(method: u64, name: &'static str) -> Method {
        Method::new(services::BLE_COMPONENT, "ble", method, name)
    }
    pub const BLE_START: Method = ble(services::BLE_START_METHOD, "start");
    pub const BLE_STOP: Method = ble(services::BLE_STOP_METHOD, "stop");
    pub const BLE_SCAN: Method = ble(services::BLE_SCAN_METHOD, "scan");
    pub const BLE_STATUS: Method = ble(services::BLE_STATUS_METHOD, "status");
    pub const BLE_SCAN_STOP: Method = ble(services::BLE_SCAN_STOP_METHOD, "scan_stop");
    pub const BLE_CONNECT: Method = ble(services::BLE_CONNECT_METHOD, "connect");
    pub const BLE_COC_SEND: Method = ble(services::BLE_COC_SEND_METHOD, "coc.send");

    pub const PROVISION_INSTALL: Method = Method::new(
        provision::COMPONENT,
        "provision",
        provision::INSTALL,
        "install",
    );
}
