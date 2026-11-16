//! Local tagged-CBOR method registry, stream adapter, and compact wire structs
//! shared by `lmesh-wifi` and `lmesh`.

use std::future::Future;
use std::io;
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use mesh_api::cbor::{Decoder, Encoder};
use mesh_api::envelope::{
    Name, PrefixDecode, Record, decode, decode_envelope_prefix, decode_prefix,
    encode_error_header, encode_numeric_error, encode_numeric_response,
};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const DIAGNOSTIC_COMPONENT: u64 = 9;
pub const DIAGNOSTIC_STATUS_METHOD: u64 = 1;
pub const DIAGNOSTIC_SERVICES_METHOD: u64 = 2;

pub const TELEMETRY_COMPONENT: u64 = 7;
pub const NAN_STATUS_METHOD: u64 = 1;
pub const NOW_METRICS_METHOD: u64 = 2;
pub const NAN_METRICS_METHOD: u64 = 3;
pub const UDP6_METRICS_METHOD: u64 = 4;
pub const WIFI_LINK_METRICS_METHOD: u64 = 5;
pub const QUIC_METRICS_METHOD: u64 = 7;
pub const QUIC_ASSOCIATIONS_METHOD: u64 = 8;
pub const BEARERS_METHOD: u64 = 9;
pub const MEMORY_METHOD: u64 = 10;
pub const DEVICE_METHOD: u64 = 13;

/// Fixed capacity of registrable methods per registry instance.
pub const REGISTRY_CAPACITY: usize = 128;

/// How a request reached the handler.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Delivery {
    #[default]
    Stream,
    Message,
    Datagram,
}

/// Provenance and timeout metadata supplied by the ingress that owns the stream.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CallContext {
    pub delivery: Delivery,
    pub local: bool,
    pub timeout_ms: Option<u64>,
}

impl CallContext {
    pub const fn local() -> Self {
        Self {
            delivery: Delivery::Stream,
            local: true,
            timeout_ms: None,
        }
    }
}

/// Identity of one registered method.
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

    pub fn wire_name(&self) -> String {
        if self.component_name.is_empty() {
            String::from(self.method_name)
        } else {
            format!("{}.{}", self.component_name, self.method_name)
        }
    }
}

pub mod methods {
    use super::{
        BEARERS_METHOD, DEVICE_METHOD, DIAGNOSTIC_COMPONENT, DIAGNOSTIC_SERVICES_METHOD,
        DIAGNOSTIC_STATUS_METHOD, MEMORY_METHOD, Method, NAN_METRICS_METHOD, NAN_STATUS_METHOD,
        NOW_METRICS_METHOD, QUIC_ASSOCIATIONS_METHOD, QUIC_METRICS_METHOD, TELEMETRY_COMPONENT,
        UDP6_METRICS_METHOD, WIFI_LINK_METRICS_METHOD,
    };
    use dmesh_discovery::{announce, control};
    use dmesh_rawnan::raw_wifi;

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

    pub const COMPANION_PAIR: Method = Method::new(209, "companion", 1, "pair");
    pub const COMPANION_UNPAIR: Method = Method::new(209, "companion", 2, "unpair");

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
        Method::new(TELEMETRY_COMPONENT, "telemetry", method, name)
    }
    pub const TELEMETRY_NAN_STATUS: Method = telemetry(NAN_STATUS_METHOD, "nan_status");
    pub const TELEMETRY_NOW_METRICS: Method = telemetry(NOW_METRICS_METHOD, "now");
    pub const TELEMETRY_NAN_METRICS: Method = telemetry(NAN_METRICS_METHOD, "nan");
    pub const TELEMETRY_UDP6_METRICS: Method = telemetry(UDP6_METRICS_METHOD, "udp6");
    pub const TELEMETRY_WIFI_LINK_METRICS: Method = telemetry(WIFI_LINK_METRICS_METHOD, "wifi_link");
    pub const TELEMETRY_QUIC_METRICS: Method = telemetry(QUIC_METRICS_METHOD, "quic");
    pub const TELEMETRY_QUIC_ASSOCIATIONS: Method =
        telemetry(QUIC_ASSOCIATIONS_METHOD, "quic_associations");
    pub const TELEMETRY_BEARERS: Method = telemetry(BEARERS_METHOD, "bearers");
    pub const TELEMETRY_MEMORY: Method = telemetry(MEMORY_METHOD, "memory");
    pub const TELEMETRY_DEVICE: Method = telemetry(DEVICE_METHOD, "device");

    const fn diagnostic(method: u64, name: &'static str) -> Method {
        Method::new(DIAGNOSTIC_COMPONENT, "", method, name)
    }
    pub const STATUS: Method = diagnostic(DIAGNOSTIC_STATUS_METHOD, "status");
    pub const SERVICES: Method = diagnostic(DIAGNOSTIC_SERVICES_METHOD, "services");

    pub const PROBE_START: Method = Method::new(
        quic_tools::PROBE_COMPONENT,
        "probe",
        quic_tools::PROBE_START,
        "start",
    );
    pub const PROBE_HANDLER: Method = Method::new(
        quic_tools::PROBE_COMPONENT,
        "probe",
        quic_tools::PROBE_HANDLER,
        "handler",
    );
}

/// One inbound request header seen by a unary handler.
#[derive(Clone, Copy, Debug)]
pub struct Call<'a> {
    pub record: Record<'a>,
    pub data: &'a [u8],
    pub fin: bool,
    pub context: CallContext,
}

pub type Reply<'a> = Pin<Box<dyn Future<Output = Option<Vec<u8>>> + Send + 'a>>;

pub trait Handler: Send + Sync + 'static {
    fn call<'a>(&'a self, call: Call<'a>) -> Reply<'a>;
}

/// Policy wrapper serving a method only to local ingress.
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

/// Outcome of opening a registered method on a stream.
pub enum StreamOutcome {
    /// Complete response header with no trailing stream body.
    Header(Vec<u8>),
    /// `discovery.nodes` response header followed by `NodesSource` chunks and `END`.
    Nodes {
        header: Vec<u8>,
        source: dmesh_discovery::nodes::NodesSource,
    },
    /// `probe.handler` upload/download stream exchange.
    Probe {
        id: u64,
        request: quic_tools::ProbeServiceRequest,
    },
}

pub type OpenStreamFuture<'a> = Pin<Box<dyn Future<Output = Option<StreamOutcome>> + Send + 'a>>;

/// Stream-capable method handler registered in [`Registry::register_stream`].
pub trait MethodStreamHandler: Send + Sync + 'static {
    fn open<'a>(&'a self, call: Call<'a>) -> OpenStreamFuture<'a>;
}

struct UnaryStream<H>(H);

impl<H: Handler> MethodStreamHandler for UnaryStream<H> {
    fn open<'a>(&'a self, call: Call<'a>) -> OpenStreamFuture<'a> {
        let reply = self.0.call(call);
        Box::pin(async move { reply.await.map(StreamOutcome::Header) })
    }
}

/// Stream handler for `probe.handler` (`8, 2`) when registered directly on [`Registry`].
#[derive(Clone, Copy, Default)]
pub struct ProbeStreamHandler;

impl MethodStreamHandler for ProbeStreamHandler {
    fn open<'a>(&'a self, call: Call<'a>) -> OpenStreamFuture<'a> {
        let outcome = quic_tools::decode_probe_handler_record(call.record).and_then(|(id, req)| {
            req.is_accepted_by_handler()
                .then_some(StreamOutcome::Probe { id, request: req })
        });
        Box::pin(core::future::ready(outcome))
    }
}

struct Entry {
    method: Method,
    handler: Arc<dyn MethodStreamHandler>,
}

/// Fixed-capacity method table (`REGISTRY_CAPACITY` entries).
#[derive(Default)]
pub struct Registry {
    entries: RwLock<Vec<Entry>>,
}

impl Registry {
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(Vec::new()),
        }
    }

    pub fn register(&self, method: Method, handler: impl Handler) -> bool {
        self.publish(method, Arc::new(UnaryStream(handler)))
    }

    pub fn register_stream(&self, method: Method, handler: impl MethodStreamHandler) -> bool {
        self.publish(method, Arc::new(handler))
    }

    pub fn register_all<H: Handler + Clone>(&self, methods: &[Method], handler: H) -> bool {
        methods
            .iter()
            .all(|method| self.register(*method, handler.clone()))
    }

    fn publish(&self, method: Method, handler: Arc<dyn MethodStreamHandler>) -> bool {
        if method.component == 0 {
            return false;
        }
        let mut guard = self
            .entries
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if guard.len() >= REGISTRY_CAPACITY
            || guard
                .iter()
                .any(|e| e.method.component == method.component && e.method.method == method.method)
        {
            return false;
        }
        guard.push(Entry { method, handler });
        true
    }

    fn lookup(&self, component: u64, method: u64) -> Option<Arc<dyn MethodStreamHandler>> {
        let guard = self
            .entries
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard
            .iter()
            .find(|e| e.method.component == component && e.method.method == method)
            .map(|e| e.handler.clone())
    }

    pub fn methods(&self) -> Vec<Method> {
        let guard = self
            .entries
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut methods: Vec<Method> = guard.iter().map(|e| e.method).collect();
        methods.sort_by_key(|m| (m.component, m.method));
        methods.dedup_by_key(|m| (m.component, m.method));
        methods
    }

    pub async fn open<'a>(
        &self,
        record: Record<'a>,
        header: &'a [u8],
        mut context: CallContext,
    ) -> Option<StreamOutcome> {
        context.timeout_ms = record.timeout.or(context.timeout_ms);
        let (Name::Tag(component), Name::Tag(method)) = (record.component?, record.method?) else {
            return None;
        };
        if let Some(handler) = self.lookup(component, method) {
            let call = Call {
                record,
                data: header,
                fin: true,
                context,
            };
            if let Some(outcome) = handler.open(call).await {
                return Some(outcome);
            }
        }
        error_outcome(&record, context.delivery, component, method, b"unsupported or invalid stream request")
    }

    pub async fn dispatch(&self, data: &[u8], _fin: bool, context: CallContext) -> Option<Vec<u8>> {
        let record = decode(data)?;
        let outcome = self.open(record, data, context).await?;
        match outcome {
            StreamOutcome::Header(header) => Some(header),
            StreamOutcome::Nodes { .. } | StreamOutcome::Probe { .. } => {
                let (Name::Tag(component), Name::Tag(method)) =
                    (record.component?, record.method?)
                else {
                    return None;
                };
                match error_outcome(
                    &record,
                    context.delivery,
                    component,
                    method,
                    b"method requires a stream body",
                )? {
                    StreamOutcome::Header(header) => Some(header),
                    StreamOutcome::Nodes { .. } | StreamOutcome::Probe { .. } => None,
                }
            }
        }
    }
}

fn error_outcome(
    record: &Record<'_>,
    delivery: Delivery,
    component: u64,
    method: u64,
    message: &[u8],
) -> Option<StreamOutcome> {
    if record.to.is_some() || delivery != Delivery::Stream {
        return None;
    }
    let mut response = [0u8; 96];
    let used = encode_numeric_error(component, method, record.id?, message, &mut response)?;
    Some(StreamOutcome::Header(response[..used].to_vec()))
}

/// Object-safe asynchronous byte stream accepted by an application handler.
pub trait AcceptedStream: AsyncRead + AsyncWrite + Unpin {}

impl<T> AcceptedStream for T where T: AsyncRead + AsyncWrite + Unpin {}

pub trait StreamHandler: Send + Sync {
    fn accept<'a>(
        &'a self,
        stream: &'a mut dyn AcceptedStream,
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + 'a>>;
}

/// Serves handler streams (header + optional body + FIN) from a [`Registry`].
#[derive(Clone)]
pub struct RegistryStreamHandler {
    registry: Arc<Registry>,
    local: bool,
    rewrite: Option<fn(&[u8]) -> Option<Vec<u8>>>,
}

impl RegistryStreamHandler {
    pub fn new(registry: Arc<Registry>) -> Self {
        Self {
            registry,
            local: false,
            rewrite: None,
        }
    }

    pub fn local(mut self) -> Self {
        self.local = true;
        self
    }

    pub fn with_header_rewrite(mut self, rewrite: fn(&[u8]) -> Option<Vec<u8>>) -> Self {
        self.rewrite = Some(rewrite);
        self
    }

    pub async fn serve<S>(&self, stream: &mut S) -> io::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + ?Sized,
    {
        let mut buffer = Vec::with_capacity(512);
        let mut chunk = [0u8; 2048];
        let header_len = loop {
            match decode_envelope_prefix(&buffer) {
                PrefixDecode::Complete { body_offset, .. } => break body_offset,
                PrefixDecode::Invalid => {
                    return write_error_and_shutdown(stream, None, b"invalid request header").await;
                }
                PrefixDecode::Incomplete => {
                    let count = stream.read(&mut chunk).await?;
                    if count == 0 {
                        return write_error_and_shutdown(
                            stream,
                            None,
                            b"request ended inside its header",
                        )
                        .await;
                    }
                    buffer.extend_from_slice(&chunk[..count]);
                }
            }
        };
        let pending = buffer.split_off(header_len);
        let mut header = buffer;
        if let Some(rewritten) = self.rewrite.and_then(|rewrite| rewrite(&header)) {
            header = rewritten;
        }
        let Some((record, _)) = decode_prefix(&header) else {
            return write_error_and_shutdown(stream, None, b"invalid request header").await;
        };
        let context = CallContext {
            local: self.local,
            ..Default::default()
        };
        let timeout = record.timeout.map(Duration::from_millis);
        let id = record.id;
        let exchange = async {
            match self.registry.open(record, &header, context).await {
                None => stream.shutdown().await,
                Some(StreamOutcome::Header(resp)) => {
                    stream.write_all(&resp).await?;
                    stream.shutdown().await
                }
                Some(StreamOutcome::Nodes { header, mut source }) => {
                    stream.write_all(&header).await?;
                    while !source.is_done() {
                        if let Some(bytes) = source.peek_chunk() {
                            let n = bytes.len();
                            stream.write_all(bytes).await?;
                            source.consume(n);
                        } else {
                            tokio::time::sleep(Duration::from_millis(10)).await;
                        }
                    }
                    stream.shutdown().await
                }
                Some(StreamOutcome::Probe { id, request }) => {
                    serve_probe_outcome(id, request, &pending, stream).await
                }
            }
        };
        match timeout {
            None => exchange.await,
            Some(limit) => match tokio::time::timeout(limit, exchange).await {
                Ok(result) => result,
                Err(_) => write_error_and_shutdown(stream, id, b"timeout").await,
            },
        }
    }
}

impl StreamHandler for RegistryStreamHandler {
    fn accept<'a>(
        &'a self,
        stream: &'a mut dyn AcceptedStream,
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + 'a>> {
        Box::pin(self.serve(stream))
    }
}

async fn write_error_and_shutdown<S>(
    stream: &mut S,
    id: Option<u64>,
    message: &[u8],
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    stream.write_all(&encode_error_header(id, message)).await?;
    stream.shutdown().await
}

async fn serve_probe_outcome<S>(
    id: u64,
    request: quic_tools::ProbeServiceRequest,
    prefetched_body: &[u8],
    stream: &mut S,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let mut chunk = [0u8; 2048];
    let plan = quic_tools::ProbePlan::from_request(
        request.workload(),
        quic_tools::DEFAULT_PROBE_MAX_STREAM_PAYLOAD,
    );

    if request.upload_bytes() != 0 {
        let mut upload_payload =
            quic_tools::ProbePayload::new(request.upload_bytes(), plan.packet_size).ok_or_else(
                || io::Error::new(io::ErrorKind::InvalidInput, "invalid probe upload"),
            )?;
        let mut rejected = false;
        if !prefetched_body.is_empty()
            && upload_payload
                .consume(prefetched_body, request.verify)
                .is_err()
        {
            rejected = true;
        }
        while !rejected {
            let n = stream.read(&mut chunk).await?;
            if n == 0 {
                if !upload_payload.is_complete() {
                    rejected = true;
                }
                break;
            }
            if upload_payload.consume(&chunk[..n], request.verify).is_err() {
                rejected = true;
                break;
            }
        }
        if rejected {
            let mut err = [0u8; 96];
            if let Some(len) = encode_numeric_error(
                quic_tools::PROBE_COMPONENT,
                quic_tools::PROBE_HANDLER,
                id,
                b"invalid probe upload",
                &mut err,
            ) {
                stream.write_all(&err[..len]).await?;
            }
            return stream.shutdown().await;
        }
    }

    let mut resp_header = [0u8; 96];
    let header_len = quic_tools::encode_probe_handler_upload_response(
        id,
        request.download_bytes(),
        plan.packet_size,
        request.upload_bytes(),
        &mut resp_header,
    )
    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "encode response"))?;
    stream.write_all(&resp_header[..header_len]).await?;

    if request.download_bytes() != 0 {
        let mut down_payload =
            quic_tools::ProbePayload::new(request.download_bytes(), plan.packet_size).ok_or_else(
                || io::Error::new(io::ErrorKind::InvalidInput, "invalid probe download"),
            )?;
        let mut out_chunk = vec![0u8; plan.packet_size.max(8)];
        while !down_payload.is_complete() {
            let count = down_payload.fill(&mut out_chunk);
            stream.write_all(&out_chunk[..count]).await?;
        }
    }
    stream.shutdown().await
}

/// Tag-keyed CBOR map marshalling matching `API.md` field tags.
pub trait TaggedCbor: Sized {
    fn encode_cbor(&self) -> Vec<u8>;
    fn decode_cbor(input: &[u8]) -> Result<Self, String>;
}

pub fn response_with_result(
    component: u64,
    method: u64,
    id: u64,
    result: &[u8],
) -> Option<Vec<u8>> {
    let mut out = vec![0u8; result.len() + 48];
    let used = encode_numeric_response(component, method, id, result, &mut out)?;
    out.truncate(used);
    Some(out)
}

fn numeric_names(record: &Record<'_>) -> Option<(u64, u64)> {
    match (record.component?, record.method?) {
        (Name::Tag(component), Name::Tag(method)) => Some((component, method)),
        _ => None,
    }
}

/// Typed registry handler decoding request tags and encoding correlated response tags.
pub struct TypedHandler<Req, Resp, F> {
    handler: F,
    _types: PhantomData<fn(Req) -> Resp>,
}

impl<Req, Resp, F> TypedHandler<Req, Resp, F> {
    pub fn new(handler: F) -> Self {
        Self {
            handler,
            _types: PhantomData,
        }
    }
}

impl<Req, Resp, F: Clone> Clone for TypedHandler<Req, Resp, F> {
    fn clone(&self) -> Self {
        Self::new(self.handler.clone())
    }
}

impl<Req, Resp, F, Fut> Handler for TypedHandler<Req, Resp, F>
where
    Req: TaggedCbor + Send + 'static,
    Resp: TaggedCbor + Send + 'static,
    F: Fn(Req, CallContext) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<Resp, String>> + Send + 'static,
{
    fn call<'a>(&'a self, call: Call<'a>) -> Reply<'a> {
        Box::pin(async move {
            let id = call.record.id?;
            let (component, method) = numeric_names(&call.record)?;
            let outcome = match Req::decode_cbor(call.record.fields.unwrap_or(&[0xa0])) {
                Ok(request) => (self.handler)(request, call.context).await,
                Err(error) => Err(format!("invalid request: {error}")),
            };
            match outcome {
                Ok(value) => response_with_result(component, method, id, &value.encode_cbor()),
                Err(message) => {
                    let mut out = vec![0u8; message.len() + 48];
                    encode_numeric_error(component, method, id, message.as_bytes(), &mut out).map(
                        |used| {
                            out.truncate(used);
                            out
                        },
                    )
                }
            }
        })
    }
}

// --- Compact tag-keyed CBOR API structs (`API.md`) ---

fn encode_with_growth(mut write_fn: impl FnMut(&mut [u8]) -> Option<usize>) -> Vec<u8> {
    let mut size = 256;
    loop {
        let mut out = vec![0u8; size];
        if let Some(used) = write_fn(&mut out) {
            out.truncate(used);
            return out;
        }
        size *= 2;
    }
}

fn decode_empty_map<T: Default>(input: &[u8]) -> Result<T, String> {
    let mut d = Decoder::new(input);
    let (major, count) = d.head().ok_or("not a CBOR map")?;
    if major != 5 {
        return Err("not a CBOR map".to_owned());
    }
    for _ in 0..count {
        let _ = d.uint().ok_or("invalid field tag")?;
        d.skip().ok_or("invalid value")?;
    }
    Ok(T::default())
}

fn read_text(d: &mut Decoder<'_>) -> Result<String, String> {
    String::from_utf8(d.text_ref().ok_or("invalid text")?.to_vec())
        .map_err(|_| "invalid UTF-8".to_owned())
}

fn read_u8(d: &mut Decoder<'_>) -> Result<u8, String> {
    u8::try_from(d.uint().ok_or("invalid unsigned integer")?)
        .map_err(|_| "integer out of range".to_owned())
}

fn read_u16(d: &mut Decoder<'_>) -> Result<u16, String> {
    u16::try_from(d.uint().ok_or("invalid unsigned integer")?)
        .map_err(|_| "integer out of range".to_owned())
}

fn read_u32(d: &mut Decoder<'_>) -> Result<u32, String> {
    u32::try_from(d.uint().ok_or("invalid unsigned integer")?)
        .map_err(|_| "integer out of range".to_owned())
}

fn read_u64(d: &mut Decoder<'_>) -> Result<u64, String> {
    Ok(d.uint().ok_or("invalid unsigned integer")?)
}

fn read_i8(d: &mut Decoder<'_>) -> Result<i8, String> {
    i8::try_from(d.int().ok_or("invalid integer")?)
        .map_err(|_| "integer out of range".to_owned())
}

fn read_i32(d: &mut Decoder<'_>) -> Result<i32, String> {
    i32::try_from(d.int().ok_or("invalid integer")?)
        .map_err(|_| "integer out of range".to_owned())
}

fn read_bool(d: &mut Decoder<'_>) -> Result<bool, String> {
    d.boolean().ok_or_else(|| "invalid bool".to_owned())
}

macro_rules! empty_cbor_struct {
    ($name:ident) => {
        #[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
        pub struct $name;

        impl TaggedCbor for $name {
            fn encode_cbor(&self) -> Vec<u8> {
                vec![0xa0]
            }

            fn decode_cbor(input: &[u8]) -> Result<Self, String> {
                decode_empty_map(input)
            }
        }
    };
}

empty_cbor_struct!(DiscoveryActiveResponse);
empty_cbor_struct!(TransportSetResponse);
empty_cbor_struct!(CompanionPairResponse);
empty_cbor_struct!(CompanionUnpairResponse);
empty_cbor_struct!(TelemetryNanStatusRequest);
empty_cbor_struct!(TelemetryNowRequest);
empty_cbor_struct!(TelemetryNanRequest);
empty_cbor_struct!(TelemetryUdp6Request);
empty_cbor_struct!(TelemetryWifiLinkRequest);
empty_cbor_struct!(TelemetryQuicRequest);
empty_cbor_struct!(TelemetryQuicAssociationsRequest);
empty_cbor_struct!(TelemetryBearersRequest);
empty_cbor_struct!(TelemetryMemoryRequest);

#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct DiscoveryActiveRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub medium: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
}

impl TaggedCbor for DiscoveryActiveRequest {
    fn encode_cbor(&self) -> Vec<u8> {
        encode_with_growth(|out| {
            let mut e = Encoder::new(out);
            e.map(u64::from(self.medium.is_some()) + u64::from(self.to.is_some()))?;
            if let Some(v) = &self.medium {
                e.uint(40)?;
                e.text_value(v.as_bytes())?;
            }
            if let Some(v) = &self.to {
                e.uint(41)?;
                e.text_value(v.as_bytes())?;
            }
            Some(e.len())
        })
    }

    fn decode_cbor(input: &[u8]) -> Result<Self, String> {
        let mut d = Decoder::new(input);
        let (major, count) = d.head().ok_or("not a CBOR map")?;
        if major != 5 {
            return Err("not a CBOR map".to_owned());
        }
        let mut out = Self::default();
        for _ in 0..count {
            match d.uint().ok_or("invalid field tag")? {
                40 => out.medium = Some(read_text(&mut d)?),
                41 => out.to = Some(read_text(&mut d)?),
                _ => d.skip().ok_or("invalid value")?,
            }
        }
        Ok(out)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct CompanionPairRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vip6: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baud: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub psm: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_public_key_b64: Option<String>,
}

impl TaggedCbor for CompanionPairRequest {
    fn encode_cbor(&self) -> Vec<u8> {
        encode_with_growth(|out| {
            let mut e = Encoder::new(out);
            let n = u64::from(self.kind.is_some())
                + u64::from(self.id.is_some())
                + u64::from(self.vip6.is_some())
                + u64::from(self.baud.is_some())
                + u64::from(self.psm.is_some())
                + u64::from(self.name.is_some())
                + u64::from(self.root_public_key_b64.is_some());
            e.map(n)?;
            if let Some(v) = &self.kind {
                e.uint(1)?;
                e.text_value(v.as_bytes())?;
            }
            if let Some(v) = &self.id {
                e.uint(2)?;
                e.text_value(v.as_bytes())?;
            }
            if let Some(v) = &self.vip6 {
                e.uint(3)?;
                e.text_value(v.as_bytes())?;
            }
            if let Some(v) = &self.baud {
                e.uint(4)?;
                e.uint(u64::from(*v))?;
            }
            if let Some(v) = &self.psm {
                e.uint(5)?;
                e.uint(u64::from(*v))?;
            }
            if let Some(v) = &self.name {
                e.uint(6)?;
                e.text_value(v.as_bytes())?;
            }
            if let Some(v) = &self.root_public_key_b64 {
                e.uint(7)?;
                e.text_value(v.as_bytes())?;
            }
            Some(e.len())
        })
    }

    fn decode_cbor(input: &[u8]) -> Result<Self, String> {
        let mut d = Decoder::new(input);
        let (major, count) = d.head().ok_or("not a CBOR map")?;
        if major != 5 {
            return Err("not a CBOR map".to_owned());
        }
        let mut out = Self::default();
        for _ in 0..count {
            match d.uint().ok_or("invalid field tag")? {
                1 => out.kind = Some(read_text(&mut d)?),
                2 => out.id = Some(read_text(&mut d)?),
                3 => out.vip6 = Some(read_text(&mut d)?),
                4 => out.baud = Some(read_u32(&mut d)?),
                5 => out.psm = Some(read_u16(&mut d)?),
                6 => out.name = Some(read_text(&mut d)?),
                7 => out.root_public_key_b64 = Some(read_text(&mut d)?),
                _ => d.skip().ok_or("invalid value")?,
            }
        }
        Ok(out)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct CompanionUnpairRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

impl TaggedCbor for CompanionUnpairRequest {
    fn encode_cbor(&self) -> Vec<u8> {
        encode_with_growth(|out| {
            let mut e = Encoder::new(out);
            e.map(u64::from(self.kind.is_some()) + u64::from(self.id.is_some()))?;
            if let Some(v) = &self.kind {
                e.uint(1)?;
                e.text_value(v.as_bytes())?;
            }
            if let Some(v) = &self.id {
                e.uint(2)?;
                e.text_value(v.as_bytes())?;
            }
            Some(e.len())
        })
    }

    fn decode_cbor(input: &[u8]) -> Result<Self, String> {
        let mut d = Decoder::new(input);
        let (major, count) = d.head().ok_or("not a CBOR map")?;
        if major != 5 {
            return Err("not a CBOR map".to_owned());
        }
        let mut out = Self::default();
        for _ in 0..count {
            match d.uint().ok_or("invalid field tag")? {
                1 => out.kind = Some(read_text(&mut d)?),
                2 => out.id = Some(read_text(&mut d)?),
                _ => d.skip().ok_or("invalid value")?,
            }
        }
        Ok(out)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct TransportSetRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bssid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_tx_rate: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sta_driver_tx: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sta_bssid_check_disabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sta_ampdu_enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sta_11b_rates_disabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sta_raw_rx_enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub espnow_capture: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nan_dw_interval: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub now: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ap: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passphrase: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uart: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ndp: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub open: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wake_target: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ble: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iface: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uart_mode: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uart_baud: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uart_port: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub radio_mode: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub radio_frequency: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub radio_bandwidth: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub radio_bitrate: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub radio_tx_power: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub radio_spreading_factor: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub radio_coding_rate: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ap_ssid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ap_passphrase: Option<String>,
}

impl TaggedCbor for TransportSetRequest {
    fn encode_cbor(&self) -> Vec<u8> {
        encode_with_growth(|out| {
            let mut e = Encoder::new(out);
            let n = u64::from(self.mode.is_some())
                + u64::from(self.ssid.is_some())
                + u64::from(self.bssid.is_some())
                + u64::from(self.channel.is_some())
                + u64::from(self.raw_tx_rate.is_some())
                + u64::from(self.sta_driver_tx.is_some())
                + u64::from(self.sta_bssid_check_disabled.is_some())
                + u64::from(self.sta_ampdu_enabled.is_some())
                + u64::from(self.sta_11b_rates_disabled.is_some())
                + u64::from(self.sta_raw_rx_enabled.is_some())
                + u64::from(self.espnow_capture.is_some())
                + u64::from(self.nan_dw_interval.is_some())
                + u64::from(self.now.is_some())
                + u64::from(self.ap.is_some())
                + u64::from(self.passphrase.is_some())
                + u64::from(self.uart.is_some())
                + u64::from(self.ndp.is_some())
                + u64::from(self.open.is_some())
                + u64::from(self.wake_target.is_some())
                + u64::from(self.ble.is_some())
                + u64::from(self.iface.is_some())
                + u64::from(self.uart_mode.is_some())
                + u64::from(self.uart_baud.is_some())
                + u64::from(self.uart_port.is_some())
                + u64::from(self.radio_mode.is_some())
                + u64::from(self.radio_frequency.is_some())
                + u64::from(self.radio_bandwidth.is_some())
                + u64::from(self.radio_bitrate.is_some())
                + u64::from(self.radio_tx_power.is_some())
                + u64::from(self.radio_spreading_factor.is_some())
                + u64::from(self.radio_coding_rate.is_some())
                + u64::from(self.ap_ssid.is_some())
                + u64::from(self.ap_passphrase.is_some());
            e.map(n)?;
            if let Some(v) = &self.mode { e.uint(1)?; e.uint(u64::from(*v))?; }
            if let Some(v) = &self.ssid { e.uint(2)?; e.text_value(v.as_bytes())?; }
            if let Some(v) = &self.bssid { e.uint(3)?; e.text_value(v.as_bytes())?; }
            if let Some(v) = &self.channel { e.uint(4)?; e.uint(u64::from(*v))?; }
            if let Some(v) = &self.raw_tx_rate { e.uint(5)?; e.uint(u64::from(*v))?; }
            if let Some(v) = &self.sta_driver_tx { e.uint(6)?; e.boolean(*v)?; }
            if let Some(v) = &self.sta_bssid_check_disabled { e.uint(7)?; e.boolean(*v)?; }
            if let Some(v) = &self.sta_ampdu_enabled { e.uint(8)?; e.boolean(*v)?; }
            if let Some(v) = &self.sta_11b_rates_disabled { e.uint(9)?; e.boolean(*v)?; }
            if let Some(v) = &self.sta_raw_rx_enabled { e.uint(10)?; e.boolean(*v)?; }
            if let Some(v) = &self.espnow_capture { e.uint(13)?; e.boolean(*v)?; }
            if let Some(v) = &self.nan_dw_interval { e.uint(14)?; e.uint(u64::from(*v))?; }
            if let Some(v) = &self.now { e.uint(15)?; e.uint(u64::from(*v))?; }
            if let Some(v) = &self.ap { e.uint(16)?; e.uint(u64::from(*v))?; }
            if let Some(v) = &self.passphrase { e.uint(17)?; e.text_value(v.as_bytes())?; }
            if let Some(v) = &self.uart { e.uint(18)?; e.uint(u64::from(*v))?; }
            if let Some(v) = &self.ndp { e.uint(19)?; e.uint(u64::from(*v))?; }
            if let Some(v) = &self.open { e.uint(24)?; e.boolean(*v)?; }
            if let Some(v) = &self.wake_target { e.uint(25)?; e.text_value(v.as_bytes())?; }
            if let Some(v) = &self.ble { e.uint(26)?; e.uint(u64::from(*v))?; }
            if let Some(v) = &self.iface { e.uint(27)?; e.text_value(v.as_bytes())?; }
            if let Some(v) = &self.uart_mode { e.uint(28)?; e.uint(u64::from(*v))?; }
            if let Some(v) = &self.uart_baud { e.uint(29)?; e.uint(u64::from(*v))?; }
            if let Some(v) = &self.uart_port { e.uint(30)?; e.uint(u64::from(*v))?; }
            if let Some(v) = &self.radio_mode { e.uint(31)?; e.uint(u64::from(*v))?; }
            if let Some(v) = &self.radio_frequency { e.uint(32)?; e.uint(u64::from(*v))?; }
            if let Some(v) = &self.radio_bandwidth { e.uint(33)?; e.uint(u64::from(*v))?; }
            if let Some(v) = &self.radio_bitrate { e.uint(34)?; e.uint(u64::from(*v))?; }
            if let Some(v) = &self.radio_tx_power { e.uint(35)?; e.int(i64::from(*v))?; }
            if let Some(v) = &self.radio_spreading_factor { e.uint(36)?; e.uint(u64::from(*v))?; }
            if let Some(v) = &self.radio_coding_rate { e.uint(37)?; e.uint(u64::from(*v))?; }
            if let Some(v) = &self.ap_ssid { e.uint(38)?; e.text_value(v.as_bytes())?; }
            if let Some(v) = &self.ap_passphrase { e.uint(39)?; e.text_value(v.as_bytes())?; }
            Some(e.len())
        })
    }

    fn decode_cbor(input: &[u8]) -> Result<Self, String> {
        let mut d = Decoder::new(input);
        let (major, count) = d.head().ok_or("not a CBOR map")?;
        if major != 5 {
            return Err("not a CBOR map".to_owned());
        }
        let mut out = Self::default();
        for _ in 0..count {
            match d.uint().ok_or("invalid field tag")? {
                1 => out.mode = Some(read_u8(&mut d)?),
                2 => out.ssid = Some(read_text(&mut d)?),
                3 => out.bssid = Some(read_text(&mut d)?),
                4 => out.channel = Some(read_u8(&mut d)?),
                5 => out.raw_tx_rate = Some(read_u8(&mut d)?),
                6 => out.sta_driver_tx = Some(read_bool(&mut d)?),
                7 => out.sta_bssid_check_disabled = Some(read_bool(&mut d)?),
                8 => out.sta_ampdu_enabled = Some(read_bool(&mut d)?),
                9 => out.sta_11b_rates_disabled = Some(read_bool(&mut d)?),
                10 => out.sta_raw_rx_enabled = Some(read_bool(&mut d)?),
                13 => out.espnow_capture = Some(read_bool(&mut d)?),
                14 => out.nan_dw_interval = Some(read_u8(&mut d)?),
                15 => out.now = Some(read_u8(&mut d)?),
                16 => out.ap = Some(read_u8(&mut d)?),
                17 => out.passphrase = Some(read_text(&mut d)?),
                18 => out.uart = Some(read_u8(&mut d)?),
                19 => out.ndp = Some(read_u8(&mut d)?),
                24 => out.open = Some(read_bool(&mut d)?),
                25 => out.wake_target = Some(read_text(&mut d)?),
                26 => out.ble = Some(read_u8(&mut d)?),
                27 => out.iface = Some(read_text(&mut d)?),
                28 => out.uart_mode = Some(read_u8(&mut d)?),
                29 => out.uart_baud = Some(read_u32(&mut d)?),
                30 => out.uart_port = Some(read_u8(&mut d)?),
                31 => out.radio_mode = Some(read_u8(&mut d)?),
                32 => out.radio_frequency = Some(read_u32(&mut d)?),
                33 => out.radio_bandwidth = Some(read_u32(&mut d)?),
                34 => out.radio_bitrate = Some(read_u32(&mut d)?),
                35 => out.radio_tx_power = Some(read_i32(&mut d)?),
                36 => out.radio_spreading_factor = Some(read_u8(&mut d)?),
                37 => out.radio_coding_rate = Some(read_u8(&mut d)?),
                38 => out.ap_ssid = Some(read_text(&mut d)?),
                39 => out.ap_passphrase = Some(read_text(&mut d)?),
                _ => d.skip().ok_or("invalid value")?,
            }
        }
        Ok(out)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct TelemetryNanStatusResponse {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cluster_id: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sync_id: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publishing: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publish_pending: Option<bool>,
}

impl TaggedCbor for TelemetryNanStatusResponse {
    fn encode_cbor(&self) -> Vec<u8> {
        encode_with_growth(|out| {
            let mut e = Encoder::new(out);
            let n = u64::from(self.active.is_some())
                + u64::from(self.cluster_id.is_some())
                + u64::from(self.sync_id.is_some())
                + u64::from(self.publishing.is_some())
                + u64::from(self.publish_pending.is_some());
            e.map(n)?;
            if let Some(v) = &self.active { e.uint(1)?; e.boolean(*v)?; }
            if let Some(v) = &self.cluster_id { e.uint(2)?; e.bytes_value(v)?; }
            if let Some(v) = &self.sync_id { e.uint(3)?; e.bytes_value(v)?; }
            if let Some(v) = &self.publishing { e.uint(4)?; e.boolean(*v)?; }
            if let Some(v) = &self.publish_pending { e.uint(5)?; e.boolean(*v)?; }
            Some(e.len())
        })
    }

    fn decode_cbor(input: &[u8]) -> Result<Self, String> {
        let mut d = Decoder::new(input);
        let (major, count) = d.head().ok_or("not a CBOR map")?;
        if major != 5 {
            return Err("not a CBOR map".to_owned());
        }
        let mut out = Self::default();
        for _ in 0..count {
            match d.uint().ok_or("invalid field tag")? {
                1 => out.active = Some(read_bool(&mut d)?),
                2 => out.cluster_id = Some(d.bytes_ref().ok_or("invalid byte string")?.to_vec()),
                3 => out.sync_id = Some(d.bytes_ref().ok_or("invalid byte string")?.to_vec()),
                4 => out.publishing = Some(read_bool(&mut d)?),
                5 => out.publish_pending = Some(read_bool(&mut d)?),
                _ => d.skip().ok_or("invalid value")?,
            }
        }
        Ok(out)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct TelemetryNowResponse {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tx_attempted: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tx_accepted: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tx_failed: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rx_dispatched: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rx_accepted: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rx_rejected: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rx_self_echo: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rx_dropped: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registered_actions: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registered_drops: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_roc_body_prefix: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_roc_body_len: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rx_invalid_drops: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rx_busy_drops: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rx_shared_ingress_drops: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_registered_body_prefix: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_registered_body_len: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tx_busy: Option<u64>,
}

impl TaggedCbor for TelemetryNowResponse {
    fn encode_cbor(&self) -> Vec<u8> {
        let fields = [
            (1, self.tx_attempted),
            (2, self.tx_accepted),
            (3, self.tx_failed),
            (4, self.rx_dispatched),
            (5, self.rx_accepted),
            (6, self.rx_rejected),
            (7, self.rx_self_echo),
            (8, self.rx_dropped),
            (9, self.registered_actions),
            (10, self.registered_drops),
            (11, self.last_roc_body_prefix),
            (12, self.last_roc_body_len),
            (13, self.rx_invalid_drops),
            (14, self.rx_busy_drops),
            (15, self.rx_shared_ingress_drops),
            (16, self.last_registered_body_prefix),
            (17, self.last_registered_body_len),
            (18, self.tx_busy),
        ];
        encode_u64_map(&fields)
    }

    fn decode_cbor(input: &[u8]) -> Result<Self, String> {
        let mut d = Decoder::new(input);
        let (major, count) = d.head().ok_or("not a CBOR map")?;
        if major != 5 {
            return Err("not a CBOR map".to_owned());
        }
        let mut out = Self::default();
        for _ in 0..count {
            match d.uint().ok_or("invalid field tag")? {
                1 => out.tx_attempted = Some(read_u64(&mut d)?),
                2 => out.tx_accepted = Some(read_u64(&mut d)?),
                3 => out.tx_failed = Some(read_u64(&mut d)?),
                4 => out.rx_dispatched = Some(read_u64(&mut d)?),
                5 => out.rx_accepted = Some(read_u64(&mut d)?),
                6 => out.rx_rejected = Some(read_u64(&mut d)?),
                7 => out.rx_self_echo = Some(read_u64(&mut d)?),
                8 => out.rx_dropped = Some(read_u64(&mut d)?),
                9 => out.registered_actions = Some(read_u64(&mut d)?),
                10 => out.registered_drops = Some(read_u64(&mut d)?),
                11 => out.last_roc_body_prefix = Some(read_u64(&mut d)?),
                12 => out.last_roc_body_len = Some(read_u64(&mut d)?),
                13 => out.rx_invalid_drops = Some(read_u64(&mut d)?),
                14 => out.rx_busy_drops = Some(read_u64(&mut d)?),
                15 => out.rx_shared_ingress_drops = Some(read_u64(&mut d)?),
                16 => out.last_registered_body_prefix = Some(read_u64(&mut d)?),
                17 => out.last_registered_body_len = Some(read_u64(&mut d)?),
                18 => out.tx_busy = Some(read_u64(&mut d)?),
                _ => d.skip().ok_or("invalid value")?,
            }
        }
        Ok(out)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct TelemetryNanResponse {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub beacons: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sdfs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub followups_rx: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub followups_queued: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub followups_sent: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub followups_dropped: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_info_matched: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_info_enqueued: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_info_dropped: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_info_dispatched: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_publish_attempted: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_publish_sent: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_publish_dropped: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_discovery_queued: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_discovery_sent: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_discovery_dropped: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dw8_radio_stop_us: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dw8_radio_resume_us: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dw8_awake_us: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_sdf_after_beacon_us: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_sdf_frame_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_sdf_source_le: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub small_sdf_max_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub small_sdf_max_source_le: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_sdf_queued: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_sdf_rejected: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_sdf_tx_attempted: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_sdf_tx_accepted: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_sdf_completed: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_sdf_count: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub light_sleep_attempts: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub light_sleep_entries: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub light_sleep_skipped: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_sleep_requested_us: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_sleep_duration_us: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_frame_after_wake_us: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_beacon_after_wake_us: Option<u64>,
}

impl TaggedCbor for TelemetryNanResponse {
    fn encode_cbor(&self) -> Vec<u8> {
        let fields = [
            (1, self.beacons),
            (2, self.sdfs),
            (3, self.followups_rx),
            (4, self.followups_queued),
            (5, self.followups_sent),
            (6, self.followups_dropped),
            (7, self.service_info_matched),
            (8, self.service_info_enqueued),
            (9, self.service_info_dropped),
            (10, self.service_info_dispatched),
            (11, self.active_publish_attempted),
            (12, self.active_publish_sent),
            (13, self.active_publish_dropped),
            (14, self.active_discovery_queued),
            (15, self.active_discovery_sent),
            (16, self.active_discovery_dropped),
            (17, self.dw8_radio_stop_us),
            (18, self.dw8_radio_resume_us),
            (19, self.dw8_awake_us),
            (20, self.last_sdf_after_beacon_us),
            (21, self.last_sdf_frame_bytes),
            (22, self.last_sdf_source_le),
            (23, self.small_sdf_max_bytes),
            (24, self.small_sdf_max_source_le),
            (25, self.pending_sdf_queued),
            (26, self.pending_sdf_rejected),
            (27, self.pending_sdf_tx_attempted),
            (28, self.pending_sdf_tx_accepted),
            (29, self.pending_sdf_completed),
            (30, self.pending_sdf_count),
            (31, self.light_sleep_attempts),
            (32, self.light_sleep_entries),
            (33, self.light_sleep_skipped),
            (34, self.last_sleep_requested_us),
            (35, self.last_sleep_duration_us),
            (36, self.first_frame_after_wake_us),
            (37, self.first_beacon_after_wake_us),
        ];
        encode_u64_map(&fields)
    }

    fn decode_cbor(input: &[u8]) -> Result<Self, String> {
        let mut d = Decoder::new(input);
        let (major, count) = d.head().ok_or("not a CBOR map")?;
        if major != 5 {
            return Err("not a CBOR map".to_owned());
        }
        let mut out = Self::default();
        for _ in 0..count {
            match d.uint().ok_or("invalid field tag")? {
                1 => out.beacons = Some(read_u64(&mut d)?),
                2 => out.sdfs = Some(read_u64(&mut d)?),
                3 => out.followups_rx = Some(read_u64(&mut d)?),
                4 => out.followups_queued = Some(read_u64(&mut d)?),
                5 => out.followups_sent = Some(read_u64(&mut d)?),
                6 => out.followups_dropped = Some(read_u64(&mut d)?),
                7 => out.service_info_matched = Some(read_u64(&mut d)?),
                8 => out.service_info_enqueued = Some(read_u64(&mut d)?),
                9 => out.service_info_dropped = Some(read_u64(&mut d)?),
                10 => out.service_info_dispatched = Some(read_u64(&mut d)?),
                11 => out.active_publish_attempted = Some(read_u64(&mut d)?),
                12 => out.active_publish_sent = Some(read_u64(&mut d)?),
                13 => out.active_publish_dropped = Some(read_u64(&mut d)?),
                14 => out.active_discovery_queued = Some(read_u64(&mut d)?),
                15 => out.active_discovery_sent = Some(read_u64(&mut d)?),
                16 => out.active_discovery_dropped = Some(read_u64(&mut d)?),
                17 => out.dw8_radio_stop_us = Some(read_u64(&mut d)?),
                18 => out.dw8_radio_resume_us = Some(read_u64(&mut d)?),
                19 => out.dw8_awake_us = Some(read_u64(&mut d)?),
                20 => out.last_sdf_after_beacon_us = Some(read_u64(&mut d)?),
                21 => out.last_sdf_frame_bytes = Some(read_u64(&mut d)?),
                22 => out.last_sdf_source_le = Some(read_u64(&mut d)?),
                23 => out.small_sdf_max_bytes = Some(read_u64(&mut d)?),
                24 => out.small_sdf_max_source_le = Some(read_u64(&mut d)?),
                25 => out.pending_sdf_queued = Some(read_u64(&mut d)?),
                26 => out.pending_sdf_rejected = Some(read_u64(&mut d)?),
                27 => out.pending_sdf_tx_attempted = Some(read_u64(&mut d)?),
                28 => out.pending_sdf_tx_accepted = Some(read_u64(&mut d)?),
                29 => out.pending_sdf_completed = Some(read_u64(&mut d)?),
                30 => out.pending_sdf_count = Some(read_u64(&mut d)?),
                31 => out.light_sleep_attempts = Some(read_u64(&mut d)?),
                32 => out.light_sleep_entries = Some(read_u64(&mut d)?),
                33 => out.light_sleep_skipped = Some(read_u64(&mut d)?),
                34 => out.last_sleep_requested_us = Some(read_u64(&mut d)?),
                35 => out.last_sleep_duration_us = Some(read_u64(&mut d)?),
                36 => out.first_frame_after_wake_us = Some(read_u64(&mut d)?),
                37 => out.first_beacon_after_wake_us = Some(read_u64(&mut d)?),
                _ => d.skip().ok_or("invalid value")?,
            }
        }
        Ok(out)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct TelemetryUdp6Response {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rx_frames: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rx_queue_drops: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rx_invalid: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub udp_delivered: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ndp_advertisements: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tx_failures: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_tx_completions: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_tx_completion_failures: Option<u64>,
}

impl TaggedCbor for TelemetryUdp6Response {
    fn encode_cbor(&self) -> Vec<u8> {
        let fields = [
            (1, self.rx_frames),
            (2, self.rx_queue_drops),
            (3, self.rx_invalid),
            (4, self.udp_delivered),
            (5, self.ndp_advertisements),
            (6, self.tx_failures),
            (7, self.raw_tx_completions),
            (8, self.raw_tx_completion_failures),
        ];
        encode_u64_map(&fields)
    }

    fn decode_cbor(input: &[u8]) -> Result<Self, String> {
        let mut d = Decoder::new(input);
        let (major, count) = d.head().ok_or("not a CBOR map")?;
        if major != 5 {
            return Err("not a CBOR map".to_owned());
        }
        let mut out = Self::default();
        for _ in 0..count {
            match d.uint().ok_or("invalid field tag")? {
                1 => out.rx_frames = Some(read_u64(&mut d)?),
                2 => out.rx_queue_drops = Some(read_u64(&mut d)?),
                3 => out.rx_invalid = Some(read_u64(&mut d)?),
                4 => out.udp_delivered = Some(read_u64(&mut d)?),
                5 => out.ndp_advertisements = Some(read_u64(&mut d)?),
                6 => out.tx_failures = Some(read_u64(&mut d)?),
                7 => out.raw_tx_completions = Some(read_u64(&mut d)?),
                8 => out.raw_tx_completion_failures = Some(read_u64(&mut d)?),
                _ => d.skip().ok_or("invalid value")?,
            }
        }
        Ok(out)
    }
}

fn encode_u64_map(fields: &[(u64, Option<u64>)]) -> Vec<u8> {
    encode_with_growth(|out| {
        let mut e = Encoder::new(out);
        let present = fields.iter().filter(|(_, v)| v.is_some()).count() as u64;
        e.map(present)?;
        for (tag, value) in fields {
            if let Some(v) = value {
                e.uint(*tag)?;
                e.uint(*v)?;
            }
        }
        Some(e.len())
    })
}

/// One `WifiLink` row (`peer_mac` tag `3` is encoded as a CBOR byte string).
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct WifiLink {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema_version: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface_index: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_mac: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rx_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tx_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rx_packets: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tx_packets: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac_tx_retries: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac_tx_failed: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rx_dropped: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rx_airtime_us: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tx_airtime_us: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signal_dbm: Option<i8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signal_avg_dbm: Option<i8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ack_signal_dbm: Option<i8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ack_signal_avg_dbm: Option<i8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rx_bitrate_kbit_s: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tx_bitrate_kbit_s: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_throughput_kbit_s: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bearer_rx_frames: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bearer_rx_drops: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bearer_rx_invalid: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bearer_udp_delivered: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bearer_ndp_advertisements: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bearer_tx_failures: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_tx_completion_failures: Option<u64>,
}

impl From<&dmesh_rawnan::raw_wifi::WifiLinkMetrics> for WifiLink {
    fn from(link: &dmesh_rawnan::raw_wifi::WifiLinkMetrics) -> Self {
        Self {
            schema_version: Some(link.schema_version),
            peer_mac: link.peer_mac.map(|mac| mac.to_vec()),
            interface_index: link.interface_index,
            rx_bytes: link.rx_bytes,
            tx_bytes: link.tx_bytes,
            rx_packets: link.rx_packets,
            tx_packets: link.tx_packets,
            mac_tx_retries: link.mac_tx_retries,
            mac_tx_failed: link.mac_tx_failed,
            rx_dropped: link.rx_dropped,
            rx_airtime_us: link.rx_airtime_us,
            tx_airtime_us: link.tx_airtime_us,
            signal_dbm: link.signal_dbm,
            signal_avg_dbm: link.signal_avg_dbm,
            ack_signal_dbm: link.ack_signal_dbm,
            ack_signal_avg_dbm: link.ack_signal_avg_dbm,
            rx_bitrate_kbit_s: link.rx_bitrate_kbit_s,
            tx_bitrate_kbit_s: link.tx_bitrate_kbit_s,
            expected_throughput_kbit_s: link.expected_throughput_kbit_s,
            bearer_rx_frames: link.bearer_rx_frames,
            bearer_rx_drops: link.bearer_rx_drops,
            bearer_rx_invalid: link.bearer_rx_invalid,
            bearer_udp_delivered: link.bearer_udp_delivered,
            bearer_ndp_advertisements: link.bearer_ndp_advertisements,
            bearer_tx_failures: link.bearer_tx_failures,
            raw_tx_completion_failures: link.raw_tx_completion_failures,
        }
    }
}

impl WifiLink {
    fn field_count(&self) -> u64 {
        u64::from(self.schema_version.is_some())
            + u64::from(self.interface_index.is_some())
            + u64::from(self.peer_mac.is_some())
            + u64::from(self.rx_bytes.is_some())
            + u64::from(self.tx_bytes.is_some())
            + u64::from(self.rx_packets.is_some())
            + u64::from(self.tx_packets.is_some())
            + u64::from(self.mac_tx_retries.is_some())
            + u64::from(self.mac_tx_failed.is_some())
            + u64::from(self.rx_dropped.is_some())
            + u64::from(self.rx_airtime_us.is_some())
            + u64::from(self.tx_airtime_us.is_some())
            + u64::from(self.signal_dbm.is_some())
            + u64::from(self.signal_avg_dbm.is_some())
            + u64::from(self.ack_signal_dbm.is_some())
            + u64::from(self.ack_signal_avg_dbm.is_some())
            + u64::from(self.rx_bitrate_kbit_s.is_some())
            + u64::from(self.tx_bitrate_kbit_s.is_some())
            + u64::from(self.expected_throughput_kbit_s.is_some())
            + u64::from(self.bearer_rx_frames.is_some())
            + u64::from(self.bearer_rx_drops.is_some())
            + u64::from(self.bearer_rx_invalid.is_some())
            + u64::from(self.bearer_udp_delivered.is_some())
            + u64::from(self.bearer_ndp_advertisements.is_some())
            + u64::from(self.bearer_tx_failures.is_some())
            + u64::from(self.raw_tx_completion_failures.is_some())
    }

    fn write_fields(&self, e: &mut Encoder<'_>) -> Option<()> {
        if let Some(v) = &self.schema_version { e.uint(1)?; e.uint(u64::from(*v))?; }
        if let Some(v) = &self.interface_index { e.uint(2)?; e.uint(u64::from(*v))?; }
        if let Some(v) = &self.peer_mac { e.uint(3)?; e.bytes_value(v)?; }
        if let Some(v) = &self.rx_bytes { e.uint(4)?; e.uint(*v)?; }
        if let Some(v) = &self.tx_bytes { e.uint(5)?; e.uint(*v)?; }
        if let Some(v) = &self.rx_packets { e.uint(6)?; e.uint(*v)?; }
        if let Some(v) = &self.tx_packets { e.uint(7)?; e.uint(*v)?; }
        if let Some(v) = &self.mac_tx_retries { e.uint(8)?; e.uint(*v)?; }
        if let Some(v) = &self.mac_tx_failed { e.uint(9)?; e.uint(*v)?; }
        if let Some(v) = &self.rx_dropped { e.uint(10)?; e.uint(*v)?; }
        if let Some(v) = &self.rx_airtime_us { e.uint(11)?; e.uint(*v)?; }
        if let Some(v) = &self.tx_airtime_us { e.uint(12)?; e.uint(*v)?; }
        if let Some(v) = &self.signal_dbm { e.uint(13)?; e.int(i64::from(*v))?; }
        if let Some(v) = &self.signal_avg_dbm { e.uint(14)?; e.int(i64::from(*v))?; }
        if let Some(v) = &self.ack_signal_dbm { e.uint(15)?; e.int(i64::from(*v))?; }
        if let Some(v) = &self.ack_signal_avg_dbm { e.uint(16)?; e.int(i64::from(*v))?; }
        if let Some(v) = &self.rx_bitrate_kbit_s { e.uint(17)?; e.uint(*v)?; }
        if let Some(v) = &self.tx_bitrate_kbit_s { e.uint(18)?; e.uint(*v)?; }
        if let Some(v) = &self.expected_throughput_kbit_s { e.uint(19)?; e.uint(*v)?; }
        if let Some(v) = &self.bearer_rx_frames { e.uint(20)?; e.uint(*v)?; }
        if let Some(v) = &self.bearer_rx_drops { e.uint(21)?; e.uint(*v)?; }
        if let Some(v) = &self.bearer_rx_invalid { e.uint(22)?; e.uint(*v)?; }
        if let Some(v) = &self.bearer_udp_delivered { e.uint(23)?; e.uint(*v)?; }
        if let Some(v) = &self.bearer_ndp_advertisements { e.uint(24)?; e.uint(*v)?; }
        if let Some(v) = &self.bearer_tx_failures { e.uint(25)?; e.uint(*v)?; }
        if let Some(v) = &self.raw_tx_completion_failures { e.uint(26)?; e.uint(*v)?; }
        Some(())
    }

    fn read_field(&mut self, tag: u64, d: &mut Decoder<'_>) -> Result<bool, String> {
        match tag {
            1 => self.schema_version = Some(read_u8(d)?),
            2 => self.interface_index = Some(read_u32(d)?),
            3 => self.peer_mac = Some(d.bytes_ref().ok_or("invalid byte string")?.to_vec()),
            4 => self.rx_bytes = Some(read_u64(d)?),
            5 => self.tx_bytes = Some(read_u64(d)?),
            6 => self.rx_packets = Some(read_u64(d)?),
            7 => self.tx_packets = Some(read_u64(d)?),
            8 => self.mac_tx_retries = Some(read_u64(d)?),
            9 => self.mac_tx_failed = Some(read_u64(d)?),
            10 => self.rx_dropped = Some(read_u64(d)?),
            11 => self.rx_airtime_us = Some(read_u64(d)?),
            12 => self.tx_airtime_us = Some(read_u64(d)?),
            13 => self.signal_dbm = Some(read_i8(d)?),
            14 => self.signal_avg_dbm = Some(read_i8(d)?),
            15 => self.ack_signal_dbm = Some(read_i8(d)?),
            16 => self.ack_signal_avg_dbm = Some(read_i8(d)?),
            17 => self.rx_bitrate_kbit_s = Some(read_u64(d)?),
            18 => self.tx_bitrate_kbit_s = Some(read_u64(d)?),
            19 => self.expected_throughput_kbit_s = Some(read_u64(d)?),
            20 => self.bearer_rx_frames = Some(read_u64(d)?),
            21 => self.bearer_rx_drops = Some(read_u64(d)?),
            22 => self.bearer_rx_invalid = Some(read_u64(d)?),
            23 => self.bearer_udp_delivered = Some(read_u64(d)?),
            24 => self.bearer_ndp_advertisements = Some(read_u64(d)?),
            25 => self.bearer_tx_failures = Some(read_u64(d)?),
            26 => self.raw_tx_completion_failures = Some(read_u64(d)?),
            _ => return Ok(false),
        }
        Ok(true)
    }
}

impl TaggedCbor for WifiLink {
    fn encode_cbor(&self) -> Vec<u8> {
        encode_with_growth(|out| {
            let mut e = Encoder::new(out);
            e.map(self.field_count())?;
            self.write_fields(&mut e)?;
            Some(e.len())
        })
    }

    fn decode_cbor(input: &[u8]) -> Result<Self, String> {
        let mut d = Decoder::new(input);
        let (major, count) = d.head().ok_or("not a CBOR map")?;
        if major != 5 {
            return Err("not a CBOR map".to_owned());
        }
        let mut out = Self::default();
        for _ in 0..count {
            let tag = d.uint().ok_or("invalid field tag")?;
            if !out.read_field(tag, &mut d)? {
                d.skip().ok_or("invalid value")?;
            }
        }
        Ok(out)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct TelemetryWifiLinkResponse {
    #[serde(flatten)]
    pub summary: WifiLink,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub links: Option<Vec<WifiLink>>,
}

impl TaggedCbor for TelemetryWifiLinkResponse {
    fn encode_cbor(&self) -> Vec<u8> {
        encode_with_growth(|out| {
            let mut e = Encoder::new(out);
            e.map(self.summary.field_count() + u64::from(self.links.is_some()))?;
            self.summary.write_fields(&mut e)?;
            if let Some(links) = &self.links {
                e.uint(27)?;
                e.array(links.len() as u64)?;
                for item in links {
                    e.encoded_value(&item.encode_cbor())?;
                }
            }
            Some(e.len())
        })
    }

    fn decode_cbor(input: &[u8]) -> Result<Self, String> {
        let mut d = Decoder::new(input);
        let (major, count) = d.head().ok_or("not a CBOR map")?;
        if major != 5 {
            return Err("not a CBOR map".to_owned());
        }
        let mut out = Self::default();
        for _ in 0..count {
            let tag = d.uint().ok_or("invalid field tag")?;
            if tag == 27 {
                let (arr_major, len) = d.head().ok_or("invalid array")?;
                if arr_major != 4 {
                    return Err("not a CBOR array".to_owned());
                }
                let mut items = Vec::new();
                for _ in 0..len {
                    let start = d.position();
                    d.skip().ok_or("invalid row")?;
                    items.push(WifiLink::decode_cbor(&input[start..d.position()])?);
                }
                out.links = Some(items);
            } else if !out.summary.read_field(tag, &mut d)? {
                d.skip().ok_or("invalid value")?;
            }
        }
        Ok(out)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct TelemetryQuicResponse {
    pub live_associations: u64,
    pub received_packets: u64,
    pub sent_packets: u64,
    pub received_stream_packets: u64,
    pub received_control_packets: u64,
    pub sent_stream_packets: u64,
    pub sent_control_packets: u64,
    pub duplicate_packets: u64,
    pub out_of_order_packets: u64,
    pub inferred_missing_packets: u64,
    pub retransmitted_packets: u64,
    pub loss_events: u64,
    pub submission_failures: u64,
}

impl TaggedCbor for TelemetryQuicResponse {
    fn encode_cbor(&self) -> Vec<u8> {
        encode_with_growth(|out| {
            let mut e = Encoder::new(out);
            e.map(13)?;
            e.uint(1)?; e.uint(self.live_associations)?;
            e.uint(2)?; e.uint(self.received_packets)?;
            e.uint(3)?; e.uint(self.sent_packets)?;
            e.uint(4)?; e.uint(self.received_stream_packets)?;
            e.uint(5)?; e.uint(self.received_control_packets)?;
            e.uint(6)?; e.uint(self.sent_stream_packets)?;
            e.uint(7)?; e.uint(self.sent_control_packets)?;
            e.uint(8)?; e.uint(self.duplicate_packets)?;
            e.uint(9)?; e.uint(self.out_of_order_packets)?;
            e.uint(10)?; e.uint(self.inferred_missing_packets)?;
            e.uint(11)?; e.uint(self.retransmitted_packets)?;
            e.uint(12)?; e.uint(self.loss_events)?;
            e.uint(13)?; e.uint(self.submission_failures)?;
            Some(e.len())
        })
    }

    fn decode_cbor(input: &[u8]) -> Result<Self, String> {
        let mut d = Decoder::new(input);
        let (major, count) = d.head().ok_or("not a CBOR map")?;
        if major != 5 {
            return Err("not a CBOR map".to_owned());
        }
        let mut out = Self::default();
        let mut seen = [false; 13];
        for _ in 0..count {
            match d.uint().ok_or("invalid field tag")? {
                1 => { out.live_associations = read_u64(&mut d)?; seen[0] = true; }
                2 => { out.received_packets = read_u64(&mut d)?; seen[1] = true; }
                3 => { out.sent_packets = read_u64(&mut d)?; seen[2] = true; }
                4 => { out.received_stream_packets = read_u64(&mut d)?; seen[3] = true; }
                5 => { out.received_control_packets = read_u64(&mut d)?; seen[4] = true; }
                6 => { out.sent_stream_packets = read_u64(&mut d)?; seen[5] = true; }
                7 => { out.sent_control_packets = read_u64(&mut d)?; seen[6] = true; }
                8 => { out.duplicate_packets = read_u64(&mut d)?; seen[7] = true; }
                9 => { out.out_of_order_packets = read_u64(&mut d)?; seen[8] = true; }
                10 => { out.inferred_missing_packets = read_u64(&mut d)?; seen[9] = true; }
                11 => { out.retransmitted_packets = read_u64(&mut d)?; seen[10] = true; }
                12 => { out.loss_events = read_u64(&mut d)?; seen[11] = true; }
                13 => { out.submission_failures = read_u64(&mut d)?; seen[12] = true; }
                _ => d.skip().ok_or("invalid value")?,
            }
        }
        if seen.iter().any(|s| !*s) {
            return Err("missing required TelemetryQuicResponse field".to_owned());
        }
        Ok(out)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct QuicAssociation {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub association: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bearer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub received_packets: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sent_packets: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retransmitted_packets: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub loss_events: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub submission_failures: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes_in_flight: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_max_data: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_sent_data: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub largest_acked_by_peer: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub streams_local_active: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub streams_peer_active: Option<u64>,
}

impl TaggedCbor for QuicAssociation {
    fn encode_cbor(&self) -> Vec<u8> {
        encode_with_growth(|out| {
            let mut e = Encoder::new(out);
            let n = u64::from(self.association.is_some())
                + u64::from(self.bearer.is_some())
                + u64::from(self.peer.is_some())
                + u64::from(self.received_packets.is_some())
                + u64::from(self.sent_packets.is_some())
                + u64::from(self.retransmitted_packets.is_some())
                + u64::from(self.loss_events.is_some())
                + u64::from(self.submission_failures.is_some())
                + u64::from(self.bytes_in_flight.is_some())
                + u64::from(self.peer_max_data.is_some())
                + u64::from(self.peer_sent_data.is_some())
                + u64::from(self.largest_acked_by_peer.is_some())
                + u64::from(self.streams_local_active.is_some())
                + u64::from(self.streams_peer_active.is_some());
            e.map(n)?;
            if let Some(v) = &self.association { e.uint(1)?; e.uint(*v)?; }
            if let Some(v) = &self.bearer { e.uint(2)?; e.text_value(v.as_bytes())?; }
            if let Some(v) = &self.peer { e.uint(3)?; e.text_value(v.as_bytes())?; }
            if let Some(v) = &self.received_packets { e.uint(4)?; e.uint(*v)?; }
            if let Some(v) = &self.sent_packets { e.uint(5)?; e.uint(*v)?; }
            if let Some(v) = &self.retransmitted_packets { e.uint(6)?; e.uint(*v)?; }
            if let Some(v) = &self.loss_events { e.uint(7)?; e.uint(*v)?; }
            if let Some(v) = &self.submission_failures { e.uint(8)?; e.uint(*v)?; }
            if let Some(v) = &self.bytes_in_flight { e.uint(9)?; e.uint(*v)?; }
            if let Some(v) = &self.peer_max_data { e.uint(10)?; e.uint(*v)?; }
            if let Some(v) = &self.peer_sent_data { e.uint(11)?; e.uint(*v)?; }
            if let Some(v) = &self.largest_acked_by_peer { e.uint(12)?; e.uint(u64::from(*v))?; }
            if let Some(v) = &self.streams_local_active { e.uint(13)?; e.uint(*v)?; }
            if let Some(v) = &self.streams_peer_active { e.uint(14)?; e.uint(*v)?; }
            Some(e.len())
        })
    }

    fn decode_cbor(input: &[u8]) -> Result<Self, String> {
        let mut d = Decoder::new(input);
        let (major, count) = d.head().ok_or("not a CBOR map")?;
        if major != 5 {
            return Err("not a CBOR map".to_owned());
        }
        let mut out = Self::default();
        for _ in 0..count {
            match d.uint().ok_or("invalid field tag")? {
                1 => out.association = Some(read_u64(&mut d)?),
                2 => out.bearer = Some(read_text(&mut d)?),
                3 => out.peer = Some(read_text(&mut d)?),
                4 => out.received_packets = Some(read_u64(&mut d)?),
                5 => out.sent_packets = Some(read_u64(&mut d)?),
                6 => out.retransmitted_packets = Some(read_u64(&mut d)?),
                7 => out.loss_events = Some(read_u64(&mut d)?),
                8 => out.submission_failures = Some(read_u64(&mut d)?),
                9 => out.bytes_in_flight = Some(read_u64(&mut d)?),
                10 => out.peer_max_data = Some(read_u64(&mut d)?),
                11 => out.peer_sent_data = Some(read_u64(&mut d)?),
                12 => out.largest_acked_by_peer = Some(read_u32(&mut d)?),
                13 => out.streams_local_active = Some(read_u64(&mut d)?),
                14 => out.streams_peer_active = Some(read_u64(&mut d)?),
                _ => d.skip().ok_or("invalid value")?,
            }
        }
        Ok(out)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct TelemetryQuicAssociationsResponse {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub associations: Option<Vec<QuicAssociation>>,
}

impl TaggedCbor for TelemetryQuicAssociationsResponse {
    fn encode_cbor(&self) -> Vec<u8> {
        encode_with_growth(|out| {
            let mut e = Encoder::new(out);
            e.map(u64::from(self.associations.is_some()))?;
            if let Some(items) = &self.associations {
                e.uint(1)?;
                e.array(items.len() as u64)?;
                for item in items {
                    e.encoded_value(&item.encode_cbor())?;
                }
            }
            Some(e.len())
        })
    }

    fn decode_cbor(input: &[u8]) -> Result<Self, String> {
        let mut d = Decoder::new(input);
        let (major, count) = d.head().ok_or("not a CBOR map")?;
        if major != 5 {
            return Err("not a CBOR map".to_owned());
        }
        let mut out = Self::default();
        for _ in 0..count {
            match d.uint().ok_or("invalid field tag")? {
                1 => {
                    let (arr_major, len) = d.head().ok_or("invalid array")?;
                    if arr_major != 4 {
                        return Err("not a CBOR array".to_owned());
                    }
                    let mut items = Vec::new();
                    for _ in 0..len {
                        let start = d.position();
                        d.skip().ok_or("invalid row")?;
                        items.push(QuicAssociation::decode_cbor(&input[start..d.position()])?);
                    }
                    out.associations = Some(items);
                }
                _ => d.skip().ok_or("invalid value")?,
            }
        }
        Ok(out)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct BearerCounters {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tx_submitted: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tx_accepted: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tx_failed: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tx_busy: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rx_packets: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rx_rejected: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rx_dropped: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queue_depth: Option<u32>,
}

impl TaggedCbor for BearerCounters {
    fn encode_cbor(&self) -> Vec<u8> {
        encode_with_growth(|out| {
            let mut e = Encoder::new(out);
            let n = u64::from(self.name.is_some())
                + u64::from(self.state.is_some())
                + u64::from(self.tx_submitted.is_some())
                + u64::from(self.tx_accepted.is_some())
                + u64::from(self.tx_failed.is_some())
                + u64::from(self.tx_busy.is_some())
                + u64::from(self.rx_packets.is_some())
                + u64::from(self.rx_rejected.is_some())
                + u64::from(self.rx_dropped.is_some())
                + u64::from(self.queue_depth.is_some());
            e.map(n)?;
            if let Some(v) = &self.name { e.uint(1)?; e.text_value(v.as_bytes())?; }
            if let Some(v) = &self.state { e.uint(2)?; e.uint(u64::from(*v))?; }
            if let Some(v) = &self.tx_submitted { e.uint(3)?; e.uint(*v)?; }
            if let Some(v) = &self.tx_accepted { e.uint(4)?; e.uint(*v)?; }
            if let Some(v) = &self.tx_failed { e.uint(5)?; e.uint(*v)?; }
            if let Some(v) = &self.tx_busy { e.uint(6)?; e.uint(*v)?; }
            if let Some(v) = &self.rx_packets { e.uint(7)?; e.uint(*v)?; }
            if let Some(v) = &self.rx_rejected { e.uint(8)?; e.uint(*v)?; }
            if let Some(v) = &self.rx_dropped { e.uint(9)?; e.uint(*v)?; }
            if let Some(v) = &self.queue_depth { e.uint(10)?; e.uint(u64::from(*v))?; }
            Some(e.len())
        })
    }

    fn decode_cbor(input: &[u8]) -> Result<Self, String> {
        let mut d = Decoder::new(input);
        let (major, count) = d.head().ok_or("not a CBOR map")?;
        if major != 5 {
            return Err("not a CBOR map".to_owned());
        }
        let mut out = Self::default();
        for _ in 0..count {
            match d.uint().ok_or("invalid field tag")? {
                1 => out.name = Some(read_text(&mut d)?),
                2 => out.state = Some(read_u8(&mut d)?),
                3 => out.tx_submitted = Some(read_u64(&mut d)?),
                4 => out.tx_accepted = Some(read_u64(&mut d)?),
                5 => out.tx_failed = Some(read_u64(&mut d)?),
                6 => out.tx_busy = Some(read_u64(&mut d)?),
                7 => out.rx_packets = Some(read_u64(&mut d)?),
                8 => out.rx_rejected = Some(read_u64(&mut d)?),
                9 => out.rx_dropped = Some(read_u64(&mut d)?),
                10 => out.queue_depth = Some(read_u32(&mut d)?),
                _ => d.skip().ok_or("invalid value")?,
            }
        }
        Ok(out)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct TelemetryBearersResponse {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bearers: Option<Vec<BearerCounters>>,
}

impl TaggedCbor for TelemetryBearersResponse {
    fn encode_cbor(&self) -> Vec<u8> {
        encode_with_growth(|out| {
            let mut e = Encoder::new(out);
            e.map(u64::from(self.bearers.is_some()))?;
            if let Some(items) = &self.bearers {
                e.uint(1)?;
                e.array(items.len() as u64)?;
                for item in items {
                    e.encoded_value(&item.encode_cbor())?;
                }
            }
            Some(e.len())
        })
    }

    fn decode_cbor(input: &[u8]) -> Result<Self, String> {
        let mut d = Decoder::new(input);
        let (major, count) = d.head().ok_or("not a CBOR map")?;
        if major != 5 {
            return Err("not a CBOR map".to_owned());
        }
        let mut out = Self::default();
        for _ in 0..count {
            match d.uint().ok_or("invalid field tag")? {
                1 => {
                    let (arr_major, len) = d.head().ok_or("invalid array")?;
                    if arr_major != 4 {
                        return Err("not a CBOR array".to_owned());
                    }
                    let mut items = Vec::new();
                    for _ in 0..len {
                        let start = d.position();
                        d.skip().ok_or("invalid row")?;
                        items.push(BearerCounters::decode_cbor(&input[start..d.position()])?);
                    }
                    out.bearers = Some(items);
                }
                _ => d.skip().ok_or("invalid value")?,
            }
        }
        Ok(out)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct TelemetryMemoryResponse {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub packet_slots: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub packet_slots_available: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub packet_drops: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_stack_bytes: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_running: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_starts: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_create_failures: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_stack_min_free_words: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub free_internal_bytes: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_free_internal_bytes: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub largest_internal_block_bytes: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_rss_bytes: Option<u64>,
}

impl TaggedCbor for TelemetryMemoryResponse {
    fn encode_cbor(&self) -> Vec<u8> {
        encode_with_growth(|out| {
            let mut e = Encoder::new(out);
            let n = u64::from(self.packet_slots.is_some())
                + u64::from(self.packet_slots_available.is_some())
                + u64::from(self.packet_drops.is_some())
                + u64::from(self.worker_stack_bytes.is_some())
                + u64::from(self.worker_running.is_some())
                + u64::from(self.worker_starts.is_some())
                + u64::from(self.worker_create_failures.is_some())
                + u64::from(self.worker_stack_min_free_words.is_some())
                + u64::from(self.free_internal_bytes.is_some())
                + u64::from(self.min_free_internal_bytes.is_some())
                + u64::from(self.largest_internal_block_bytes.is_some())
                + u64::from(self.process_rss_bytes.is_some());
            e.map(n)?;
            if let Some(v) = &self.packet_slots { e.uint(1)?; e.uint(u64::from(*v))?; }
            if let Some(v) = &self.packet_slots_available { e.uint(2)?; e.uint(u64::from(*v))?; }
            if let Some(v) = &self.packet_drops { e.uint(3)?; e.uint(u64::from(*v))?; }
            if let Some(v) = &self.worker_stack_bytes { e.uint(4)?; e.uint(u64::from(*v))?; }
            if let Some(v) = &self.worker_running { e.uint(5)?; e.boolean(*v)?; }
            if let Some(v) = &self.worker_starts { e.uint(6)?; e.uint(u64::from(*v))?; }
            if let Some(v) = &self.worker_create_failures { e.uint(7)?; e.uint(u64::from(*v))?; }
            if let Some(v) = &self.worker_stack_min_free_words { e.uint(8)?; e.uint(u64::from(*v))?; }
            if let Some(v) = &self.free_internal_bytes { e.uint(9)?; e.uint(u64::from(*v))?; }
            if let Some(v) = &self.min_free_internal_bytes { e.uint(10)?; e.uint(u64::from(*v))?; }
            if let Some(v) = &self.largest_internal_block_bytes { e.uint(11)?; e.uint(u64::from(*v))?; }
            if let Some(v) = &self.process_rss_bytes { e.uint(12)?; e.uint(*v)?; }
            Some(e.len())
        })
    }

    fn decode_cbor(input: &[u8]) -> Result<Self, String> {
        let mut d = Decoder::new(input);
        let (major, count) = d.head().ok_or("not a CBOR map")?;
        if major != 5 {
            return Err("not a CBOR map".to_owned());
        }
        let mut out = Self::default();
        for _ in 0..count {
            match d.uint().ok_or("invalid field tag")? {
                1 => out.packet_slots = Some(read_u32(&mut d)?),
                2 => out.packet_slots_available = Some(read_u32(&mut d)?),
                3 => out.packet_drops = Some(read_u32(&mut d)?),
                4 => out.worker_stack_bytes = Some(read_u32(&mut d)?),
                5 => out.worker_running = Some(read_bool(&mut d)?),
                6 => out.worker_starts = Some(read_u32(&mut d)?),
                7 => out.worker_create_failures = Some(read_u32(&mut d)?),
                8 => out.worker_stack_min_free_words = Some(read_u32(&mut d)?),
                9 => out.free_internal_bytes = Some(read_u32(&mut d)?),
                10 => out.min_free_internal_bytes = Some(read_u32(&mut d)?),
                11 => out.largest_internal_block_bytes = Some(read_u32(&mut d)?),
                12 => out.process_rss_bytes = Some(read_u64(&mut d)?),
                _ => d.skip().ok_or("invalid value")?,
            }
        }
        Ok(out)
    }
}
