use anyhow::Context;
use axum::{
    Router,
    body::Body,
    extract::OriginalUri,
    extract::{Path as AxumPath, State},
    http::{Method, Request, StatusCode},
    response::{Html, IntoResponse, Json, Redirect, Response},
    routing::{any, get},
};
use bytes::Bytes;
use http_body_util::BodyExt;
use log::{debug, info};
use russh::server::Server;
use rust_embed::RustEmbed;
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::Arc;
use tokio::net::{TcpStream, UnixStream};
use tokio::sync::mpsc;
use tokio_stream::StreamExt;
use tracing::{error as tracing_error, instrument};

// Keep the administrative UI embedded with the server binary. Asset-only
// changes therefore require rebuilding this crate before a supervised lmesh
// restart can serve them.
#[derive(RustEmbed)]
#[folder = "web/"]
pub struct Assets;

use crate::AppState;

/// Serve a JSON file from the `web/` directory by path.
///
/// The path is confined to the `web/` directory: any `..` components or
/// absolute paths are rejected to prevent traversal.
async fn serve_json(AxumPath(path): AxumPath<String>) -> impl IntoResponse {
    let confined = confine_to_web_dir(std::path::Path::new("web"), &path);
    let file_path = match confined {
        Some(p) => p,
        None => return (StatusCode::BAD_REQUEST, "invalid path").into_response(),
    };
    match tokio::fs::read_to_string(&file_path).await {
        Ok(content) => (
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            content,
        )
            .into_response(),
        Err(_) => (StatusCode::NOT_FOUND, format!("{} not found", path)).into_response(),
    }
}

/// Resolve a request path to a filesystem path confined within the `web/`
/// directory. Returns `None` if the path escapes `web/` (via `..`, absolute
/// paths, or symlink resolution outside the root).
fn confine_to_web_dir(root: &std::path::Path, request_path: &str) -> Option<std::path::PathBuf> {
    let web_root_canonical = std::fs::canonicalize(root).ok()?;
    let joined = root.join(request_path.trim_start_matches('/'));
    // Canonicalize if the file exists; otherwise canonicalize the parent and
    // re-append the leaf so not-yet-existing files are still checked.
    let canonical = match std::fs::canonicalize(&joined) {
        Ok(c) => c,
        Err(_) => {
            let parent = joined.parent()?;
            let leaf = joined.file_name()?;
            let parent_canonical = std::fs::canonicalize(parent).ok()?;
            parent_canonical.join(leaf)
        }
    };
    if canonical.starts_with(&web_root_canonical) {
        Some(canonical)
    } else {
        None
    }
}

/// appCore is the core handler for H2C - for example in CloudRun
/// or K8S with a Gateway/ztunnel.
///
/// All access to admin interface will be available by creating
/// SSH port forwards.
pub fn app_core(app_state: AppState) -> Router {
    let router = Router::new()
        .route("/_m/_ssh", any(handle_ssh_request))
        .fallback(handle_proxy_request);

    router.with_state(app_state)
}

/// "Mesh" like function, like Istio but using POST.
/// Should be exposed over mTLS (H2 proper).
///
/// SSH can be exposed as a proxy to port 15022.
///
/// WIP: needs authz.
pub fn app_mesh(app_state: AppState) -> Router {
    let router = Router::new()
        .route("/_m/_ssh", any(handle_ssh_request))
        .route("/_m/_tcp/:host/:port", any(handle_tcp_proxy))
        // This could be restricted to a prefix.
        .route("/_m/_uds", any(handle_uds_proxy))
        .route("/_m/_uds/*path", any(handle_uds_proxy))
        // This could be replaced with a configured host:port
        .route("/_m/_exec/*cmd", any(handle_exec))
        .fallback(handle_proxy_request);

    router.with_state(app_state)
}

/// Admin app. Exposed over SSH for admin/authorized_keys.
/// For devel can be exposed locally. Should be on different port
/// from the H2C - and not exposed on H2 directly.
/// Has all other features - for testing.
pub fn app(app_state: AppState) -> Router {
    let router = Router::new()
        .route("/", get(redirect_admin))
        .nest("/_m", mesh_routes(&app_state))
        .nest("/:prefix1/_m", mesh_routes(&app_state))
        .nest("/:prefix1/:prefix2/_m", mesh_routes(&app_state))
        .fallback(handle_proxy_request);

    router.with_state(app_state)
}

async fn redirect_admin() -> Redirect {
    Redirect::temporary("/_m/adm/")
}

fn mesh_routes(app_state: &AppState) -> Router<AppState> {
    Router::new()
        .route("/", get(redirect_admin_from_uri))
        .route("/adm", get(redirect_trailing_slash))
        .route("/adm/", get(serve_index))
        .route("/adm/*path", get(handle_web_request))
        .route("/_ssh", any(handle_ssh_request))
        .route("/_tcp/:host/:port", any(handle_tcp_proxy))
        .route("/_uds", any(handle_uds_proxy))
        .route("/_uds/*path", any(handle_uds_proxy))
        .route("/_exec/*cmd", any(handle_exec))
        .route("/_ssh/*rest", any(handle_ssh_request))
        .nest("/mcp", crate::mcp_proxy::routes())
        .nest("/mesh", crate::mesh_rest::routes())
        .nest("/proxy", crate::generic_proxy::routes())
        .nest("/trace", crate::trace_proxy::routes())
        .route("/api/ssh/clients", get(get_ssh_clients))
        .nest_service(
            "/api/sshc",
            crate::sshc::sshc_routes(app_state.ssh_client_manager.clone()),
        )
        .route("/api/*path", get(serve_json))
}

async fn redirect_admin_from_uri(OriginalUri(uri): OriginalUri) -> Redirect {
    let path = uri.path().trim_end_matches('/');
    Redirect::temporary(&format!("{path}/adm/"))
}

async fn redirect_trailing_slash(OriginalUri(uri): OriginalUri) -> Redirect {
    let mut path = uri.path().to_string();
    if !path.ends_with('/') {
        path.push('/');
    }
    Redirect::temporary(&path)
}

/// Guess the MIME type for a file path.
fn mime_for_path(path: &str) -> String {
    mime_guess::from_path(path)
        .first_or_octet_stream()
        .to_string()
}

/// Serve embedded or local web assets by path.
pub async fn handle_web_request(
    State(app_state): State<AppState>,
    AxumPath(path): AxumPath<String>,
) -> impl axum::response::IntoResponse {
    let path = path.trim_start_matches('/');
    handle_web_asset(app_state.web_root.as_deref(), path)
}

fn handle_web_asset(dev_root: Option<&std::path::Path>, path: &str) -> Response {
    if let Some(response) = serve_local_web_asset(dev_root, path) {
        return response;
    }

    match Assets::get(path) {
        Some(content) => {
            let mime = mime_for_path(path);
            (
                StatusCode::OK,
                [(axum::http::header::CONTENT_TYPE, mime)],
                content.data.clone(),
            )
                .into_response()
        }
        None => (StatusCode::NOT_FOUND, "Not Found").into_response(),
    }
}

/// Serve the web asset index page.
async fn serve_index(State(app_state): State<AppState>) -> impl IntoResponse {
    serve_index_asset(app_state.web_root.as_deref())
}

fn serve_index_asset(dev_root: Option<&std::path::Path>) -> Response {
    if let Some(response) = serve_local_web_asset(dev_root, "index.html") {
        return response;
    }
    match Assets::get("index.html").or_else(|| Assets::get("ssh.html")) {
        Some(content) => Html(String::from_utf8_lossy(&content.data).into_owned()).into_response(),
        None => Html("<h1>Error: index.html not found</h1>".to_string()).into_response(),
    }
}

/// Look up an asset in an explicitly configured development tree first, then
/// preserve the historical cwd-relative `web/` override for ssh-mesh itself.
/// Every lookup is canonicalized and confined to its selected root.
fn serve_local_web_asset(dev_root: Option<&std::path::Path>, path: &str) -> Option<Response> {
    let roots = dev_root
        .into_iter()
        .chain(std::iter::once(std::path::Path::new("web")));
    for root in roots {
        let Some(local_path) = confine_to_web_dir(root, path) else {
            continue;
        };
        if !local_path.is_file() {
            continue;
        }
        let content = std::fs::read(&local_path).ok()?;
        let mime = mime_for_path(&local_path.to_string_lossy());
        return Some(
            (
                StatusCode::OK,
                [(axum::http::header::CONTENT_TYPE, mime)],
                content,
            )
                .into_response(),
        );
    }
    None
}

fn response_with_status(status: StatusCode, body: Body) -> Response {
    let mut response = Response::new(body);
    *response.status_mut() = status;
    response
}

async fn get_ssh_clients(State(app_state): State<AppState>) -> impl IntoResponse {
    let clients = app_state.ssh_server.connected_clients.lock().await;
    (StatusCode::OK, Json(clients.clone()))
}

/// SSH-over-HTTP/2 handler.
///
/// Bridges a bidirectional HTTP/2 body stream to a `russh` server session,
/// allowing SSH protocol to tunnel over H2C.
#[instrument(skip(req, state), fields(method = %req.method(), uri = %req.uri()))]
pub async fn handle_ssh_request(
    State(state): State<AppState>,
    req: Request<Body>,
) -> impl IntoResponse {
    info!("Received SSH request: {} {}", req.method(), req.uri());

    // Use shared SSH server
    // We clone the server to get a mutable instance (interior mutability handles state)
    // SshServer is designed to be cloned
    let mut ssh_server = state.ssh_server.as_ref().clone();
    let config = Arc::new(ssh_server.get_config());
    let handler = ssh_server.new_client(None);

    // Create a bidirectional stream adapter for HTTP/2 body
    let (reader_tx, reader_rx) = mpsc::channel::<Result<Bytes, std::io::Error>>(100);
    let (writer_tx, writer_rx) = mpsc::channel::<Bytes>(100);

    // Spawn task to read from HTTP request body and feed to SSH
    tokio::spawn(pipe_body_to_tx(req.into_body(), reader_tx));

    // Create the bidirectional stream adapter
    let stream = crate::utils::ChannelStream::new(reader_rx, writer_tx);

    let handler_id = handler.id;
    let connected_clients = ssh_server.connected_clients.clone();

    // Spawn task to run the SSH session asynchronously so response headers can be sent immediately
    tokio::spawn(async move {
        match russh::server::run_stream(config, stream, handler).await {
            Ok(session) => {
                info!("SSH session started successfully");
                if let Err(e) = session.await {
                    tracing_error!("SSH session error: {:?}", e);
                }
                info!("SSH session completed");
            }
            Err(e) => {
                tracing_error!("Failed to start SSH session: {:?}", e);
            }
        }
        let mut clients = connected_clients.lock().await;
        if clients.remove(&handler_id).is_some() {
            debug!("Removed client {} from connected_clients", handler_id);
        }
    });

    // Create response body from writer_rx and return HTTP 200 OK immediately
    let response_stream =
        tokio_stream::wrappers::ReceiverStream::new(writer_rx).map(Ok::<_, std::io::Error>);

    response_with_status(StatusCode::OK, Body::from_stream(response_stream))
}

/// Pipe frames from an HTTP body into an MPSC sender.
async fn pipe_body_to_tx(body: Body, tx: mpsc::Sender<Result<Bytes, std::io::Error>>) {
    let mut body = body;
    while let Some(frame_res) = body.frame().await {
        match frame_res {
            Ok(frame) => {
                if let Ok(data) = frame.into_data() {
                    if !data.is_empty() && tx.send(Ok(data)).await.is_err() {
                        return;
                    }
                }
            }
            Err(e) => {
                let _ = tx
                    .send(Err(std::io::Error::other(format!(
                        "Body read error: {}",
                        e
                    ))))
                    .await;
                return;
            }
        }
    }
}

/// TCP proxy handler.
///
/// Connects to `host:port` via TCP and bridges the connection over the HTTP/2 body stream.
///
/// * `host` — Target hostname or IP.
/// * `port` — Target port number.
#[instrument(skip(req, _state), fields(method = %req.method(), uri = %req.uri(), host = %host, port = %port))]
pub async fn handle_tcp_proxy(
    State(_state): State<AppState>,
    AxumPath((host, port)): AxumPath<(String, u32)>,
    req: Request<Body>,
) -> impl IntoResponse {
    let method = req.method().clone();
    if method != Method::POST {
        return (StatusCode::METHOD_NOT_ALLOWED, "Use POST").into_response();
    }

    info!(
        "Received TCP proxy request: {} to {}:{}",
        method, host, port
    );

    let target_addr = format!("{}:{}", host, port);
    let tcp_stream = match TcpStream::connect(&target_addr).await {
        Ok(s) => s,
        Err(e) => {
            let err_msg = format!("Failed to connect to {}: {}", target_addr, e);
            tracing_error!("{}", err_msg);
            return (StatusCode::BAD_GATEWAY, err_msg).into_response();
        }
    };

    // Create a bidirectional stream adapter for HTTP/2 body
    let (reader_tx, reader_rx) = mpsc::channel::<Result<Bytes, std::io::Error>>(100);
    let (writer_tx, writer_rx) = mpsc::channel::<Bytes>(100);

    // Spawn task to read from HTTP request body and feed to adapter
    tokio::spawn(pipe_body_to_tx(req.into_body(), reader_tx));

    let stream = crate::utils::ChannelStream::new(reader_rx, writer_tx);

    // Forward data between the HTTP/2 stream and the TCP connection
    tokio::spawn(async move {
        crate::utils::bridge(
            tcp_stream,
            stream,
            &format!("TCP session to {}:{}", host, port),
        )
        .await;
    });

    // Create response body from writer_rx
    let response_stream =
        tokio_stream::wrappers::ReceiverStream::new(writer_rx).map(Ok::<_, std::io::Error>);

    response_with_status(StatusCode::OK, Body::from_stream(response_stream)).into_response()
}

/// Unix domain socket proxy handler.
///
/// Connects to a UDS at the given path and bridges it over the HTTP/2 body stream.
///
/// * `path` — Absolute path to the Unix domain socket.
#[instrument(skip(req, _state), fields(method = %req.method(), uri = %req.uri(), path = %path))]
pub async fn handle_uds_proxy(
    State(_state): State<AppState>,
    AxumPath(path): AxumPath<String>,
    req: Request<Body>,
) -> impl IntoResponse {
    let method = req.method().clone();
    if method != Method::POST {
        return (StatusCode::METHOD_NOT_ALLOWED, "Use POST").into_response();
    }

    info!("Received UDS proxy request: {} to {}", method, path);

    let full_path = if path.starts_with('/') {
        path.clone()
    } else {
        format!("/{}", path)
    };

    let unix_stream = match UnixStream::connect(&full_path).await {
        Ok(s) => s,
        Err(e) => {
            let err_msg = format!("Failed to connect to UDS {}: {}", full_path, e);
            tracing_error!("{}", err_msg);
            return (StatusCode::BAD_GATEWAY, err_msg).into_response();
        }
    };

    // Create a bidirectional stream adapter for HTTP/2 body
    let (reader_tx, reader_rx) = mpsc::channel::<Result<Bytes, std::io::Error>>(100);
    let (writer_tx, writer_rx) = mpsc::channel::<Bytes>(100);

    // Spawn task to read from HTTP request body and feed to adapter
    tokio::spawn(pipe_body_to_tx(req.into_body(), reader_tx));

    let stream = crate::utils::ChannelStream::new(reader_rx, writer_tx);

    // Forward data between the HTTP/2 stream and the UDS connection
    tokio::spawn(async move {
        crate::utils::bridge(
            unix_stream,
            stream,
            &format!("UDS session to {}", full_path),
        )
        .await;
    });

    // Create response body from writer_rx
    let response_stream =
        tokio_stream::wrappers::ReceiverStream::new(writer_rx).map(Ok::<_, std::io::Error>);

    response_with_status(StatusCode::OK, Body::from_stream(response_stream)).into_response()
}

async fn open_mesh_init_exec_stream(
    cmd: String,
    env: std::collections::HashMap<String, String>,
) -> Result<UnixStream, anyhow::Error> {
    let (child_end, parent_end) = std::os::unix::net::UnixStream::pair()?;
    tokio::task::spawn_blocking(move || {
        send_mesh_init_exec_fd_blocking(cmd, env, child_end.into())
    })
    .await
    .map_err(|e| anyhow::anyhow!("mesh-init exec task failed: {}", e))??;

    parent_end.set_nonblocking(true)?;
    Ok(UnixStream::from_std(parent_end)?)
}

fn send_mesh_init_exec_fd_blocking(
    cmd: String,
    env: std::collections::HashMap<String, String>,
    fd: OwnedFd,
) -> Result<(), anyhow::Error> {
    let socket_path = mesh_init_socket_path();
    // TEMPORARY compatibility path. The final HTTP exec target is resolved
    // from the authenticated request, exactly like SSH exec: an ordinary
    // command uses that user's UID/GID/home; a registered service uses its
    // mesh-init configuration and is admitted only after service-specific
    // authorization. Do not use ssh-mesh's own HOME for a different target
    // UID: mesh-init intentionally verifies that the requested home belongs
    // to the target identity.
    //
    // Until HTTP authentication and target resolution are wired here, this
    // legacy admin endpoint asks for system rather than root. It is not the
    // intended long-term authorization model.
    let system_uid = mesh::auth::system_uid().unwrap_or(1000);
    let system_gid = system_uid; // system user's primary GID matches UID
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    let fds = [fd.as_raw_fd()];
    // Duplicated constants are acceptable: the mesh-init control API is
    // stable, and these numeric identities (component/method/field tags from
    // crates/mesh-init/API.md, mirrored by mesh-init's generated catalog) are
    // exactly what this seqpacket start_terminal request and mesh-init
    // expect. No runtime schema load at this boundary; mesh::tagged::
    // load_service_catalog stays the gateway/CLI translation path for
    // generic, on-demand method translation.
    let request_env = env
        .clone()
        .into_iter()
        .map(|(k, v)| (k, serde_json::Value::String(v)))
        .collect::<serde_json::Map<String, serde_json::Value>>();
    let record = mesh::tagged::TaggedRecord {
        component: mesh::tagged::NameOrTag::Tag(mesh_api::mesh_init_ids::COMPONENT_MESH_INIT),
        method: mesh::tagged::NameOrTag::Tag(
            mesh_api::mesh_init_ids::METHOD_MESH_INIT_START_TERMINAL,
        ),
        id: Some(serde_json::json!(1)),
        env: [
            (
                mesh_api::mesh_init_ids::FIELD_MESH_INIT_START_TERMINAL_NAME,
                serde_json::Value::String("system".to_string()),
            ),
            (
                mesh_api::mesh_init_ids::FIELD_MESH_INIT_START_TERMINAL_HOME,
                serde_json::json!(home),
            ),
            (
                mesh_api::mesh_init_ids::FIELD_MESH_INIT_START_TERMINAL_UID,
                serde_json::json!(system_uid),
            ),
            (
                mesh_api::mesh_init_ids::FIELD_MESH_INIT_START_TERMINAL_GID,
                serde_json::json!(system_gid),
            ),
            (
                mesh_api::mesh_init_ids::FIELD_MESH_INIT_START_TERMINAL_PTY,
                serde_json::json!(false),
            ),
            (
                mesh_api::mesh_init_ids::FIELD_MESH_INIT_START_TERMINAL_ENV,
                serde_json::Value::Object(request_env),
            ),
            (
                mesh_api::mesh_init_ids::FIELD_MESH_INIT_START_TERMINAL_COMMAND,
                serde_json::json!(Some(cmd.clone())),
            ),
            (
                mesh_api::mesh_init_ids::FIELD_MESH_INIT_START_TERMINAL_FD_COUNT,
                serde_json::json!(1),
            ),
        ]
        .into_iter()
        .map(|(tag, value)| (mesh::tagged::NameOrTag::Tag(tag), value))
        .collect(),
        ..Default::default()
    };
    let response = tokio::runtime::Handle::current().block_on(async {
        let stream =
            mesh::seqpacket::UnixSeqpacket::connect(mesh_init_seqpacket_socket_path(&socket_path))
                .await?;
        stream.send_cbor_record(&record, &fds).await?;
        let (response, returned_fds) = stream
            .recv_cbor_record()
            .await?
            .context("mesh-init closed seqpacket control socket")?;
        anyhow::ensure!(
            returned_fds.is_empty(),
            "mesh-init returned unexpected file descriptors"
        );
        response
            .result
            .context("mesh-init seqpacket response omitted result")
    })?;
    let response: mesh::protocol::Response = serde_json::from_value(response)?;
    if response.success {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "mesh-init exec failed: {}",
            response.error.as_deref().unwrap_or("unknown error")
        ))
    }
}

fn mesh_init_socket_path() -> String {
    if let Ok(path) = std::env::var("MESH_INIT_SOCK") {
        return path;
    }
    let root_path = std::path::Path::new("/run/mesh/mesh-init/mesh.sock");
    if root_path.exists() {
        return root_path.to_string_lossy().into_owned();
    }
    mesh::paths::AppPaths::for_app("mesh-init")
        .mesh_socket()
        .to_string_lossy()
        .into_owned()
}

fn mesh_init_seqpacket_socket_path(stream_path: &str) -> String {
    std::env::var("MESH_INIT_SEQPACKET_SOCK").unwrap_or_else(|_| format!("{stream_path}.cbor"))
}

/// Execute an authenticated command and stream stdin/stdout over the HTTP/2 body.
///
/// Environment variables can be passed via `X-E-<NAME>` request headers.
/// The completed HTTP exec protocol also carries requested PTY metadata in
/// headers. It shares SSH exec's identity and service-authorization policy:
/// ordinary commands use the authenticated user's home; registered services
/// use their mesh-init service home. This handler's current system-account
/// request is a temporary compatibility implementation and must be replaced
/// by authenticated target resolution before exposing it beyond an admin path.
///
/// * `cmd` — Shell command to execute via `sh -c`.
#[instrument(skip(req, _state), fields(method = %req.method(), uri = %req.uri(), cmd = %cmd))]
pub async fn handle_exec(
    State(_state): State<AppState>,
    AxumPath(cmd): AxumPath<String>,
    req: Request<Body>,
) -> impl IntoResponse {
    let method = req.method().clone();
    if method != Method::POST {
        return (StatusCode::METHOD_NOT_ALLOWED, "Use POST").into_response();
    }

    info!("Received Exec request: {} for command: {}", method, cmd);

    // Prepare environment variables from X-E- headers
    let mut env_vars = std::collections::HashMap::new();
    for (name, value) in req.headers() {
        let name_str = name.as_str().to_lowercase();
        if let Some(stripped) = name_str.strip_prefix("x-e-") {
            let env_name = stripped.to_uppercase().replace('-', "_");
            if let Ok(val_str) = value.to_str() {
                debug!("Setting env var: {}={}", env_name, val_str);
                env_vars.insert(env_name, val_str.to_string());
            }
        }
    }

    let mesh_init_stream = match open_mesh_init_exec_stream(cmd.clone(), env_vars).await {
        Ok(stream) => stream,
        Err(e) => {
            tracing_error!("Failed to start mesh-init exec {}: {}", cmd, e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to start mesh-init exec: {}", e),
            )
                .into_response();
        }
    };

    // Create a bidirectional stream adapter for HTTP/2 body
    let (reader_tx, reader_rx) = mpsc::channel::<Result<Bytes, std::io::Error>>(100);
    let (writer_tx, writer_rx) = mpsc::channel::<Bytes>(100);

    // Spawn task to read from HTTP request body and feed to adapter
    tokio::spawn(pipe_body_to_tx(req.into_body(), reader_tx));

    let stream = crate::utils::ChannelStream::new(reader_rx, writer_tx);

    // Forward data between the HTTP/2 stream and the child process
    tokio::spawn(async move {
        crate::utils::bridge(
            mesh_init_stream,
            stream,
            &format!("Exec session for {}", cmd),
        )
        .await;
        info!("Exec session completed for: {}", cmd);
    });

    // Create response body from writer_rx
    let response_stream =
        tokio_stream::wrappers::ReceiverStream::new(writer_rx).map(Ok::<_, std::io::Error>);

    response_with_status(StatusCode::OK, Body::from_stream(response_stream)).into_response()
}

/// WebSocket handler for SSH-over-WS at `/_m/_ws/_ssh`.
pub struct SshWsHandler {
    pub ssh_server: Arc<crate::MeshNode>,
}

impl mesh::Routable for SshWsHandler {
    fn route(&self) -> &str {
        "/_m/_ws/_ssh"
    }
}

#[async_trait::async_trait]
impl mesh::StreamHandler for SshWsHandler {
    async fn handle(
        &self,
        _dest: &str,
        _headers: &std::collections::HashMap<String, String>,
        stream: tokio::io::DuplexStream,
    ) {
        let mut ssh_server = self.ssh_server.as_ref().clone();
        let config = Arc::new(ssh_server.get_config());
        let handler = ssh_server.new_client(None);
        let handler_id = handler.id;
        let connected_clients = self.ssh_server.connected_clients.clone();

        match russh::server::run_stream(config, stream, handler).await {
            Ok(session) => {
                info!("WS SSH session started successfully");
                if let Err(e) = session.await {
                    tracing_error!("WS SSH session error: {:?}", e);
                }
                info!("WS SSH session completed");

                let mut clients = connected_clients.lock().await;
                clients.remove(&handler_id);
            }
            Err(e) => {
                tracing_error!("Failed to start WS SSH session: {:?}", e);
            }
        }
    }
}

/// WebSocket handler for TCP proxy at `/_m/_ws/_tcp/*path`.
pub struct TcpProxyWsHandler;

impl mesh::Routable for TcpProxyWsHandler {
    fn route(&self) -> &str {
        "/_m/_ws/_tcp/*path"
    }
}

#[async_trait::async_trait]
impl mesh::StreamHandler for TcpProxyWsHandler {
    async fn handle(
        &self,
        dest: &str,
        _headers: &std::collections::HashMap<String, String>,
        stream: tokio::io::DuplexStream,
    ) {
        let parts: Vec<&str> = dest.splitn(5, '/').collect();
        let host_port = parts.get(4).unwrap_or(&"");
        let (host, port) = match host_port.split_once('/') {
            Some((h, p)) => (h, p),
            None => {
                tracing_error!("Invalid TCP proxy dest format: {}", dest);
                return;
            }
        };
        match TcpStream::connect(format!("{}:{}", host, port)).await {
            Ok(tcp_stream) => {
                crate::utils::bridge(tcp_stream, stream, &format!("WS TCP to {}:{}", host, port))
                    .await;
            }
            Err(e) => {
                tracing_error!("WS TCP connect error to {}:{}: {}", host, port, e);
            }
        }
    }
}

/// WebSocket handler for UDS proxy at `/_m/_ws/_uds/*path`.
pub struct UdsProxyWsHandler;

impl mesh::Routable for UdsProxyWsHandler {
    fn route(&self) -> &str {
        "/_m/_ws/_uds/*path"
    }
}

#[async_trait::async_trait]
impl mesh::StreamHandler for UdsProxyWsHandler {
    async fn handle(
        &self,
        dest: &str,
        _headers: &std::collections::HashMap<String, String>,
        stream: tokio::io::DuplexStream,
    ) {
        let parts: Vec<&str> = dest.splitn(5, '/').collect();
        let mut path_clone = String::from("/");
        path_clone.push_str(parts.get(4).unwrap_or(&""));

        match UnixStream::connect(&path_clone).await {
            Ok(unix_stream) => {
                crate::utils::bridge(unix_stream, stream, &format!("WS UDS to {}", path_clone))
                    .await;
            }
            Err(e) => {
                tracing_error!("WS UDS connect error to {}: {}", path_clone, e);
            }
        }
    }
}

/// WebSocket handler for command execution at `/_m/_ws/_exec/*cmd`.
pub struct ExecWsHandler;

impl mesh::Routable for ExecWsHandler {
    fn route(&self) -> &str {
        "/_m/_ws/_exec/*cmd"
    }
}

#[async_trait::async_trait]
impl mesh::StreamHandler for ExecWsHandler {
    async fn handle(
        &self,
        dest: &str,
        _headers: &std::collections::HashMap<String, String>,
        stream: tokio::io::DuplexStream,
    ) {
        let parts: Vec<&str> = dest.splitn(5, '/').collect();
        let cmd = parts.get(4).unwrap_or(&"").to_string();
        info!("WS Executing command: {}", cmd);
        let mesh_init_stream =
            match open_mesh_init_exec_stream(cmd.clone(), Default::default()).await {
                Ok(stream) => stream,
                Err(e) => {
                    tracing_error!("WS mesh-init exec error for {}: {}", cmd, e);
                    return;
                }
            };
        crate::utils::bridge(mesh_init_stream, stream, &format!("WS Exec for {}", cmd)).await;
        info!("WS Exec session completed for: {}", cmd);
    }
}

/// Fallback reverse proxy handler.
///
/// Forwards unmatched requests to `target_http_address` if configured.
pub async fn handle_proxy_request(
    State(state): State<AppState>,
    req: axum::extract::Request,
) -> impl IntoResponse {
    let host_header = req
        .headers()
        .get(axum::http::header::HOST)
        .and_then(|h| h.to_str().ok());
    let path = req.uri().path();

    if let Some(response) = handle_static_routes(&state, host_header, path) {
        return response;
    }

    if let Some(response) =
        prefixed_admin_response(path, state.web_root.as_deref()).await
    {
        return response;
    }

    let target_addr = match &state.target_http_address {
        Some(addr) => addr,
        None => {
            if let Some(location) = prefixed_admin_location(path) {
                return Redirect::temporary(&location).into_response();
            }
            return (StatusCode::NOT_FOUND, "Not Found").into_response();
        }
    };

    let path = req.uri().path();
    let query = req
        .uri()
        .query()
        .map(|q| format!("?{}", q))
        .unwrap_or_default();

    let uri_str = if target_addr.contains(':') {
        format!("http://{}{}{}", target_addr, path, query)
    } else {
        format!("http://127.0.0.1:{}{}{}", target_addr, path, query)
    };

    let (mut parts, body) = req.into_parts();
    parts.uri = match uri_str.parse() {
        Ok(uri) => uri,
        Err(error) => {
            return (
                StatusCode::BAD_GATEWAY,
                format!("invalid proxy target URI {uri_str}: {error}"),
            )
                .into_response();
        }
    };

    // Update Host header
    let host = match target_addr.parse() {
        Ok(host) => host,
        Err(error) => {
            return (
                StatusCode::BAD_GATEWAY,
                format!("invalid proxy host header {target_addr}: {error}"),
            )
                .into_response();
        }
    };
    parts.headers.insert(hyper::header::HOST, host);

    let proxy_req = hyper::Request::from_parts(parts, body);

    use hyper_util::client::legacy::Client;
    use hyper_util::client::legacy::connect::HttpConnector;
    let client: Client<HttpConnector, axum::body::Body> =
        Client::builder(hyper_util::rt::TokioExecutor::new()).build(HttpConnector::new());

    match client.request(proxy_req).await {
        Ok(res) => res.into_response(),
        Err(err) => (StatusCode::BAD_GATEWAY, format!("Proxy error: {}", err)).into_response(),
    }
}

async fn prefixed_admin_response(
    path: &str,
    dev_root: Option<&std::path::Path>,
) -> Option<Response> {
    let marker = "/_m/adm";
    let idx = path.find(marker)?;
    let prefix = &path[..idx];
    let admin_path = &path[idx..];

    if admin_path == marker {
        return Some(Redirect::temporary(&format!("{prefix}{marker}/")).into_response());
    }
    if admin_path == format!("{marker}/") {
        return Some(serve_index_asset(dev_root));
    }
    let asset_path = admin_path.strip_prefix("/_m/adm/")?;
    Some(handle_web_asset(dev_root, asset_path))
}

fn prefixed_admin_location(path: &str) -> Option<String> {
    if path == "/" {
        return Some("/_m/adm/".to_string());
    }
    if path.ends_with('/') && !path.contains("/_m") {
        return Some(format!("{}_m/adm/", path));
    }
    None
}

fn normalize_host(host_header: Option<&str>) -> Option<&str> {
    let host = host_header?.trim();
    if host.is_empty() {
        return None;
    }
    // Strip port if present (handling both IPv4/names and bracketed IPv6)
    if let Some(rest) = host.strip_prefix('[') {
        if let Some((ipv6, _)) = rest.split_once(']') {
            return Some(ipv6);
        }
    }
    Some(host.split(':').next().unwrap_or(host))
}

fn extract_service_name<'a>(host: &'a str, domain: &str) -> Option<&'a str> {
    let suffix = format!(".{}", domain.trim_start_matches('.'));
    if host.len() > suffix.len() && host.ends_with(&suffix) {
        let service = &host[..host.len() - suffix.len()];
        if !service.is_empty() && !service.contains('.') {
            return Some(service);
        }
    }
    None
}

fn serve_directory_asset(root: &std::path::Path, relative_path: &str) -> Option<Response> {
    let rel = relative_path.trim_start_matches('/');
    let target_file = if rel.is_empty() || rel.ends_with('/') {
        let index = if rel.is_empty() {
            "index.html".to_string()
        } else {
            format!("{rel}index.html")
        };
        confine_to_web_dir(root, &index)?
    } else {
        match confine_to_web_dir(root, rel) {
            Some(p) if p.is_file() => p,
            Some(p) if p.is_dir() => {
                let index = format!("{rel}/index.html");
                confine_to_web_dir(root, &index)?
            }
            _ => return None,
        }
    };

    if !target_file.is_file() {
        return None;
    }

    let content = std::fs::read(&target_file).ok()?;
    let mime = mime_for_path(&target_file.to_string_lossy());
    Some(
        (
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, mime)],
            content,
        )
            .into_response(),
    )
}

fn handle_static_routes(
    state: &AppState,
    host_header: Option<&str>,
    path: &str,
) -> Option<Response> {
    let host = normalize_host(host_header);

    // 1. Check explicit static_routes configured in TOML
    for route in &state.ssh_server.cfg.static_routes {
        if let Some(ref required_host) = route.host {
            let req_host = normalize_host(Some(required_host.as_str()));
            if req_host != host {
                continue;
            }
        }

        let prefix = route.path_prefix.as_str();
        if path == prefix {
            if let Some(resp) = serve_directory_asset(&route.dir, "") {
                return Some(resp);
            }
        } else if let Some(suffix) = path.strip_prefix(prefix) {
            if prefix.ends_with('/') || suffix.starts_with('/') {
                if let Some(resp) = serve_directory_asset(&route.dir, suffix) {
                    return Some(resp);
                }
            }
        }
    }

    // 2. Check automatic SERVICE.[domain] -> /home/SERVICE/www mapping
    let domain = std::env::var("MESH_DOMAIN").unwrap_or_else(|_| "localhost".to_string());
    if let Some(host_str) = host {
        if let Some(service) = extract_service_name(host_str, &domain) {
            let service_www = std::path::PathBuf::from(format!("/home/{service}/www"));
            if service_www.is_dir() {
                if let Some(resp) = serve_directory_asset(&service_www, path) {
                    return Some(resp);
                }
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirects_prefixed_root_to_admin() {
        assert_eq!(prefixed_admin_location("/").as_deref(), Some("/_m/adm/"));
        assert_eq!(
            prefixed_admin_location("/proxy/15080/").as_deref(),
            Some("/proxy/15080/_m/adm/")
        );
        assert_eq!(prefixed_admin_location("/favicon.ico"), None);
    }

    #[tokio::test]
    async fn serves_prefixed_admin_index_from_fallback() {
        let response = prefixed_admin_response("/proxy/15080/_m/adm/", None)
            .await
            .expect("prefixed admin response");
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[test]
    fn embeds_mesh_init_process_and_cgroup_pages() {
        for asset in ["mesh/mesh.js", "mesh/processes.html", "mesh/cgroups.html"] {
            assert!(
                Assets::get(asset).is_some(),
                "missing embedded asset {asset}"
            );
        }
        assert!(Assets::get("dashboard.html").is_none());
        assert!(Assets::get("discovery.html").is_none());
        assert!(Assets::get("probe.html").is_none());
        let helper = Assets::get("mesh/mesh.js").expect("mesh-init helper asset");
        let helper = std::str::from_utf8(&helper.data).expect("helper is UTF-8");
        assert!(helper.contains("proxy/jsonrpc/mesh-init"));
        assert!(helper.contains("jsonrpc: '2.0'"));
        let processes = Assets::get("mesh/processes.html").expect("processes asset");
        let processes = std::str::from_utf8(&processes.data).expect("processes is UTF-8");
        assert!(processes.contains("escapeHtml(process.cmdline"));
        assert!(!processes.contains("fonts.googleapis.com"));
        let cgroups = Assets::get("mesh/cgroups.html").expect("cgroups asset");
        let cgroups = std::str::from_utf8(&cgroups.data).expect("cgroups is UTF-8");
        assert!(cgroups.contains("escapeHtml(p.cmdline"));
        assert!(!cgroups.contains("fonts.googleapis.com"));
    }

    #[test]
    fn test_normalize_host() {
        assert_eq!(normalize_host(Some("example.com")), Some("example.com"));
        assert_eq!(normalize_host(Some("example.com:8080")), Some("example.com"));
        assert_eq!(normalize_host(Some("[::1]:8080")), Some("::1"));
        assert_eq!(normalize_host(Some("  localhost:3000  ")), Some("localhost"));
        assert_eq!(normalize_host(None), None);
        assert_eq!(normalize_host(Some("   ")), None);
    }

    #[test]
    fn test_extract_service_name() {
        assert_eq!(extract_service_name("lmesh.localhost", "localhost"), Some("lmesh"));
        assert_eq!(extract_service_name("lmesh.test.m", "test.m"), Some("lmesh"));
        assert_eq!(extract_service_name("lmesh.test.m", ".test.m"), Some("lmesh"));
        assert_eq!(extract_service_name("sub.lmesh.localhost", "localhost"), None);
        assert_eq!(extract_service_name("localhost", "localhost"), None);
        assert_eq!(extract_service_name("other.org", "localhost"), None);
    }

    #[tokio::test]
    async fn test_serve_directory_asset_and_static_routes() {
        let temp = tempfile::tempdir().unwrap();
        let www_dir = temp.path().join("www");
        std::fs::create_dir_all(&www_dir).unwrap();
        std::fs::write(www_dir.join("index.html"), "<h1>Home</h1>").unwrap();
        std::fs::write(www_dir.join("hello.txt"), "world").unwrap();

        // 1. Direct serve_directory_asset
        let resp = serve_directory_asset(&www_dir, "/").expect("serve root");
        assert_eq!(resp.status(), StatusCode::OK);

        let resp = serve_directory_asset(&www_dir, "/hello.txt").expect("serve hello.txt");
        assert_eq!(resp.status(), StatusCode::OK);

        let resp_missing = serve_directory_asset(&www_dir, "/missing.txt");
        assert!(resp_missing.is_none());

        // Traversal attempt should fail
        let resp_traversal = serve_directory_asset(&www_dir, "../outside.txt");
        assert!(resp_traversal.is_none());
    }
}
