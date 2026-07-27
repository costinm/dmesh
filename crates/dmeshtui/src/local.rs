use crate::MeshClient;
use anyhow::Context;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

pub struct LocalMeshSocket {
    active_service: String,
    socket_path: PathBuf,
    remote: Option<RemoteTarget>,
}

impl LocalMeshSocket {
    pub fn from_env() -> Self {
        Self::from_options(MeshSocketOptions::default()).unwrap_or_else(|err| {
            eprintln!("failed to configure dmeshtui mesh socket: {err}");
            let app = "mesh-init".to_owned();
            Self {
                socket_path: socket_path_for(&app),
                active_service: app,
                remote: None,
            }
        })
    }

    pub fn from_options(options: MeshSocketOptions) -> anyhow::Result<Self> {
        let remote = options
            .remote
            .or_else(|| std::env::var("DMESHTUI_REMOTE").ok())
            .filter(|remote| !remote.is_empty());
        let app = options
            .app
            .or_else(|| std::env::var("DMESHTUI_MESH_APP").ok())
            .unwrap_or_else(|| {
                if remote.is_some() {
                    "ssh-mesh".to_owned()
                } else {
                    "mesh-init".to_owned()
                }
            });

        let socket_path = options
            .socket
            .or_else(|| std::env::var_os("DMESHTUI_MESH_SOCK").map(PathBuf::from))
            .unwrap_or_else(|| socket_path_for(&app));
        let remote = remote.map(|node| RemoteTarget {
            node,
            app: options
                .target_app
                .or_else(|| std::env::var("DMESHTUI_TARGET_APP").ok())
                .unwrap_or_else(|| "mesh-init".to_owned()),
            method: options
                .remote_method
                .or_else(|| std::env::var("DMESHTUI_REMOTE_METHOD").ok())
                .unwrap_or_else(|| "mesh.remote.jsonl".to_owned()),
        });
        Ok(Self {
            active_service: app,
            socket_path,
            remote,
        })
    }

    pub fn new_for_service(service: &str, socket_path: PathBuf) -> Self {
        Self {
            active_service: service.to_string(),
            socket_path,
            remote: None,
        }
    }

    pub fn active_service(&self) -> &str {
        &self.active_service
    }

    pub fn set_active_service(&mut self, service: &str) {
        self.active_service = service.to_string();
        self.socket_path = socket_path_for(service);
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    pub fn is_socket_available(&self) -> bool {
        self.socket_path.exists()
    }
}

impl MeshClient for LocalMeshSocket {
    fn send_command(&mut self, line: &str) -> anyhow::Result<String> {
        let request = MeshRequest::parse(line)?;
        let request = match &self.remote {
            Some(remote) => remote.wrap_request(request.to_json_value()),
            None => request.to_json_value(),
        };
        let mut stream = UnixStream::connect(&self.socket_path).with_context(|| {
            format!(
                "failed to connect to {} socket at {}",
                self.active_service,
                self.socket_path.display()
            )
        })?;

        serde_json::to_writer(&mut stream, &request)?;
        stream.write_all(b"\n")?;
        stream.flush()?;
        stream.shutdown(std::net::Shutdown::Write).ok();

        let mut response = String::new();
        let mut reader = BufReader::new(stream);
        reader.read_line(&mut response).with_context(|| {
            format!(
                "failed to read response from {} socket at {}",
                self.active_service,
                self.socket_path.display()
            )
        })?;

        let response = response.trim();
        if response.is_empty() {
            anyhow::bail!("empty response from {}", self.socket_path.display());
        }
        Ok(response.to_string())
    }
}

pub type LocalMeshCommand = LocalMeshSocket;

#[derive(Default)]
pub struct MeshSocketOptions {
    pub app: Option<String>,
    pub socket: Option<PathBuf>,
    pub remote: Option<String>,
    pub target_app: Option<String>,
    pub remote_method: Option<String>,
}

struct RemoteTarget {
    node: String,
    app: String,
    method: String,
}

impl RemoteTarget {
    fn wrap_request(&self, request: serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "method": self.method,
            "node": self.node,
            "app": self.app,
            "data": request,
        })
    }
}

struct MeshRequest {
    method: String,
    params: Option<String>,
}

impl MeshRequest {
    fn parse(line: &str) -> anyhow::Result<Self> {
        let line = line.trim();
        if line.is_empty() {
            anyhow::bail!("empty command");
        }

        let (method, rest) = line
            .split_once(char::is_whitespace)
            .map(|(method, rest)| (method, rest.trim()))
            .unwrap_or((line, ""));
        if method.is_empty() {
            anyhow::bail!("missing method");
        }

        let params = if rest.is_empty() {
            None
        } else if rest.starts_with('{') {
            let value: serde_json::Value = serde_json::from_str(rest)
                .with_context(|| format!("invalid JSON object params: {}", rest))?;
            if !value.is_object() {
                anyhow::bail!("params must be a JSON object");
            }
            Some(rest.to_owned())
        } else {
            let mut params = serde_json::Map::new();
            params.insert("text".to_owned(), serde_json::Value::String(rest.to_owned()));
            Some(serde_json::Value::Object(params).to_string())
        };

        Ok(Self {
            method: method.to_owned(),
            params,
        })
    }

    fn to_json_value(&self) -> serde_json::Value {
        let mut request = serde_json::Map::new();
        request.insert(
            "method".to_owned(),
            serde_json::Value::String(self.method.clone()),
        );
        if let Some(params) = &self.params {
            if let Ok(serde_json::Value::Object(params)) =
                serde_json::from_str::<serde_json::Value>(params)
            {
                for (key, value) in params {
                    request.insert(key, value);
                }
            }
        }
        serde_json::Value::Object(request)
    }
}

pub fn socket_path_for(app: &str) -> PathBuf {
    if let Some(path) = std::env::var_os("DMESHTUI_MESH_SOCK") {
        return PathBuf::from(path);
    }

    let env_prefix = app.to_uppercase().replace('-', "_");
    if let Some(path) = std::env::var_os(format!("{}_UDS", env_prefix)) {
        return PathBuf::from(path);
    }
    if let Some(run_dir) = std::env::var_os(format!("{}_RUN", env_prefix)) {
        return PathBuf::from(run_dir).join("control.sock");
    }

    if let Some(base) = std::env::var_os("MESH_RUN_BASE") {
        return PathBuf::from(base).join(app).join("mesh.sock");
    }
    if let Some(root) = std::env::var_os("MESH_HOME") {
        return PathBuf::from(root)
            .join("run")
            .join("mesh")
            .join(app)
            .join("mesh.sock");
    }

    PathBuf::from("/run/mesh").join(app).join("mesh.sock")
}
