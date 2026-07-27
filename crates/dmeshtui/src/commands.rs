use std::path::{Path, PathBuf};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct ToolCommand {
    pub name: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub group: String,
    #[serde(default)]
    pub input_schema: serde_json::Value,
}

#[derive(Debug, Clone)]
pub struct MeshCommand {
    pub name: String,
    pub description: String,
    pub service: String,
    pub group: String,
    pub params: Vec<CommandParam>,
}

#[derive(Debug, Clone)]
pub struct CommandParam {
    pub name: String,
    pub required: bool,
    pub param_type: String,
    pub description: String,
}

impl MeshCommand {
    pub fn from_tool(tool: ToolCommand, service: impl Into<String>) -> Self {
        let params = parse_input_schema(&tool.input_schema);
        Self {
            name: tool.name,
            description: tool.description,
            service: service.into(),
            group: tool.group,
            params,
        }
    }
}

fn parse_input_schema(schema: &serde_json::Value) -> Vec<CommandParam> {
    let mut params = Vec::new();
    if let Some(props) = schema.get("properties").and_then(|v| v.as_object()) {
        let required: Vec<String> = schema
            .get("required")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        for (name, prop) in props {
            if let Some(obj) = prop.as_object() {
                let param_type = obj
                    .get("type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("string")
                    .to_owned();
                let description = obj
                    .get("description")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_owned();
                let required = required.contains(name);
                params.push(CommandParam {
                    name: name.clone(),
                    required,
                    param_type,
                    description,
                });
            }
        }
    }
    params
}

fn load_tools_from_path(path: &Path) -> Vec<ToolCommand> {
    let Ok(content) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    if let Ok(tools) = serde_json::from_str::<Vec<ToolCommand>>(&content) {
        return tools;
    }
    if let Ok(val) = serde_json::from_str::<serde_json::Value>(&content) {
        if let Some(arr) = val.get("tools").and_then(|t| t.as_array()) {
            if let Ok(tools) = serde_json::from_value::<Vec<ToolCommand>>(serde_json::Value::Array(arr.clone())) {
                return tools;
            }
        }
    }
    Vec::new()
}

#[derive(Debug, Clone)]
pub struct ServiceInfo {
    pub name: String,
    pub connected: bool,
    pub socket_path: PathBuf,
}

fn socket_path_for(service: &str) -> PathBuf {
    PathBuf::from(format!("/run/mesh/{}/mesh.sock", service))
}

pub fn discover_services(cwd: &Path) -> Vec<ServiceInfo> {
    let tools_dir = cwd.join(".dmeshtui");
    let mut services = Vec::new();

    if let Ok(entries) = std::fs::read_dir(&tools_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            let tools_json = path.join("tools.json");
            if !tools_json.exists() {
                continue;
            }
            let sock = socket_path_for(name);
            services.push(ServiceInfo {
                name: name.to_string(),
                connected: sock.exists(),
                socket_path: sock,
            });
        }
    }

    services.sort_by(|a, b| a.name.cmp(&b.name));
    services
}

pub fn discover_commands(cwd: &Path) -> Vec<MeshCommand> {
    let env_override = std::env::var("DMESH_TOOLS").ok();
    let mut commands = Vec::new();

    if let Some(env_val) = env_override {
        for path_str in env_val.split(',') {
            let path_str = path_str.trim();
            if path_str.is_empty() {
                continue;
            }
            let path = Path::new(path_str);
            let tools = load_tools_from_path(path);
            let service = path
                .parent()
                .and_then(|p| p.file_name())
                .and_then(|n| n.to_str())
                .unwrap_or("unknown")
                .to_string();
            for tool in tools {
                commands.push(MeshCommand::from_tool(tool, &service));
            }
        }
        return commands;
    }

    let tools_dir = cwd.join(".dmeshtui");
    if let Ok(entries) = std::fs::read_dir(&tools_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            let tools_json = path.join("tools.json");
            if !tools_json.exists() {
                continue;
            }
            let tools = load_tools_from_path(&tools_json);
            for tool in tools {
                commands.push(MeshCommand::from_tool(tool, name));
            }
        }
    }

    commands.sort_by(|a, b| a.service.cmp(&b.service).then_with(|| a.name.cmp(&b.name)));
    commands
}
