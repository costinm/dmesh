//! Client-owned schema catalog discovery and process-lifetime caching.
//!
//! A service catalog is a set of MCP-style tool descriptors (`tools.json`
//! shape: a JSON array of tools, or an object with a `tools` array). The
//! resolver assembles one catalog per service from every JSON file found in
//! the standard schema directories, searched in priority order:
//!
//! 1. `$MESH_SCHEMA_DIR/<service>/` when `MESH_SCHEMA_DIR` is set;
//! 2. `/opt/<service>/etc/schemas/` — installed with the service package;
//! 3. `$HOME/opt/<service>/etc/schemas/` — per-user installed catalog;
//! 4. `$HOME/etc/schemas/` — user-installed schemas shared across services.
//!
//! Within one directory, files load in sorted file-name order. A tool name
//! that appears in more than one file keeps the definition from the
//! higher-priority location, so a user file can extend but not shadow a
//! packaged catalog.
//!
//! The ssh-mesh admin gateway serves the same catalog for operator
//! discovery: `GET /_m/mesh/services` lists the registered services and
//! `GET /_m/mesh/services/<service>/tools` returns the catalog, where
//! `?view=all` includes every entry and the default view shows only tools
//! whose `x-ui-visibility` is `default` or unset. The visibility value is
//! presentation metadata only: catalog methods remain callable through the
//! policy-controlled record and named-call endpoints.

use std::{
    collections::{HashMap, HashSet},
    ffi::OsString,
    path::{Component, Path, PathBuf},
    sync::{Arc, OnceLock, RwLock},
};

use anyhow::{Context, Result, anyhow, bail};
use serde_json::Value;

use crate::tagged::TaggedSchema;

/// One parsed catalog together with the source used to load it.
#[derive(Debug)]
pub struct ResolvedCatalog {
    pub component: String,
    pub path: PathBuf,
    pub tools: Arc<Value>,
    pub catalog: Arc<TaggedSchema>,
}

/// Lazy resolver shared by general clients and mesh gateway implementations.
///
/// Successful parses remain cached for the life of the resolver. Missing and
/// malformed files are not cached, so correcting package/configuration state
/// does not require a process restart before the first successful load.
#[derive(Clone, Default)]
pub struct CatalogResolver {
    cache: Arc<RwLock<HashMap<(String, Vec<PathBuf>), Arc<ResolvedCatalog>>>>,
}

impl CatalogResolver {
    /// Resolve a required installed catalog using the standard search path.
    pub fn require(&self, component: &str) -> Result<Arc<ResolvedCatalog>> {
        self.resolve(component).ok_or_else(|| {
            anyhow!(
                "no {component} catalog found; install a .json schema under \
                 /opt/{component}/etc/schemas, $HOME/opt/{component}/etc/schemas, \
                 or $HOME/etc/schemas, or set MESH_SCHEMA_DIR/MESH_TOOLS"
            )
        })?
    }
    /// Resolve a component using the standard client-side schema locations.
    ///
    /// `MESH_TOOLS` is an exact override. If it is set, failure to load that
    /// file is an error rather than permission to silently select another
    /// catalog. Other locations are searched in order and may be absent.
    pub fn resolve(&self, component: &str) -> Option<Result<Arc<ResolvedCatalog>>> {
        self.resolve_with(component, |key| std::env::var_os(key))
    }

    fn resolve_with<F>(
        &self,
        component: &str,
        mut env: F,
    ) -> Option<Result<Arc<ResolvedCatalog>>>
    where
        F: FnMut(&str) -> Option<OsString>,
    {
        if let Err(error) = validate_component(component) {
            return Some(Err(error));
        }

        if let Some(path) = env("MESH_TOOLS") {
            return Some(self.load_path(component, PathBuf::from(path)));
        }

        let files = catalog_files_with(component, env);
        if files.is_empty() {
            return None;
        }
        Some(self.load_files(component, files))
    }

    /// Load and cache one explicit catalog path.
    pub fn load_path(
        &self,
        component: &str,
        path: impl Into<PathBuf>,
    ) -> Result<Arc<ResolvedCatalog>> {
        self.load_files(component, vec![path.into()])
    }

    /// Load and cache the union of several catalog files, in priority order.
    pub fn load_files(
        &self,
        component: &str,
        files: Vec<PathBuf>,
    ) -> Result<Arc<ResolvedCatalog>> {
        validate_component(component)?;
        let key = (component.to_owned(), files.clone());
        if let Some(cached) = self
            .cache
            .read()
            .expect("schema catalog lock poisoned")
            .get(&key)
            .cloned()
        {
            return Ok(cached);
        }

        let mut merged: Vec<Value> = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();
        for path in &files {
            let contents = std::fs::read_to_string(path)
                .with_context(|| format!("read schema catalog {}", path.display()))?;
            let value: Value = serde_json::from_str(&contents)
                .with_context(|| format!("parse schema catalog {}", path.display()))?;
            let tools = value
                .as_array()
                .cloned()
                .or_else(|| value.get("tools").and_then(Value::as_array).cloned())
                .with_context(|| {
                    format!(
                        "{} is not a tools catalog (array or object with a tools array)",
                        path.display()
                    )
                })?;
            for tool in tools {
                if let Some(name) = tool.get("name").and_then(Value::as_str) {
                    if !seen.insert(name.to_owned()) {
                        continue;
                    }
                }
                merged.push(tool);
            }
        }
        let tools = Arc::new(Value::Array(merged));
        let catalog = Arc::new(
            TaggedSchema::from_tools_json(&tools)
                .with_context(|| format!("parse {component} tools: invalid tagged catalog"))?,
        );
        let resolved = Arc::new(ResolvedCatalog {
            component: component.to_owned(),
            path: files
                .into_iter()
                .next()
                .expect("resolve() guarantees at least one file"),
            tools,
            catalog,
        });
        let mut cache = self
            .cache
            .write()
            .expect("schema catalog lock poisoned");
        Ok(cache.entry(key).or_insert(resolved).clone())
    }
}

/// Process-wide resolver used by compatibility helpers and gateway registries.
pub fn service_catalog_resolver() -> &'static CatalogResolver {
    static RESOLVER: OnceLock<CatalogResolver> = OnceLock::new();
    RESOLVER.get_or_init(CatalogResolver::default)
}

fn validate_component(component: &str) -> Result<()> {
    let mut parts = Path::new(component).components();
    if component.is_empty()
        || !matches!(parts.next(), Some(Component::Normal(_)))
        || parts.next().is_some()
        || component == "."
        || component == ".."
    {
        bail!("invalid schema component {component:?}");
    }
    Ok(())
}

fn catalog_dirs_with<F>(component: &str, env: &mut F) -> Vec<PathBuf>
where
    F: FnMut(&str) -> Option<OsString>,
{
    let mut dirs = Vec::new();
    if let Some(root) = env("MESH_SCHEMA_DIR") {
        dirs.push(PathBuf::from(root).join(component));
    }
    dirs.push(
        PathBuf::from("/opt")
            .join(component)
            .join("etc/schemas"),
    );
    if let Some(home) = env("HOME") {
        dirs.push(
            PathBuf::from(&home)
                .join("opt")
                .join(component)
                .join("etc/schemas"),
        );
        dirs.push(PathBuf::from(home).join("etc/schemas"));
    }
    dirs
}

fn catalog_files_with<F>(component: &str, env: F) -> Vec<PathBuf>
where
    F: FnMut(&str) -> Option<OsString>,
{
    let mut env = env;
    let mut files = Vec::new();
    for dir in catalog_dirs_with(component, &mut env) {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut dir_files: Vec<PathBuf> = entries
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.is_file()
                    && path
                        .extension()
                        .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
            })
            .collect();
        dir_files.sort();
        files.extend(dir_files);
    }
    files
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_dirs_use_schema_root_then_opt_then_home() {
        let dirs = catalog_dirs_with("demo", &mut |key| match key {
            "MESH_SCHEMA_DIR" => Some(OsString::from("/schemas")),
            "HOME" => Some(OsString::from("/home/client")),
            _ => None,
        });
        assert_eq!(
            dirs,
            vec![
                PathBuf::from("/schemas/demo"),
                PathBuf::from("/opt/demo/etc/schemas"),
                PathBuf::from("/home/client/opt/demo/etc/schemas"),
                PathBuf::from("/home/client/etc/schemas"),
            ]
        );
    }

    #[test]
    fn catalog_files_scan_all_json_in_priority_order() {
        let temp = tempfile::tempdir().unwrap();
        let opt = temp.path().join("opt");
        let home = temp.path().join("home");
        for dir in [
            opt.join("demo/etc/schemas"),
            home.join("opt/demo/etc/schemas"),
            home.join("etc/schemas"),
        ] {
            std::fs::create_dir_all(&dir).unwrap();
        }
        std::fs::write(opt.join("demo/etc/schemas/zz-late.json"), "[]").unwrap();
        std::fs::write(opt.join("demo/etc/schemas/aa-first.json"), "[]").unwrap();
        std::fs::write(home.join("opt/demo/etc/schemas/extra.json"), "[]").unwrap();
        std::fs::write(home.join("etc/schemas/user.json"), "[]").unwrap();
        std::fs::write(home.join("etc/schemas/notes.txt"), "not json").unwrap();

        let files = catalog_files_with("demo", |key| match key {
            "HOME" => Some(home.as_os_str().to_os_string()),
            _ => None,
        });
        // /opt/demo/etc/schemas does not exist in this temp tree, so only the
        // HOME directories contribute, each in sorted file-name order.
        assert_eq!(
            files,
            vec![
                home.join("opt/demo/etc/schemas/extra.json"),
                home.join("etc/schemas/user.json"),
            ]
        );
    }

    #[test]
    fn component_cannot_escape_schema_root() {
        for component in ["", ".", "..", "../demo", "demo/other", "/demo"] {
            assert!(
                validate_component(component).is_err(),
                "accepted {component:?}"
            );
        }
        assert!(validate_component("mesh-init").is_ok());
    }

    #[test]
    fn successful_catalog_is_cached_by_component_and_path() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("tools.json");
        std::fs::write(
            &path,
            r#"[{"name":"demo.ping","x-component-index":1,"x-method-index":2}]"#,
        )
        .unwrap();
        let resolver = CatalogResolver::default();
        let first = resolver.load_path("demo", &path).unwrap();
        std::fs::write(&path, "not json").unwrap();
        let second = resolver.load_path("demo", &path).unwrap();
        assert!(Arc::ptr_eq(&first, &second));
        assert!(first.catalog.method("demo.ping").is_some());
    }

    #[test]
    fn merged_catalog_keeps_higher_priority_tool_on_name_conflict() {
        let temp = tempfile::tempdir().unwrap();
        let high = temp.path().join("high.json");
        let low = temp.path().join("low.json");
        std::fs::write(
            &high,
            r#"[{"name":"demo.ping","x-component-index":1,"x-method-index":2}]"#,
        )
        .unwrap();
        std::fs::write(
            &low,
            r#"[{"name":"demo.ping","x-component-index":9,"x-method-index":9},
                {"name":"demo.pong","x-component-index":1,"x-method-index":3}]"#,
        )
        .unwrap();
        let resolved = CatalogResolver::default()
            .load_files("demo", vec![high, low])
            .unwrap();
        let methods: Vec<String> = resolved
            .tools
            .as_array()
            .unwrap()
            .iter()
            .map(|tool| tool["name"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(methods, vec!["demo.ping", "demo.pong"]);
        assert_eq!(
            resolved
                .catalog
                .method("demo.ping")
                .unwrap()
                .method,
            crate::tagged::NameOrTag::Tag(2)
        );
    }

    #[test]
    fn resolve_uses_home_user_schemas_when_system_opt_is_absent() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        std::fs::create_dir_all(home.join("etc/schemas")).unwrap();
        std::fs::write(
            home.join("etc/schemas/lmesh.json"),
            r#"[{"name":"demo.ping","x-component-index":1,"x-method-index":2}]"#,
        )
        .unwrap();
        let resolver = CatalogResolver::default();
        let resolved = resolver
            .resolve_with("demo", |key| match key {
                "HOME" => Some(home.as_os_str().to_os_string()),
                _ => None,
            })
            .unwrap()
            .unwrap();
        assert!(resolved.catalog.method("demo.ping").is_some());
    }
}
