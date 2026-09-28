//! Client-owned `tools.json` discovery and process-lifetime caching.

use std::{
    collections::HashMap,
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
    cache: Arc<RwLock<HashMap<(String, PathBuf), Arc<ResolvedCatalog>>>>,
}

impl CatalogResolver {
    /// Resolve a required installed catalog using the standard search path.
    pub fn require(&self, component: &str) -> Result<Arc<ResolvedCatalog>> {
        self.resolve(component).ok_or_else(|| {
            anyhow!("missing {component} tools.json; set MESH_SCHEMA_DIR or install /opt/{component}/etc/schemas/tools.json")
        })?
    }
    /// Resolve a component using the standard client-side schema locations.
    ///
    /// `MESH_TOOLS` is an exact override. If it is set, failure to load that
    /// file is an error rather than permission to silently select another
    /// catalog. Other locations are searched in order and may be absent.
    pub fn resolve(&self, component: &str) -> Option<Result<Arc<ResolvedCatalog>>> {
        if let Err(error) = validate_component(component) {
            return Some(Err(error));
        }

        if let Some(path) = std::env::var_os("MESH_TOOLS") {
            return Some(self.load_path(component, PathBuf::from(path)));
        }

        let candidates = catalog_candidates_with(component, |key| std::env::var_os(key));
        let path = candidates.into_iter().find(|path| path.is_file())?;
        Some(self.load_path(component, path))
    }

    /// Load and cache one explicit catalog path.
    pub fn load_path(
        &self,
        component: &str,
        path: impl Into<PathBuf>,
    ) -> Result<Arc<ResolvedCatalog>> {
        validate_component(component)?;
        let path = path.into();
        let key = (component.to_owned(), path.clone());
        if let Some(catalog) = self
            .cache
            .read()
            .expect("catalog resolver lock poisoned")
            .get(&key)
            .cloned()
        {
            return Ok(catalog);
        }

        let contents = std::fs::read_to_string(&path)
            .with_context(|| format!("read tools catalog {}", path.display()))?;
        let tools: Value = serde_json::from_str(&contents)
            .with_context(|| format!("parse tools catalog {}", path.display()))?;
        let catalog = TaggedSchema::from_tools_json(&tools).with_context(|| {
            format!(
                "parse tools catalog {}: invalid tagged catalog",
                path.display()
            )
        })?;
        let resolved = Arc::new(ResolvedCatalog {
            component: component.to_owned(),
            path,
            tools: Arc::new(tools),
            catalog: Arc::new(catalog),
        });
        let mut cache = self.cache.write().expect("catalog resolver lock poisoned");
        Ok(cache.entry(key).or_insert_with(|| resolved.clone()).clone())
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
        bail!("invalid schema component {component:?}")
    }
    Ok(())
}

fn catalog_candidates_with<F>(component: &str, mut env: F) -> Vec<PathBuf>
where
    F: FnMut(&str) -> Option<OsString>,
{
    let mut candidates = Vec::new();
    if let Some(root) = env("MESH_SCHEMA_DIR") {
        candidates.push(PathBuf::from(root).join(component).join("tools.json"));
    }
    if let Some(home) = env("HOME") {
        candidates.push(
            PathBuf::from(home)
                .join("opt")
                .join(component)
                .join("etc/schemas/tools.json"),
        );
    }
    candidates.push(
        PathBuf::from("/opt")
            .join(component)
            .join("etc/schemas/tools.json"),
    );
    candidates
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidates_use_schema_root_then_home_then_system_opt() {
        let candidates = catalog_candidates_with("demo", |key| match key {
            "MESH_SCHEMA_DIR" => Some(OsString::from("/schemas")),
            "HOME" => Some(OsString::from("/home/client")),
            _ => None,
        });
        assert_eq!(
            candidates,
            vec![
                PathBuf::from("/schemas/demo/tools.json"),
                PathBuf::from("/home/client/opt/demo/etc/schemas/tools.json"),
                PathBuf::from("/opt/demo/etc/schemas/tools.json"),
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
}
