//! Catalog generated from the root API.md.

use serde_json::Value;
use std::sync::LazyLock;

static TOOLS: LazyLock<Vec<Value>> = LazyLock::new(|| {
    serde_json::from_str(include_str!("../platform/tools.json"))
        .expect("platform tools.json must be generated from API.md")
});

pub(crate) fn tools_for(prefix: &str) -> Value {
    Value::Array(
        TOOLS
            .iter()
            .filter(|tool| {
                tool.get("name")
                    .and_then(Value::as_str)
                    .is_some_and(|name| name.starts_with(prefix))
            })
            .cloned()
            .collect(),
    )
}
