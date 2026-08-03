use serde_json::Value;

#[derive(Debug, Clone)]
pub enum RenderFormat {
    Flat,
    Csv { headers: Vec<String> },
    Table,
    Summary,
}

impl Default for RenderFormat {
    fn default() -> Self {
        RenderFormat::Flat
    }
}

pub fn render_json_flat(value: &Value) -> String {
    let mut out = String::new();
    flatten_value(value, "", &mut out, 0);
    if out.ends_with('\n') {
        out.pop();
    }
    out
}

pub fn render_json_with_format(value: &Value, fmt: &RenderFormat) -> String {
    match fmt {
        RenderFormat::Flat => render_json_flat(value),
        RenderFormat::Summary => render_summary(value),
        RenderFormat::Csv { headers } => render_csv(value, headers),
        RenderFormat::Table => render_table(value),
    }
}

fn flatten_value(value: &Value, prefix: &str, out: &mut String, depth: usize) {
    if depth > 8 {
        return;
    }
    match value {
        Value::Object(map) => {
            for (k, v) in map {
                let key = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{}.{}", prefix, k)
                };
                flatten_value(v, &key, out, depth + 1);
            }
        }
        Value::Array(arr) => {
            if arr.is_empty() {
                out.push_str(prefix);
                out.push_str(": []\n");
            } else if arr.len() <= 4 && !arr.iter().any(|v| v.is_object() || v.is_array()) {
                let items: Vec<String> = arr.iter().map(render_scalar).collect();
                out.push_str(prefix);
                out.push_str(": [");
                out.push_str(&items.join(", "));
                out.push_str("]\n");
            } else if arr.iter().all(|v| v.is_object()) {
                for (i, item) in arr.iter().enumerate() {
                    let key = format!("{}.{}", prefix, i);
                    flatten_value(item, &key, out, depth + 1);
                }
            } else {
                out.push_str(prefix);
                out.push_str(&format!(": [{} items]\n", arr.len()));
            }
        }
        _ => {
            out.push_str(prefix);
            out.push_str(": ");
            out.push_str(&render_scalar(value));
            out.push('\n');
        }
    }
}

fn render_scalar(value: &Value) -> String {
    match value {
        Value::Null => "(empty)".to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => s.clone(),
        Value::Array(a) => {
            if a.len() <= 3 {
                let items: Vec<String> = a.iter().map(render_scalar).collect();
                format!("[{}]", items.join(", "))
            } else {
                format!("[{} items]", a.len())
            }
        }
        Value::Object(_) => "{ ... }".to_string(),
    }
}

fn render_summary(value: &Value) -> String {
    match value {
        Value::Object(map) => {
            let first = map.iter().next();
            match first {
                Some((k, v)) if map.len() == 1 => format!("{}: {}", k, render_scalar(v)),
                Some(_) => {
                    let count = map.len();
                    let keys: Vec<&str> = map.keys().take(4).map(|s| s.as_str()).collect();
                    format!(
                        "{} keys ({}): {}",
                        count,
                        keys.join(", "),
                        if count > 4 { "..." } else { "" }
                    )
                }
                None => "(empty object)".to_string(),
            }
        }
        Value::Array(arr) => format!("[{} items]", arr.len()),
        _ => render_scalar(value),
    }
}

fn render_csv(value: &Value, headers: &[String]) -> String {
    match value {
        Value::Array(rows) => {
            let mut out = String::new();
            out.push_str(&headers.join(", "));
            out.push('\n');
            for row in rows {
                if let Value::Object(map) = row {
                    let cells: Vec<String> = headers
                        .iter()
                        .map(|h| map.get(h).map(render_scalar).unwrap_or_default())
                        .collect();
                    out.push_str(&cells.join(", "));
                    out.push('\n');
                }
            }
            out
        }
        _ => render_json_flat(value),
    }
}

fn render_table(value: &Value) -> String {
    match value {
        Value::Array(rows) if !rows.is_empty() => {
            let headers: Vec<String> = match &rows[0] {
                Value::Object(map) => map.keys().cloned().collect(),
                _ => return render_json_flat(value),
            };
            let mut widths: Vec<usize> = headers.iter().map(|h| h.len()).collect();
            let str_rows: Vec<Vec<String>> = rows
                .iter()
                .map(|row| {
                    if let Value::Object(map) = row {
                        headers
                            .iter()
                            .enumerate()
                            .map(|(i, h)| {
                                let val =
                                    map.get(h.as_str()).map(render_scalar).unwrap_or_default();
                                if val.len() > widths[i] {
                                    widths[i] = val.len();
                                }
                                val
                            })
                            .collect()
                    } else {
                        vec![]
                    }
                })
                .collect();
            let sep: String = widths
                .iter()
                .map(|w| "-".repeat(*w + 2))
                .collect::<Vec<_>>()
                .join("+");
            let mut out = String::new();
            let header_line: String = headers
                .iter()
                .enumerate()
                .map(|(i, h)| format!("{:width$}", h, width = widths[i]))
                .collect::<Vec<_>>()
                .join(" | ");
            out.push_str(&header_line);
            out.push('\n');
            out.push_str(&sep);
            out.push('\n');
            for row in &str_rows {
                let line: String = row
                    .iter()
                    .enumerate()
                    .map(|(i, c)| format!("{:width$}", c, width = widths[i]))
                    .collect::<Vec<_>>()
                    .join(" | ");
                out.push_str(&line);
                out.push('\n');
            }
            out
        }
        _ => render_json_flat(value),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn flat_object() {
        let v = json!({"success": true, "pid": 42});
        let out = render_json_flat(&v);
        assert!(out.contains("success: true"));
        assert!(out.contains("pid: 42"));
    }

    #[test]
    fn nested_object() {
        let v = json!({"data": {"ssh-mesh": {"pid": 42, "state": "running"}}});
        let out = render_json_flat(&v);
        assert!(out.contains("data.ssh-mesh.pid: 42"));
        assert!(out.contains("data.ssh-mesh.state: running"));
    }

    #[test]
    fn null_value() {
        let v = json!({"x": null});
        let out = render_json_flat(&v);
        assert!(out.contains("(empty)"));
    }

    #[test]
    fn empty_array() {
        let v = json!({"items": []});
        let out = render_json_flat(&v);
        assert!(out.contains("[]"));
    }

    #[test]
    fn small_array_inline() {
        let v = json!({"ports": [15022, 18480]});
        let out = render_json_flat(&v);
        assert!(out.contains("[15022, 18480]"));
    }

    #[test]
    fn summary_mode() {
        let v = json!({"success": true, "data": {"x": 1}});
        let out = render_summary(&v);
        assert!(out.contains("2 keys"));
    }

    #[test]
    fn table_mode() {
        let v = json!([
            {"name": "ssh-mesh", "pid": 42},
            {"name": "lmesh", "pid": 99}
        ]);
        let out = render_table(&v);
        assert!(out.contains("name"));
        assert!(out.contains("pid"));
        assert!(out.contains("ssh-mesh"));
        assert!(out.contains("lmesh"));
    }
}
