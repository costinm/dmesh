//! Compact, unambiguous `key=value` rendering of structured JSON values.

use serde_json::Value;

/// Flatten nested objects with dotted keys; keep arrays as JSON values.
pub fn flatten_json(value: &Value) -> String {
    let mut fields = Vec::new();
    flatten_into(&mut fields, None, value);
    fields.join(" ")
}

fn flatten_into(fields: &mut Vec<String>, prefix: Option<&str>, value: &Value) {
    match value {
        Value::Object(values) => {
            for (key, value) in values {
                let key = prefix
                    .map(|prefix| format!("{prefix}.{key}"))
                    .unwrap_or_else(|| key.clone());
                flatten_into(fields, Some(&key), value);
            }
        }
        _ => {
            if let Some(key) = prefix {
                fields.push(format!("{key}={}", render_value(value)));
            }
        }
    }
}

fn render_value(value: &Value) -> String {
    match value {
        Value::String(value)
            if !value.is_empty()
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_graphic() && !matches!(byte, b'=' | b'"')) =>
        {
            value.clone()
        }
        _ => value.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn nested_values_are_flattened_and_ambiguous_text_is_quoted() {
        assert_eq!(
            flatten_json(
                &json!({"radio": {"count": 2, "name": "a b", "items": [1, 2]}, "ready": true})
            ),
            "radio.count=2 radio.items=[1,2] radio.name=\"a b\" ready=true"
        );
    }
}
