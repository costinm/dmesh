//! Generic JSON gateway for a local or adb-forwarded mesh HTTP service.
//! The server translates this request to the same tagged-CBOR service handler
//! used by other transports; this module owns no Android command semantics.

use serde_json::{Map, Value, json};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

pub(crate) fn run(args: &[String]) -> Result<(), String> {
    let (authority, service, _method, body) = request(args)?;
    let address = authority
        .strip_prefix('[')
        .and_then(|rest| {
            let (host, port) = rest.split_once("]:")?;
            Some(format!("[{host}]:{port}"))
        })
        .unwrap_or_else(|| authority.to_owned());
    let mut stream =
        TcpStream::connect(&address).map_err(|error| format!("HTTP connect {address}: {error}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .map_err(|error| error.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(30)))
        .map_err(|error| error.to_string())?;
    let mut path = format!("/_m/mesh/services/{service}/records");
    if let Ok(key) = std::env::var("DMESH_HTTP_API_KEY") {
        if !key.is_empty() {
            path.push_str("?apikey=");
            for byte in key.bytes() {
                if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.') {
                    path.push(byte as char);
                } else {
                    path.push_str(&format!("%{byte:02X}"));
                }
            }
        }
    }
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {authority}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|error| error.to_string())?;
    let mut response = Vec::new();
    stream
        .take(1024 * 1024 + 1)
        .read_to_end(&mut response)
        .map_err(|error| error.to_string())?;
    if response.len() > 1024 * 1024 {
        return Err("HTTP response exceeds 1 MiB".into());
    }
    let response = String::from_utf8(response).map_err(|error| error.to_string())?;
    let (headers, body) = response
        .split_once("\r\n\r\n")
        .ok_or("HTTP endpoint closed before a response; the service may still be starting")?;
    let status = headers.lines().next().ok_or("missing HTTP status")?;
    if !status.contains(" 200 ") {
        return Err(format!("{status}: {body}"));
    }
    println!("{body}");
    Ok(())
}

fn request(args: &[String]) -> Result<(&str, &str, &str, String), String> {
    let [target, method, fields @ ..] = args else {
        return Err("usage: dmesh-cli http://HOST:PORT SERVICE.METHOD [--field=value ...]".into());
    };
    let authority = target
        .strip_prefix("http://")
        .ok_or("HTTP target must use http://")?;
    if authority.is_empty() || authority.contains('/') || authority.contains('@') {
        return Err("HTTP target must be an authority without path or credentials".into());
    }
    let (service, _) = method
        .split_once('.')
        .ok_or("method must be SERVICE.METHOD")?;
    if !valid_segment(service) || !valid_segment(method) {
        return Err("invalid HTTP service method".into());
    }
    let service = if service == "radio" && method == "radio.history" {
        "history"
    } else {
        service
    };
    let mut body = Map::new();
    for field in fields {
        let field = field.strip_prefix("--").ok_or("expected --field=value")?;
        let (key, value) = field.split_once('=').ok_or("expected --field=value")?;
        if !valid_segment(key) || key == "id" {
            return Err("invalid or reserved HTTP field".into());
        }
        let value = match value {
            value if value.starts_with("text:") => Value::String(value[5..].into()),
            "true" => Value::Bool(true),
            "false" => Value::Bool(false),
            _ => value
                .parse::<u64>()
                .map(Value::from)
                .unwrap_or_else(|_| Value::String(value.into())),
        };
        body.insert(key.into(), value);
    }
    let (_, method_name) = method.split_once('.').expect("validated method");
    let record = json!({"component": method.split_once('.').unwrap().0, "method": method_name, "id": 1, "env": body});
    Ok((authority, service, method, record.to_string()))
}

fn valid_segment(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_gateway_request_is_bounded_to_a_named_service() {
        let args = [
            "http://127.0.0.1:18480",
            "transport.set",
            "--mode=6",
            "--ap=1",
        ]
        .map(str::to_owned);
        let (authority, service, method, body) = request(&args).unwrap();
        assert_eq!(
            (authority, service, method),
            ("127.0.0.1:18480", "transport", "transport.set")
        );
        assert_eq!(
            serde_json::from_str::<Value>(&body).unwrap(),
            json!({"component":"transport","method":"set","id":1,"env":{"mode":6,"ap":1}})
        );
        assert!(request(&["http://host:1".into(), "../other".into()]).is_err());
    }
}
