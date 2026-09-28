use std::path::Path;

use anyhow::{Context, Result, bail};
use mesh_api_gen::{
    api_markdown_from_tools_json_for_component, java::java_api, json_schema, merge_tools_json,
    parse_api_markdown, parse_required_path, rust_api, rust_ids, tools_json,
};

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let mut api = None;
    let mut tools = None;
    let mut out_api = None;
    let mut out_tools = None;
    let mut out_schema = None;
    let mut out_ids = None;
    let mut out_rust = None;
    let mut out_java = None;
    let mut java_package = None;
    let mut base_tools = None;
    let mut component = None;
    let mut check = false;
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--api" => api = Some(args.next().context("--api requires a path")?),
            "--tools" => tools = Some(args.next().context("--tools requires a path")?),
            "--out-api" => out_api = Some(args.next().context("--out-api requires a path")?),
            "--out-tools" => out_tools = Some(args.next().context("--out-tools requires a path")?),
            "--out-schema" => {
                out_schema = Some(args.next().context("--out-schema requires a path")?)
            }
            "--out-ids" => out_ids = Some(args.next().context("--out-ids requires a path")?),
            "--out-rust" => out_rust = Some(args.next().context("--out-rust requires a path")?),
            "--out-java" => out_java = Some(args.next().context("--out-java requires a path")?),
            "--java-package" => {
                java_package = Some(args.next().context("--java-package requires a name")?)
            }
            "--base-tools" => {
                base_tools = Some(args.next().context("--base-tools requires a path")?)
            }
            "--component" => component = Some(args.next().context("--component requires a name")?),
            "--check" => check = true,
            "--help" | "-h" => {
                println!(
                    "mesh-api-gen --api API.md [--base-tools tools.json] --out-tools tools.json --out-schema schema.json --out-ids ids.rs --out-rust src/api.rs [--java-package p] --out-java MeshApi.java [--check]\nmesh-api-gen --tools tools.json --component service --out-api migration.md"
                );
                return Ok(());
            }
            _ => bail!("unknown argument {argument}"),
        }
    }

    if let Some(tools) = tools {
        let generated = api_markdown_from_tools_json_for_component(
            &serde_json::from_str(&std::fs::read_to_string(tools)?)?,
            component.as_deref(),
        )?;
        write_or_check(
            &parse_required_path(out_api, "--out-api")?,
            &generated,
            check,
        )?;
        return Ok(());
    }
    let api = parse_required_path(api, "--api")?;
    let methods = parse_api_markdown(&std::fs::read_to_string(&api)?)?;
    if let Some(path) = out_tools {
        let generated = if let Some(base_tools) = base_tools {
            merge_tools_json(
                &serde_json::from_str(&std::fs::read_to_string(base_tools)?)?,
                &methods,
            )?
        } else {
            tools_json(&methods)
        };
        write_or_check(
            &path,
            &format!("{}\n", serde_json::to_string_pretty(&generated)?),
            check,
        )?;
    }
    if let Some(path) = out_schema {
        write_or_check(
            &path,
            &format!(
                "{}\n",
                serde_json::to_string_pretty(&json_schema(&methods))?
            ),
            check,
        )?;
    }
    if let Some(path) = out_ids {
        write_or_check(&path, &rust_ids(&methods), check)?;
    }
    if let Some(path) = out_rust {
        write_or_check(&path, &rust_api(&methods), check)?;
    }
    if let Some(path) = out_java {
        let class_name = java_class_name(&path)?;
        write_or_check(
            &path,
            &java_api(&methods, java_package.as_deref(), &class_name),
            check,
        )?;
    }
    Ok(())
}

/// Derive the generated Java class name from the output file stem, so the
/// class follows the artifact file the way generated Rust does.
fn java_class_name(path: &str) -> Result<String> {
    let stem = Path::new(path)
        .file_stem()
        .and_then(|stem| stem.to_str())
        .context("--out-java requires a file name")?;
    let class: String = stem
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|part| !part.is_empty())
        .map(|part| {
            let mut characters = part.chars();
            match characters.next() {
                Some(first) => format!("{}{}", first.to_ascii_uppercase(), characters.as_str()),
                None => String::new(),
            }
        })
        .collect();
    if class.is_empty() {
        bail!("--out-java file stem {stem:?} has no usable class name");
    }
    Ok(class)
}

fn write_or_check(path: &str, contents: &str, check: bool) -> Result<()> {
    if check {
        let current = std::fs::read_to_string(path)
            .with_context(|| format!("read generated artifact {path}"))?;
        if current != contents {
            bail!("generated artifact is stale: {path}");
        }
        return Ok(());
    }
    if let Some(parent) = Path::new(path).parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, contents).with_context(|| format!("write generated artifact {path}"))
}
