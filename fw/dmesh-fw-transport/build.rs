fn main() {
    // A physical UART rate is a firmware image property: host and device must
    // be switched together.  Keep the accepted set explicit so a typo cannot
    // produce a silently unusable console image.
    println!("cargo:rerun-if-env-changed=DMESH_UART_BAUD");
    let baud = std::env::var("DMESH_UART_BAUD").unwrap_or_else(|_| "115200".to_owned());
    let numeric = match baud.as_str() {
        "115200" => 115_200,
        "230400" => 230_400,
        "460800" => 460_800,
        "921600" => 921_600,
        _ => panic!("DMESH_UART_BAUD must be one of 115200, 230400, 460800, or 921600; got {baud}"),
    };
    println!("cargo:rustc-env=DMESH_UART_BAUD={baud}");
    let output = std::path::Path::new(&std::env::var("OUT_DIR").expect("OUT_DIR"))
        .join("physical_uart_baud.rs");
    std::fs::write(
        output,
        format!("pub const PHYSICAL_UART_BAUD: i32 = {numeric};\n"),
    )
    .expect("write physical UART baud constant");
}
