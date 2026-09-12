fn main() {
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR");
    let partition = std::path::Path::new("../boot/partitions.csv");
    std::fs::copy(partition, format!("{out_dir}/partitions.csv"))
        .expect("copy Main partition table");
    println!("cargo:rerun-if-changed={}", partition.display());
    println!("cargo:rerun-if-changed=sdkconfig.defaults");
    println!("cargo:rerun-if-changed=sdkconfig.esp32s3.defaults");
    println!("cargo:rerun-if-changed=sdkconfig.esp32c6.defaults");
    println!("cargo:rerun-if-changed=../ble/native/dmesh_nimble/dmesh_nimble.c");
    println!("cargo:rerun-if-changed=../ble/native/dmesh_nimble/include/dmesh_nimble.h");
    println!("cargo:rerun-if-changed=../ble/native/dmesh_nimble/CMakeLists.txt");
    println!("cargo:rerun-if-changed=../modules/native/dmesh_module_loader/dmesh_module_loader.c");
    println!("cargo:rerun-if-changed=../modules/native/dmesh_module_loader/dmesh_hw_host.c");
    println!(
        "cargo:rerun-if-changed=../modules/native/dmesh_module_loader/dmesh_module_weak_platform.c"
    );
    println!("cargo:rerun-if-changed=../modules/native/dmesh_module_loader/CMakeLists.txt");
    println!("cargo:rerun-if-changed=native/dmesh_uart_log/CMakeLists.txt");
    println!("cargo:rerun-if-changed=native/dmesh_uart_log/dmesh_uart_log.c");
    embuild::espidf::sysenv::output();
}
