fn main() {
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR");
    let partition = std::path::Path::new("../boot/partitions.csv");
    std::fs::copy(partition, format!("{out_dir}/partitions.csv"))
        .expect("copy Main partition table");
    println!("cargo:rerun-if-changed={}", partition.display());
    println!("cargo:rerun-if-changed=sdkconfig.defaults");
    println!("cargo:rerun-if-changed=sdkconfig.esp32s3.defaults");
    println!("cargo:rerun-if-changed=sdkconfig.esp32c6.defaults");
    println!("cargo:rerun-if-changed=../modules/native/dmesh_module_loader/CMakeLists.txt");
    embuild::espidf::sysenv::output();
}
