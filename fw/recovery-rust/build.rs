fn main() {
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR");
    let partition = std::path::Path::new("../boot/partitions.csv");
    std::fs::copy(partition, format!("{out_dir}/partitions.csv"))
        .expect("copy Recovery partition table");
    println!("cargo:rerun-if-changed={}", partition.display());
    println!("cargo:rerun-if-changed=sdkconfig.defaults");
    println!("cargo:rerun-if-changed=../modules/native/dmesh_module_loader/dmesh_module_loader.c");
    println!("cargo:rerun-if-changed=../modules/native/dmesh_module_loader/dmesh_hw_host.c");
    println!("cargo:rerun-if-changed=../modules/native/dmesh_module_loader/dmesh_module_weak_platform.c");
    println!("cargo:rerun-if-changed=../modules/native/dmesh_module_loader/CMakeLists.txt");
    embuild::espidf::sysenv::output();
}
