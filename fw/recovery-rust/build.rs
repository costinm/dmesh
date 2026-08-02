fn main() {
    println!("cargo:rerun-if-changed=sdkconfig.defaults");
    println!("cargo:rerun-if-changed=../boot/partitions.csv");
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR");
    std::fs::copy("../boot/partitions.csv", format!("{out_dir}/partitions.csv"))
        .expect("copy canonical partition table");
    embuild::espidf::sysenv::output();
}
