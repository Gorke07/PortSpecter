fn main() {
    println!("cargo:rerun-if-changed=../../assets/icons/portspecter.ico");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let icon = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../assets/icons/portspecter.ico");
        winresource::WindowsResource::new()
            .set_icon(icon.to_str().expect("UTF-8 icon path"))
            .set("ProductName", "PortSpecter")
            .set(
                "FileDescription",
                "PortSpecter network discovery and port scanner",
            )
            .set("OriginalFilename", "portspecter.exe")
            .compile()
            .expect("Compile Windows application icon and version resources");
    }
}
