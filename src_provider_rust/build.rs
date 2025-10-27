// Build script for linking OpenSSL and setting up Windows-specific build configuration

fn main() {
    // Print build information
    println!("cargo:rerun-if-changed=build.rs");
    
    // Platform-specific configurations
    #[cfg(target_os = "windows")]
    {
        // Windows-specific build settings
        println!("cargo:rustc-link-lib=dylib=user32");
        println!("cargo:rustc-link-lib=dylib=advapi32");
    }
    
    // OpenSSL linking is handled by openssl-sys crate
    // but we can add custom configurations here if needed
}
