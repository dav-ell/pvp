use std::env;
use std::path::PathBuf;
// Removed: use std::fs; (unused)

fn main() {
    // Rerun build if build.rs changes
    println!("cargo:rerun-if-changed=build.rs");

    // --- OpenCV Configuration ---
    // Use cargo:rustc-env to pass variables to dependency build scripts

    // Use dynamic linking for macOS Homebrew compatibility (static libs not available by default)
    println!("cargo:rustc-env=OPENCV_STATIC=0");

    // Specify OpenCV libraries for the opencv crate's build script
    let opencv_libs = "opencv_core,opencv_imgproc,opencv_highgui,opencv_videoio,opencv_imgcodecs";
    println!("cargo:rustc-env=OPENCV_LINK_LIBS={}", opencv_libs);

    // Try to use pkg-config to find OpenCV
    let pkg_config_result = pkg_config::Config::new()
        .probe("opencv4");

    let (opencv_include_path, opencv_lib_path) = match pkg_config_result {
        Ok(lib) => {
            // Use paths from pkg-config
            let include_paths = lib
                .include_paths
                .iter()
                .map(|p| p.to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join(":");
            let lib_paths = lib
                .link_paths
                .iter()
                .map(|p| p.to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join(":");
            println!("cargo:warning=pkg-config found OpenCV: include_paths={}, lib_paths={}", include_paths, lib_paths);

            // Validate that required libraries exist (skip on macOS for dynamic linking)
            let target_os = env::var("CARGO_CFG_TARGET_OS").expect("CARGO_CFG_TARGET_OS not set");
            if target_os != "macos" {
                let lib_path = lib.link_paths.iter().next()
                    .expect("pkg-config returned no link paths")
                    .to_string_lossy()
                    .into_owned();
                for lib in opencv_libs.split(',') {
                    let lib_name = format!("lib{}.a", lib); // Static library
                    let lib_file = PathBuf::from(&lib_path).join(&lib_name);
                    if !lib_file.exists() {
                        panic!("Static library {} not found at {}. Ensure OpenCV is built with static libraries.", lib_name, lib_file.display());
                    }
                }

                // Validate additional static libraries (skip on macOS)
                let additional_libs = ["z", "png", "jpeg", "tiff", "webp", "openjp2", "tbb"];
                for lib in additional_libs.iter() {
                    let lib_name = format!("lib{}.a", lib);
                    let lib_file = PathBuf::from(&lib_path).join(&lib_name);
                    if !lib_file.exists() {
                        panic!("Static library {} not found at {}. Ensure dependency is built and installed.", lib_name, lib_file.display());
                    }
                }
            }

            (include_paths, lib_paths)
        }
        Err(e) => {
            println!("cargo:warning=pkg-config failed for opencv4: {}. Falling back to environment variables.", e);
            // Fall back to environment variables or defaults
            let include_path = env::var("OPENCV_INCLUDE_PATHS")
                .unwrap_or_else(|_| "/usr/local/opencv/include/opencv4".to_string());
            let lib_path = env::var("OPENCV_LINK_PATHS")
                .unwrap_or_else(|_| "/usr/local/opencv/lib".to_string());
            (include_path, lib_path)
        }
    };

    println!("cargo:rustc-env=OPENCV_INCLUDE_PATHS={}", &opencv_include_path);
    println!("cargo:rustc-env=OPENCV_LINK_PATHS={}", &opencv_lib_path);

    // --- Linker Configuration (for rustc) ---
    // Add the library path for the final linker stage
    println!("cargo:rustc-link-search=native={}", opencv_lib_path);

    // Add Homebrew's main lib path on macOS for dependencies like zlib
    let target_os = env::var("CARGO_CFG_TARGET_OS").expect("CARGO_CFG_TARGET_OS not set");
    if target_os == "macos" {
        println!("cargo:rustc-link-search=native=/opt/homebrew/lib");
        println!("cargo:rustc-link-search=native=/opt/homebrew/opt/zlib/lib");
    }

    // Link additional required libraries (dynamic on macOS, static otherwise)
    let additional_libs = ["z", "png", "jpeg", "tiff", "webp", "openjp2", "tbb"];
    for lib in additional_libs.iter() {
        if target_os == "macos" {
            println!("cargo:rustc-link-lib={}", lib); // Dynamic on macOS
        } else {
            println!("cargo:rustc-link-lib=static={}", lib); // Static on other platforms
        }
    }

    // --- Platform-specific linker configuration ---
    let target_env = env::var("CARGO_CFG_TARGET_ENV").expect("CARGO_CFG_TARGET_ENV not set");

    if target_os == "macos" {
        // On macOS, the C++ standard library is libc++, not libstdc++. Link it statically.
        println!("cargo:rustc-link-lib=static=c++");

        // Additionally, link against the system frameworks that provide GUI and media services.
        // Frameworks themselves are not statically linked, but we must instruct the linker to use them.
        let frameworks = [
            "AVFoundation", "CoreMedia", "CoreVideo", "CoreGraphics", "CoreFoundation",
            "Foundation", "AppKit", "QuartzCore", "Security"
        ];
        for framework in frameworks.iter() {
            println!("cargo:rustc-link-lib=framework={}", framework);
        }
    } else if target_os == "linux" {
        // Link standard C++ (libstdc++) and C (libgcc) libraries statically.
        println!("cargo:rustc-link-lib=static=stdc++");
        println!("cargo:rustc-link-lib=static=gcc");
        if target_env == "musl" {
            // For musl, pass the -static flag to the linker to create a fully static executable.
            println!("cargo:rustc-link-arg=-static");
        }
        // Statically link libstdc++ for gnu targets as well.
        println!("cargo:rustc-link-arg=-static-libstdc++");
    } else if target_os == "windows" {
        // Use the static multithreaded runtime library on Windows.
        println!("cargo:rustc-link-arg=/MT");
    }

    // --- Diagnostics ---
    println!("=== Build Script (pvp) Configuration for Target ===");
    println!("Target OS: {}", target_os);
    println!("Target Env: {}", target_env);
    println!("Setting for opencv crate -> OPENCV_STATIC=0 (dynamic for Homebrew compatibility)");
    println!("Setting for opencv crate -> OPENCV_LINK_LIBS={}", opencv_libs);
    println!("Setting for opencv crate -> OPENCV_INCLUDE_PATHS={}", &opencv_include_path);
    println!("Setting for opencv crate -> OPENCV_LINK_PATHS={}", &opencv_lib_path);
    println!("Setting for rustc linker -> Search Path: native={}", opencv_lib_path);
    if target_os == "macos" {
        println!("Setting for rustc linker -> Additional Search Path: native=/opt/homebrew/lib");
    }
    println!("Setting for rustc linker -> Link (dynamic on macOS): {}", additional_libs.join(","));
    println!("=================================================");
}