use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    if env::var_os("CARGO_FEATURE_LEGACY").is_none() {
        return;
    }

    let target_os = env::var("CARGO_CFG_TARGET_OS").expect("CARGO_CFG_TARGET_OS not set");
    let target_env = env::var("CARGO_CFG_TARGET_ENV").expect("CARGO_CFG_TARGET_ENV not set");

    // Dynamic OpenCV on macOS (Homebrew) and Windows (mingw DLLs); static preferred on Linux.
    let prefer_static = target_os == "linux";
    println!(
        "cargo:rustc-env=OPENCV_STATIC={}",
        if prefer_static { "1" } else { "0" }
    );

    // Windows MinGW OpenCV packages use versioned sonames (e.g. opencv_core470).
    let opencv_libs = if target_os == "windows" {
        env::var("OPENCV_LINK_LIBS").unwrap_or_else(|_| {
            "opencv_core470,opencv_imgproc470,opencv_highgui470,opencv_videoio470,opencv_imgcodecs470"
                .to_string()
        })
    } else {
        env::var("OPENCV_LINK_LIBS").unwrap_or_else(|_| {
            "opencv_core,opencv_imgproc,opencv_highgui,opencv_videoio,opencv_imgcodecs".to_string()
        })
    };
    println!("cargo:rustc-env=OPENCV_LINK_LIBS={}", opencv_libs);

    // Prefer env (cross builds), then pkg-config.
    let (opencv_include_path, opencv_lib_path) =
        if let (Ok(inc), Ok(lib)) = (
            env::var("OPENCV_INCLUDE_PATHS"),
            env::var("OPENCV_LINK_PATHS"),
        ) {
            println!("cargo:warning=Using OPENCV_* env paths");
            (inc, lib)
        } else {
            match pkg_config::Config::new().probe("opencv4") {
                Ok(lib) => {
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
                    println!(
                        "cargo:warning=pkg-config found OpenCV: include_paths={}, lib_paths={}",
                        include_paths, lib_paths
                    );

                    // Validate static libs only for non-macOS, non-Windows (musl/static linux recipe).
                    if target_os != "macos" && target_os != "windows" && prefer_static {
                        let lib_path = lib
                            .link_paths
                            .first()
                            .expect("pkg-config returned no link paths")
                            .to_string_lossy()
                            .into_owned();
                        for lib_name in opencv_libs.split(',') {
                            let file = PathBuf::from(&lib_path).join(format!("lib{}.a", lib_name));
                            if !file.exists() {
                                panic!(
                                    "Static library {} not found at {}. Ensure OpenCV is built with static libraries.",
                                    file.file_name().unwrap().to_string_lossy(),
                                    file.display()
                                );
                            }
                        }
                    }

                    (include_paths, lib_paths)
                }
                Err(e) => {
                    println!(
                        "cargo:warning=pkg-config failed for opencv4: {}. Using defaults.",
                        e
                    );
                    let include_path = env::var("OPENCV_INCLUDE_PATHS")
                        .unwrap_or_else(|_| "/usr/local/opencv/include/opencv4".to_string());
                    let lib_path = env::var("OPENCV_LINK_PATHS")
                        .unwrap_or_else(|_| "/usr/local/opencv/lib".to_string());
                    (include_path, lib_path)
                }
            }
        };

    // opencv crate reads these via cargo:rustc-env from its build script parent...
    // The opencv crate's build uses OPENCV_* environment variables; set both env-style and rustc-env.
    println!("cargo:rustc-env=OPENCV_INCLUDE_PATHS={}", opencv_include_path);
    println!("cargo:rustc-env=OPENCV_LINK_PATHS={}", opencv_lib_path);

    // Also re-export as cargo instructions for dependent build scripts when possible.
    // (opencv 0.94 primarily reads process env; Docker build script sets real env.)

    for path in opencv_lib_path.split(':').filter(|s| !s.is_empty()) {
        println!("cargo:rustc-link-search=native={}", path);
    }

    if target_os == "macos" {
        println!("cargo:rustc-link-search=native=/opt/homebrew/lib");
        println!("cargo:rustc-link-search=native=/opt/homebrew/opt/zlib/lib");
    }

    // Extra image/codec libs. Windows MinGW OpenCV already pulls its deps via
    // import libs; forcing -ltbb etc. fails when those packages are absent.
    if target_os == "macos" {
        for lib in ["z", "png", "jpeg", "tiff", "webp", "openjp2", "tbb"].iter() {
            println!("cargo:rustc-link-lib={}", lib);
        }
    } else if target_os == "linux" {
        for lib in ["z", "png", "jpeg", "tiff", "webp", "openjp2", "tbb"].iter() {
            println!("cargo:rustc-link-lib=static={}", lib);
        }
    }
    // windows: do not force extra -l flags; opencv_*.dll.a + mingw runtime suffice

    if target_os == "macos" {
        println!("cargo:rustc-link-lib=static=c++");
        let frameworks = [
            "AVFoundation",
            "CoreMedia",
            "CoreVideo",
            "CoreGraphics",
            "CoreFoundation",
            "Foundation",
            "AppKit",
            "QuartzCore",
            "Security",
        ];
        for framework in frameworks.iter() {
            println!("cargo:rustc-link-lib=framework={}", framework);
        }
    } else if target_os == "linux" {
        println!("cargo:rustc-link-lib=static=stdc++");
        println!("cargo:rustc-link-lib=static=gcc");
        if target_env == "musl" {
            println!("cargo:rustc-link-arg=-static");
        }
        println!("cargo:rustc-link-arg=-static-libstdc++");
    } else if target_os == "windows" {
        // MinGW: link libstdc++ dynamically with the DLL we ship; MSVC /MT is wrong for gnu.
        if target_env == "gnu" {
            println!("cargo:rustc-link-lib=stdc++");
            println!("cargo:rustc-link-lib=pthread");
        } else if target_env == "msvc" {
            println!("cargo:rustc-link-arg=/MT");
        }
    }

    println!("=== Build Script (pvp) Configuration for Target ===");
    println!("Target OS: {}", target_os);
    println!("Target Env: {}", target_env);
    println!("OPENCV_LINK_LIBS={}", opencv_libs);
    println!("OPENCV_INCLUDE_PATHS={}", opencv_include_path);
    println!("OPENCV_LINK_PATHS={}", opencv_lib_path);
    println!("=================================================");
}
