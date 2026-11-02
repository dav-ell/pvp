//! Launch the native Flutter macOS app. Rust handles call coordination.
#[cfg(target_os = "macos")]
use std::path::PathBuf;
use std::{env, error::Error, process::Command};

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = env::args().skip(1);
    let mut url = env::var("PVP_URL").unwrap_or_else(|_| "https://lopixel.space".into());
    let mut print_only = false;
    let mut web = false;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--web" => web = true,
            "--url" => {
                web = true;
                url = args.next().ok_or("--url needs an HTTPS URL")?;
            }
            "--print-url" => {
                web = true;
                print_only = true;
            }
            "--help" | "-h" => {
                println!("pvp [--web] [--url HTTPS_URL] [--print-url]\n\nOpens native PVP.app on macOS. Build with scripts/build-macos.sh.\n--web opens the optional browser client. PVP_APP overrides the app location.\nOriginal UDP client: cargo run --features legacy --bin pvp-legacy");
                return Ok(());
            }
            _ => return Err(format!("Unknown argument: {arg}").into()),
        }
    }
    if !web {
        #[cfg(target_os = "macos")]
        {
            let mut candidates: Vec<PathBuf> = env::var_os("PVP_APP")
                .map(PathBuf::from)
                .into_iter()
                .collect();
            if let Some(home) = env::var_os("HOME") {
                candidates.push(PathBuf::from(home).join("Applications/PVP.app"));
            }
            candidates.extend([
                PathBuf::from("dist/PVP-macOS-1.0.13/PVP.app"),
                PathBuf::from("dist/PVP-macOS-1.0.12/PVP.app"),
                PathBuf::from("dist/PVP-macOS-1.0.11/PVP.app"),
                PathBuf::from("/Applications/PVP.app"),
                PathBuf::from("dist/PVP-macOS-1.0.10/PVP.app"),
                PathBuf::from("dist/PVP-macOS-1.0.10/PVP.app"),
                PathBuf::from("dist/PVP-macOS-1.0.9/PVP.app"),
                PathBuf::from("dist/PVP-macOS-1.0.8/PVP.app"),
                PathBuf::from("dist/PVP-macOS-1.0.7/PVP.app"),
                PathBuf::from("dist/PVP-macOS-1.0.6/PVP.app"),
                PathBuf::from("dist/PVP-macOS-1.0.5/PVP.app"),
                PathBuf::from("dist/PVP-macOS-1.0.4/PVP.app"),
                PathBuf::from("dist/PVP-macOS-1.0.3/PVP.app"),
                PathBuf::from("dist/PVP-macOS-1.0.2/PVP.app"),
                PathBuf::from("dist/PVP-macOS-1.0.1/PVP.app"),
                PathBuf::from("dist/PVP-macOS/PVP.app"),
                PathBuf::from("desktop/build/macos/Build/Products/Release/PVP.app"),
            ]);
            let app = candidates.into_iter().find(|p| p.join("Contents/Info.plist").is_file())
                .ok_or("PVP.app is not installed. Run scripts/build-macos.sh, then open dist/PVP-macOS-1.0.13/PVP.app.")?;
            if !Command::new("open").arg(&app).status()?.success() {
                return Err("Could not open PVP.app".into());
            }
            return Ok(());
        }
        #[cfg(not(target_os = "macos"))]
        return Err(
            "The native desktop client currently supports macOS. Use --web for the browser client."
                .into(),
        );
    }
    if !(url.starts_with("https://")
        || url.starts_with("http://localhost:")
        || url.starts_with("http://127.0.0.1:"))
        || url.chars().any(char::is_control)
    {
        return Err("Use HTTPS, or a localhost HTTP URL for development".into());
    }
    println!("{url}");
    if print_only {
        return Ok(());
    }
    #[cfg(target_os = "macos")]
    let status = Command::new("open").arg(&url).status()?;
    #[cfg(target_os = "windows")]
    let status = Command::new("rundll32")
        .args(["url.dll,FileProtocolHandler", &url])
        .status()?;
    #[cfg(all(unix, not(target_os = "macos")))]
    let status = Command::new("xdg-open").arg(&url).status()?;
    if !status.success() {
        return Err("Could not open your browser; open the URL above".into());
    }
    Ok(())
}
