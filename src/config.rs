//! Common configuration utilities

use directories::ProjectDirs;
#[cfg(unix)]
use std::path::Path;
use std::{env, path::PathBuf};

/// Default configuration file path
pub fn get_default_config_path() -> Option<PathBuf> {
    // config.json in the current working directory ($PWD)
    if let Ok(mut path) = env::current_dir() {
        path.push("config.json");

        if path.exists() {
            return Some(path);
        }
    }

    // config.json in the current working directory (relative path)
    let relative_path = PathBuf::from("config.json");
    if relative_path.exists() {
        return Some(relative_path);
    }

    // System standard directories
    if let Some(project_dirs) = ProjectDirs::from("org", "shadowsocks", "shadowsocks-rust") {
        // Linux: $XDG_CONFIG_HOME/shadowsocks-rust/config.json
        //        $HOME/.config/shadowsocks-rust/config.json
        // macOS: $HOME/Library/Application Support/org.shadowsocks.shadowsocks-rust/config.json
        // Windows: {FOLDERID_RoamingAppData}/shadowsocks/shadowsocks-rust/config/config.json

        let mut config_path = project_dirs.config_dir().to_path_buf();
        config_path.push("config.json");

        if config_path.exists() {
            return Some(config_path);
        }
    }

    // UNIX systems, XDG Base Directory
    // https://specifications.freedesktop.org/basedir-spec/basedir-spec-latest.html
    #[cfg(unix)]
    if let Ok(base_directories) = xdg::BaseDirectories::with_prefix("shadowsocks-rust") {
        // $XDG_CONFIG_HOME/shadowsocks-rust/config.json
        // for dir in $XDG_CONFIG_DIRS; $dir/shadowsocks-rust/config.json
        if let Some(config_path) = base_directories.find_config_file("config.json") {
            return Some(config_path);
        }
    }

    // UNIX global configuration file
    #[cfg(unix)]
    {
        let global_config_path = Path::new("/etc/shadowsocks-rust/config.json");
        if global_config_path.exists() {
            return Some(global_config_path.to_path_buf());
        }
    }

    None
}
