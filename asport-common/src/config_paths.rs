use std::path::PathBuf;

/// Supported extensions for configuration files.
pub const CONFIG_EXTENSIONS: [&str; 6] = ["json", "jsonc", "ron", "toml", "yaml", "yml"];

/// Return ordered candidate file names for a given endpoint (e.g. "client" or "server").
pub fn config_filenames(prefix: &str) -> Vec<String> {
    CONFIG_EXTENSIONS
        .iter()
        .map(|ext| format!("{prefix}.{ext}"))
        .collect()
}

/// Attempt to locate a configuration file for the provided prefix.
pub fn find_config(prefix: &str) -> Option<PathBuf> {
    let names = config_filenames(prefix);

    if let Some(path) = find_in_working_dir(&names) {
        return Some(path);
    }

    #[cfg(unix)]
    {
        if let Some(path) = find_in_xdg(&names) {
            return Some(path);
        }
    }

    None
}

fn find_in_working_dir(names: &[String]) -> Option<PathBuf> {
    for name in names {
        let candidate = PathBuf::from(name);
        if candidate.exists() {
            return Some(candidate);
        }
    }

    None
}

#[cfg(unix)]
fn find_in_xdg(names: &[String]) -> Option<PathBuf> {
    let xdg_dirs = xdg::BaseDirectories::with_prefix("asport");

    for name in names {
        if let Some(path) = xdg_dirs.find_config_file(name) {
            return Some(path);
        }
    }

    None
}
