//! Settings, resolved from defaults, a TOML file, and the environment.
//! Ported from `src/slap/config.py`.
//!
//! The same config.toml serves both apps while they coexist, so the read
//! side matches Python's behaviour exactly, quirks included: unknown keys
//! in `[collector]` and `[discovery]` are errors (Python's
//! `dataclasses.replace` raised on them), while unknown keys in
//! `[lighthouse]` are ignored (Python checked `hasattr` first). Freezing
//! the quirk beats changing which files load between one app and the other.
//!
//! The write side is the same surgical editor: config.toml is user-owned,
//! may carry comments and hand-tuned settings, and there is no TOML writer
//! that preserves them, so `save_setting` touches the one line it is about
//! and proves the result parses back before replacing the file.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::paths;

fn expand_user(path: PathBuf) -> PathBuf {
    if let Ok(stripped) = path.strip_prefix("~") {
        if let Some(home) = dirs::home_dir() {
            return home.join(stripped);
        }
    }
    path
}

/// The writable vulnerability-database copy, in the per-user data directory.
///
/// The Python app prefers the NEWER of this and the bundle's copy; the
/// bundled path needs the Tauri resource dir, which only the shell knows,
/// so the newer-of choice lands there when the vulndb module ports.
pub fn user_vulndb_path() -> PathBuf {
    paths::default_data_dir().join("vulndb.json")
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct CollectorConfig {
    pub timeout: f64,
    pub user_agent: String,
    pub max_redirects: u32,
    pub max_body_bytes: u64,
    pub crux_api_key: Option<String>,
    pub crux_rate_per_second: f64,
    pub verify_tls: bool,
    pub http_concurrency: u32,
}

impl Default for CollectorConfig {
    fn default() -> Self {
        Self {
            timeout: 20.0,
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
                         (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 SLAP/0.1"
                .to_string(),
            max_redirects: 10,
            max_body_bytes: 4_000_000,
            crux_api_key: None,
            crux_rate_per_second: 2.0,
            verify_tls: true,
            http_concurrency: 20,
        }
    }
}

/// Lighthouse settings. `concurrency` is NOT `http_concurrency`: contended
/// CPU inflates TBT and TTI, producing plausible, irreproducible scores.
/// The UI hard-caps it at 4; the default stays 3.
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(default)]
pub struct LighthouseConfig {
    /// Off by default. Phase 1 batches take seconds per site; enabling
    /// this takes them to roughly 90 seconds per site.
    pub enabled: bool,
    pub runs: u32,
    pub form_factors: Vec<String>,
    pub categories: Vec<String>,
    pub concurrency: u32,
    pub timeout: f64,
    pub node_path: String,
    pub worker_path: Option<PathBuf>,
    pub chrome_path: Option<String>,
    pub keep_artifacts: bool,
}

impl Default for LighthouseConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            runs: 3,
            form_factors: vec!["mobile".to_string()],
            categories: vec![
                "performance".to_string(),
                "accessibility".to_string(),
                "best-practices".to_string(),
                "seo".to_string(),
            ],
            concurrency: 3,
            timeout: 150.0,
            node_path: "node".to_string(),
            worker_path: None,
            chrome_path: None,
            keep_artifacts: true,
        }
    }
}

/// How many pages of a site to find, and how many to measure.
/// `page_concurrency` is separate from `http_concurrency` for the reason
/// the Lighthouse cap is separate: multiplying two unbounded fan-outs
/// together is how a batch ends up with hundreds of requests in flight.
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct DiscoveryConfig {
    pub enabled: bool,
    /// Pages audited per site, including the home page. The cap that bites
    /// on a large site, and the one the report must disclose when it does.
    pub pages_per_site: u32,
    /// Pages given the browser audit. At ~90s per page against a hard
    /// concurrency cap of 3, this decides whether a 24-site batch takes 48
    /// minutes or two hours.
    pub lighthouse_pages_per_site: u32,
    pub page_concurrency: u32,
    pub crawl_depth: u32,
    pub allow_crawl: bool,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            pages_per_site: 20,
            lighthouse_pages_per_site: 5,
            page_concurrency: 5,
            crawl_depth: 2,
            allow_crawl: true,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Settings {
    pub db_path: PathBuf,
    pub artifact_dir: PathBuf,
    pub report_dir: PathBuf,
    pub rules_path: Option<PathBuf>,
    pub collector: CollectorConfig,
    pub lighthouse: LighthouseConfig,
    pub discovery: DiscoveryConfig,
    pub vulndb_path: PathBuf,
    /// Endpoint probing. Off by default and authorised per host, never
    /// globally: a global flag gets switched on once and then silently
    /// applies to the next client, who never agreed to it.
    pub probe_enabled: bool,
    pub probe_rate_per_second: f64,
    /// Report branding. Deliberately a plain map so a settings page and a
    /// TOML file can both populate it without a schema change.
    pub branding: BTreeMap<String, toml::Value>,
    /// Where these settings were loaded from, and therefore where a
    /// settings page must write. Recorded whether or not the file exists.
    pub config_path: Option<PathBuf>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            db_path: paths::db_path(),
            artifact_dir: paths::default_data_dir().join("artifacts"),
            report_dir: paths::default_data_dir().join("reports"),
            rules_path: None,
            collector: CollectorConfig::default(),
            lighthouse: LighthouseConfig::default(),
            discovery: DiscoveryConfig::default(),
            vulndb_path: user_vulndb_path(),
            probe_enabled: false,
            probe_rate_per_second: 2.0,
            branding: BTreeMap::new(),
            config_path: None,
        }
    }
}

#[derive(Debug)]
pub struct SettingsError(pub String);

impl std::fmt::Display for SettingsError {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.write_str(&self.0)
    }
}
impl std::error::Error for SettingsError {}

impl Settings {
    pub fn load(config_path: Option<&Path>) -> Result<Self, SettingsError> {
        let mut settings = Settings::default();

        let path = config_path
            .map(Path::to_path_buf)
            .unwrap_or_else(|| paths::default_data_dir().join("config.toml"));
        settings.config_path = Some(path.clone());

        if path.is_file() {
            let text = std::fs::read_to_string(&path).map_err(|error| {
                SettingsError(format!("cannot read {}: {error}", path.display()))
            })?;
            let raw: toml::Table = text.parse().map_err(|error| {
                SettingsError(format!("{} is not valid TOML: {error}", path.display()))
            })?;

            let path_of = |key: &str| -> Option<PathBuf> {
                raw.get(key)
                    .and_then(|value| value.as_str())
                    .map(|value| expand_user(PathBuf::from(value)))
            };
            if let Some(value) = path_of("db_path") {
                settings.db_path = value;
            }
            if let Some(value) = path_of("artifact_dir") {
                settings.artifact_dir = value;
            }
            if let Some(value) = path_of("report_dir") {
                settings.report_dir = value;
            }
            if let Some(value) = path_of("vulndb_path") {
                settings.vulndb_path = value;
            }
            if let Some(value) = path_of("rules_path") {
                settings.rules_path = Some(value);
            }

            // Sections. collector and discovery are strict (unknown keys
            // error, as dataclasses.replace did); lighthouse ignores
            // unknown keys (Python checked hasattr first).
            if let Some(section) = raw.get("collector") {
                settings.collector = section
                    .clone()
                    .try_into()
                    .map_err(|error| SettingsError(format!("[collector]: {error}")))?;
            }
            if let Some(section) = raw.get("discovery") {
                settings.discovery = section
                    .clone()
                    .try_into()
                    .map_err(|error| SettingsError(format!("[discovery]: {error}")))?;
            }
            if let Some(section) = raw.get("lighthouse") {
                settings.lighthouse = section
                    .clone()
                    .try_into()
                    .map_err(|error| SettingsError(format!("[lighthouse]: {error}")))?;
            }
            if let Some(toml::Value::Table(branding)) = raw.get("branding") {
                settings.branding = branding.clone().into_iter().collect();
            }
            if let Some(toml::Value::Boolean(enabled)) = raw.get("probe_enabled") {
                settings.probe_enabled = *enabled;
            }
            match raw.get("probe_rate_per_second") {
                Some(toml::Value::Float(rate)) => settings.probe_rate_per_second = *rate,
                Some(toml::Value::Integer(rate)) => settings.probe_rate_per_second = *rate as f64,
                _ => {}
            }
        }

        // Environment wins, so a teammate can point at their own key
        // without editing a shared config file.
        if let Ok(key) = std::env::var("CRUX_API_KEY") {
            if !key.is_empty() {
                settings.collector.crux_api_key = Some(key);
            }
        }
        // SALP_DB still works; see paths::db_path for why.
        if let Some(env_db) = std::env::var_os("SLAP_DB").or_else(|| std::env::var_os("SALP_DB")) {
            settings.db_path = expand_user(PathBuf::from(env_db));
        }

        Ok(settings)
    }

    pub fn ensure_dirs(&self) -> std::io::Result<()> {
        if let Some(parent) = self.db_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::create_dir_all(&self.artifact_dir)?;
        std::fs::create_dir_all(&self.report_dir)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Writing one setting back.
// ---------------------------------------------------------------------------

/// The value shapes `save_setting` accepts, rendered exactly as the Python
/// `_render` did (bools lowercase, numbers via their natural display,
/// strings quoted).
#[derive(Clone, Debug, PartialEq)]
pub enum SettingValue {
    Str(String),
    Bool(bool),
    Int(i64),
    Float(f64),
}

impl SettingValue {
    fn render(&self) -> String {
        match self {
            SettingValue::Bool(b) => (if *b { "true" } else { "false" }).to_string(),
            SettingValue::Int(int) => int.to_string(),
            SettingValue::Float(float) => {
                // Python str(2.0) == "2.0"; TOML needs the point anyway to
                // keep the value a float on read-back.
                if float.fract() == 0.0 && float.is_finite() {
                    format!("{float:.1}")
                } else {
                    format!("{float}")
                }
            }
            SettingValue::Str(text) => format!("\"{text}\""),
        }
    }

    fn matches(&self, parsed: &toml::Value) -> bool {
        match (self, parsed) {
            (SettingValue::Bool(b), toml::Value::Boolean(p)) => b == p,
            (SettingValue::Int(int), toml::Value::Integer(p)) => int == p,
            (SettingValue::Float(float), toml::Value::Float(p)) => float == p,
            (SettingValue::Str(text), toml::Value::String(p)) => text == p,
            _ => false,
        }
    }
}

fn is_section_header(line: &str) -> bool {
    let trimmed = line.trim();
    trimmed.len() >= 2 && trimmed.starts_with('[') && trimmed.ends_with(']')
}

fn line_sets_key(line: &str, key: &str) -> bool {
    let trimmed = line.trim_start();
    match trimmed.strip_prefix(key) {
        Some(rest) => rest.trim_start().starts_with('='),
        None => false,
    }
}

/// Persist (or remove, with `value: None`) one setting in config.toml.
/// Returns the path written.
///
/// A surgical text edit, not a parse-and-rewrite: config.toml is
/// user-owned and may carry comments and formatting the user chose.
/// `section: None` means a top-level key, and that case carries the trap:
/// in TOML a bare key written after `[collector]` belongs to *collector*,
/// so a top-level setting goes in the region above the first section
/// header, the only place it means what it says.
///
/// The result is parsed BEFORE it replaces the original, and a result that
/// does not parse, or does not read back as the value it was asked to
/// write, errors with the original file untouched. An editor that can
/// corrupt a config file is worse than no editor.
pub fn save_setting(
    key: &str,
    value: Option<SettingValue>,
    section: Option<&str>,
    path: Option<&Path>,
) -> Result<PathBuf, SettingsError> {
    let path = path
        .map(Path::to_path_buf)
        .unwrap_or_else(|| paths::default_data_dir().join("config.toml"));
    let original =
        if path.is_file() {
            Some(std::fs::read_to_string(&path).map_err(|error| {
                SettingsError(format!("cannot read {}: {error}", path.display()))
            })?)
        } else {
            None
        };
    let mut lines: Vec<String> = original
        .as_deref()
        .unwrap_or("")
        .lines()
        .map(str::to_string)
        .collect();

    let header = section.map(|name| format!("[{name}]"));

    // Walk once, tracking which section each line is in, and record both
    // the existing entry (if any) and where a new one would have to go.
    let mut current: Option<String> = None;
    let mut key_line: Option<usize> = None;
    let mut insert_at: Option<usize> = None;
    for (index, line) in lines.iter().enumerate() {
        if is_section_header(line) {
            if current.is_none() && section.is_none() && insert_at.is_none() {
                insert_at = Some(index); // end of the top-level region
            }
            current = Some(line.trim().to_string());
            if current.as_deref() == header.as_deref() {
                insert_at = Some(index + 1);
            }
            continue;
        }
        if current.as_deref() == header.as_deref() && line_sets_key(line, key) {
            key_line = Some(index);
        }
    }
    let insert_at = insert_at.unwrap_or(lines.len());

    let entry = value.as_ref().map(|v| format!("{key} = {}", v.render()));
    match (key_line, entry) {
        (Some(index), None) => {
            lines.remove(index);
        }
        (Some(index), Some(entry)) => {
            lines[index] = entry;
        }
        (None, Some(entry)) => {
            if let Some(header) = &header {
                let present = lines.iter().any(|line| line.trim() == header);
                if !present {
                    if lines.last().is_some_and(|line| !line.trim().is_empty()) {
                        lines.push(String::new());
                    }
                    lines.push(header.clone());
                    lines.push(entry);
                } else {
                    lines.insert(insert_at, entry);
                }
            } else {
                lines.insert(insert_at, entry);
            }
        }
        (None, None) => {
            // Removing something that is not there: nothing to do, and
            // creating an empty file to say so would be noise.
            return Ok(path);
        }
    }

    if original.is_none() {
        lines.insert(
            0,
            "# SLAP configuration. Read at startup; the settings page edits it in place."
                .to_string(),
        );
    }

    let text = lines.join("\n") + "\n";
    let parsed: toml::Table = text
        .parse()
        .map_err(|error| SettingsError(format!("the edited config does not parse: {error}")))?;
    let scope: Option<&toml::Value> = match section {
        None => parsed.get(key),
        Some(name) => parsed
            .get(name)
            .and_then(|table| table.as_table())
            .and_then(|table| table.get(key)),
    };
    let reads_back = match (&value, scope) {
        (None, None) => true,
        (Some(wanted), Some(parsed_value)) => wanted.matches(parsed_value),
        _ => false,
    };
    if !reads_back {
        return Err(SettingsError(
            "the edited config did not read back correctly; nothing was saved".to_string(),
        ));
    }

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| {
            SettingsError(format!("cannot create {}: {error}", parent.display()))
        })?;
    }
    let scratch = path.with_file_name(format!(
        "{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("config.toml")
    ));
    std::fs::write(&scratch, &text)
        .map_err(|error| SettingsError(format!("cannot write {}: {error}", scratch.display())))?;
    std::fs::rename(&scratch, &path)
        .map_err(|error| SettingsError(format!("cannot replace {}: {error}", path.display())))?;
    Ok(path)
}

/// Persist (or clear) the CrUX API key. The key is validated against the
/// shape API keys actually have, because the failure mode of writing an
/// arbitrary string into a quoted TOML value is an injection into a file
/// the whole app reads at startup.
pub fn save_crux_api_key(key: Option<&str>, path: Option<&Path>) -> Result<PathBuf, SettingsError> {
    let key = key.map(str::trim).filter(|text| !text.is_empty());
    if let Some(text) = key {
        let shape_ok = (10..=200).contains(&text.len())
            && text
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
        if !shape_ok {
            return Err(SettingsError(
                "That does not look like an API key (letters, digits, - and _ only). \
                 Nothing was saved."
                    .to_string(),
            ));
        }
    }
    save_setting(
        "crux_api_key",
        key.map(|text| SettingValue::Str(text.to_string())),
        Some("collector"),
        path,
    )
}

/// Persist the global endpoint-probing switch. Top-level, not in a
/// section, because that is the shape the app has always documented.
pub fn save_probe_enabled(enabled: bool, path: Option<&Path>) -> Result<PathBuf, SettingsError> {
    save_setting(
        "probe_enabled",
        Some(SettingValue::Bool(enabled)),
        None,
        path,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(path: &Path, text: &str) {
        std::fs::write(path, text).unwrap();
    }

    #[test]
    fn defaults_match_the_python_defaults() {
        let collector = CollectorConfig::default();
        assert_eq!(collector.http_concurrency, 20);
        assert_eq!(collector.crux_rate_per_second, 2.0);
        assert_eq!(collector.max_body_bytes, 4_000_000);
        let lighthouse = LighthouseConfig::default();
        assert!(!lighthouse.enabled);
        assert_eq!(lighthouse.runs, 3);
        assert_eq!(
            lighthouse.concurrency, 3,
            "NOT http_concurrency; see docstring"
        );
        assert_eq!(lighthouse.form_factors, vec!["mobile"]);
        let discovery = DiscoveryConfig::default();
        assert_eq!(discovery.pages_per_site, 20);
        assert_eq!(discovery.lighthouse_pages_per_site, 5);
    }

    #[test]
    fn a_config_file_overrides_and_the_environment_beats_it() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.toml");
        write(
            &config,
            "probe_enabled = true\n\
             probe_rate_per_second = 1\n\
             [collector]\n\
             http_concurrency = 5\n\
             crux_api_key = \"from-file-key\"\n\
             [lighthouse]\n\
             enabled = true\n\
             some_future_key = 1\n",
        );
        // Env wins over the file for the key.
        std::env::set_var("CRUX_API_KEY", "from-env-key-123");
        let settings = Settings::load(Some(&config)).unwrap();
        std::env::remove_var("CRUX_API_KEY");

        assert!(settings.probe_enabled);
        assert_eq!(
            settings.probe_rate_per_second, 1.0,
            "integer accepted as rate"
        );
        assert_eq!(settings.collector.http_concurrency, 5);
        assert_eq!(
            settings.collector.crux_api_key.as_deref(),
            Some("from-env-key-123")
        );
        assert!(
            settings.lighthouse.enabled,
            "unknown lighthouse keys are ignored"
        );
        assert_eq!(settings.config_path.as_deref(), Some(config.as_path()));
    }

    #[test]
    fn an_unknown_collector_key_is_an_error_matching_python_replace() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.toml");
        write(&config, "[collector]\ntypo_key = 1\n");
        assert!(Settings::load(Some(&config)).is_err());
    }

    #[test]
    fn save_setting_edits_one_line_and_keeps_the_users_comments() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.toml");
        write(
            &config,
            "# my precious comment\n\
             probe_enabled = false\n\
             \n\
             [collector]\n\
             # tuned by hand\n\
             http_concurrency = 12\n",
        );
        save_setting(
            "http_concurrency",
            Some(SettingValue::Int(8)),
            Some("collector"),
            Some(&config),
        )
        .unwrap();
        let text = std::fs::read_to_string(&config).unwrap();
        assert!(text.contains("# my precious comment"));
        assert!(text.contains("# tuned by hand"));
        assert!(text.contains("http_concurrency = 8"));
        assert!(text.contains("probe_enabled = false"), "untouched");
    }

    #[test]
    fn a_top_level_key_lands_above_the_first_section() {
        // In TOML a bare key written after [collector] belongs to
        // collector, so appending would silently change its meaning.
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.toml");
        write(&config, "[collector]\nhttp_concurrency = 12\n");
        save_probe_enabled(true, Some(&config)).unwrap();
        let parsed: toml::Table = std::fs::read_to_string(&config).unwrap().parse().unwrap();
        assert_eq!(
            parsed.get("probe_enabled"),
            Some(&toml::Value::Boolean(true))
        );
        assert!(parsed["collector"].get("probe_enabled").is_none());
    }

    #[test]
    fn a_missing_file_is_created_with_its_banner() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.toml");
        save_crux_api_key(Some("valid-key-12345"), Some(&config)).unwrap();
        let text = std::fs::read_to_string(&config).unwrap();
        assert!(text.starts_with("# SLAP configuration."));
        let parsed: toml::Table = text.parse().unwrap();
        assert_eq!(
            parsed["collector"]["crux_api_key"].as_str(),
            Some("valid-key-12345")
        );
    }

    #[test]
    fn an_injection_shaped_key_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.toml");
        let attack = "x\"\n[collector]\nverify_tls = false\n#";
        assert!(save_crux_api_key(Some(attack), Some(&config)).is_err());
        assert!(!config.exists(), "nothing was saved");
    }

    #[test]
    fn removing_an_absent_key_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.toml");
        save_setting("crux_api_key", None, Some("collector"), Some(&config)).unwrap();
        assert!(!config.exists());
    }
}
