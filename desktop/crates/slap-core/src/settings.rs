//! Settings, resolved from defaults, a TOML file, and the environment.
//!
//! The same config.toml serves every app version, so the read side
//! preserves the original behaviour exactly, quirks included: unknown keys
//! in `[collector]` and `[discovery]` are errors (the strict dataclasses
//! path raised on them), while unknown keys in `[lighthouse]` are ignored
//! (that section was checked with `hasattr` first). Freezing the quirk
//! beats changing which files load between versions.
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
/// The app prefers the NEWER of this and the bundle's copy; the bundled
/// path needs the Tauri resource dir, which only the shell knows, so the
/// newer-of choice lands there in the vulndb module.
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
    /// Whether New audit starts with Lighthouse ticked. On by default: the
    /// report's gauges and speed figures come from Lighthouse, so an audit
    /// without it is the exception. Each audit can still untick it, for a
    /// quick server-and-security pass in seconds rather than minutes.
    pub enabled: bool,
    pub runs: u32,
    pub form_factors: Vec<String>,
    pub categories: Vec<String>,
    pub concurrency: u32,
    pub timeout: f64,
    pub node_path: String,
    pub worker_path: Option<PathBuf>,
    pub chrome_path: Option<String>,
    /// Keep the median run's full Lighthouse report (gzipped JSON, ~600KB a
    /// page) beside the database. A compact per-page summary, which is what
    /// the client report renders from, is always kept; this decides whether
    /// the raw LHR is too. Across an every-page batch it is the difference
    /// between ~1.2GB and a few MB per 2,000 pages.
    pub keep_artifacts: bool,
    /// `"sampled"` (one page per template, the default) or `"every_page"`.
    /// Kept as text and read through [`LighthouseConfig::scope`], so a typo
    /// in a hand-edited config falls back to the default instead of
    /// refusing to load; this section has always been the lenient one.
    pub scope: String,
}

impl LighthouseConfig {
    /// The configured coverage mode, defaulting to sampled for anything
    /// unrecognised.
    pub fn scope(&self) -> crate::schema::LighthouseScope {
        crate::schema::LighthouseScope::parse(self.scope.trim())
            .unwrap_or(crate::schema::LighthouseScope::Sampled)
    }

    /// The Lighthouse concurrency actually used: at least 1, at most 4.
    /// Contended CPU inflates TBT and gives plausible, irreproducible
    /// scores, so the cap holds whatever a config file says.
    pub fn effective_concurrency(&self) -> usize {
        self.concurrency.clamp(1, 4) as usize
    }
}

impl Default for LighthouseConfig {
    fn default() -> Self {
        Self {
            enabled: true,
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
            scope: crate::schema::LighthouseScope::Sampled.as_str().to_string(),
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
    /// The base directory for the database and the app's saved files. Defaults
    /// to the per-user data directory; a `data_dir` key in config.toml (set by
    /// the Settings screen) relocates it, and the path fields below derive from
    /// it unless individually overridden.
    pub data_dir: PathBuf,
    pub db_path: PathBuf,
    pub artifact_dir: PathBuf,
    pub report_dir: PathBuf,
    pub rules_path: Option<PathBuf>,
    pub collector: CollectorConfig,
    pub lighthouse: LighthouseConfig,
    pub discovery: DiscoveryConfig,
    pub vulndb_path: PathBuf,
    /// The NVD API key, if the user saved one. Optional: the in-app database
    /// regenerator works without it at NVD's unauthenticated rate (~10 min);
    /// a key raises the pace roughly sevenfold. A top-level key, not in a
    /// section, and the `NVD_API_KEY` environment variable overrides it (as
    /// `CRUX_API_KEY` does the CrUX key).
    pub nvd_api_key: Option<String>,
    /// Endpoint probing. Off by default and authorised per host, never
    /// globally: a global flag gets switched on once and then silently
    /// applies to the next client, who never agreed to it.
    pub probe_enabled: bool,
    pub probe_rate_per_second: f64,
    /// Whether the client-facing report includes WP Rocket remediation
    /// suggestions (the "In WP Rocket" line under a finding's fix). On by
    /// default; turned off for a site that does not run WP Rocket, or a
    /// report that should not carry plugin-specific advice. Top-level, like
    /// `probe_enabled`, so a bare key is never trapped inside a strict section.
    pub wp_rocket_suggestions: bool,
    /// Whether the client-facing report includes each finding's "How to
    /// fix" advice (its remediation line). On by default; turned off for a
    /// report that should state the problems and leave the fixes to be
    /// quoted separately. Top-level, like `wp_rocket_suggestions`.
    pub fix_advice: bool,
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
            data_dir: paths::default_data_dir(),
            db_path: paths::db_path(),
            artifact_dir: paths::default_data_dir().join("artifacts"),
            report_dir: paths::default_data_dir().join("reports"),
            rules_path: None,
            collector: CollectorConfig::default(),
            lighthouse: LighthouseConfig::default(),
            discovery: DiscoveryConfig::default(),
            vulndb_path: user_vulndb_path(),
            nvd_api_key: None,
            probe_enabled: false,
            probe_rate_per_second: 2.0,
            wp_rocket_suggestions: true,
            fix_advice: true,
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
            // A single relocated data directory: the base for the database and
            // the app's saved files. The individual *_path overrides below still
            // win, and SLAP_DB still wins for the database.
            if let Some(dir) = path_of("data_dir") {
                settings.data_dir = dir.clone();
                settings.db_path = dir.join(format!("{}.sqlite3", paths::DIRNAME));
                settings.artifact_dir = dir.join("artifacts");
                settings.report_dir = dir.join("reports");
                settings.vulndb_path = dir.join("vulndb.json");
            }
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
            // error, as the dataclasses path did); lighthouse ignores
            // unknown keys (checked with hasattr first).
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
            // Absent means on, so a report keeps its WP Rocket advice unless a
            // config explicitly switches it off.
            if let Some(toml::Value::Boolean(enabled)) = raw.get("wp_rocket_suggestions") {
                settings.wp_rocket_suggestions = *enabled;
            }
            // The same for "How to fix": absent means on.
            if let Some(toml::Value::Boolean(enabled)) = raw.get("fix_advice") {
                settings.fix_advice = *enabled;
            }
            match raw.get("probe_rate_per_second") {
                Some(toml::Value::Float(rate)) => settings.probe_rate_per_second = *rate,
                Some(toml::Value::Integer(rate)) => settings.probe_rate_per_second = *rate as f64,
                _ => {}
            }
            if let Some(toml::Value::String(key)) = raw.get("nvd_api_key") {
                if !key.is_empty() {
                    settings.nvd_api_key = Some(key.clone());
                }
            }
        }

        // Environment wins, so a teammate can point at their own key
        // without editing a shared config file.
        if let Ok(key) = std::env::var("CRUX_API_KEY") {
            if !key.is_empty() {
                settings.collector.crux_api_key = Some(key);
            }
        }
        // Same convention for the NVD key the regenerator uses.
        if let Ok(key) = std::env::var("NVD_API_KEY") {
            if !key.is_empty() {
                settings.nvd_api_key = Some(key);
            }
        }
        // SLAP_DB overrides the configured database location; see
        // paths::db_path for why.
        if let Some(env_db) = std::env::var_os("SLAP_DB") {
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

/// The value shapes `save_setting` accepts, rendered exactly as the
/// original `_render` did (bools lowercase, numbers via their natural
/// display, strings quoted).
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
                // A whole float keeps its ".0" so TOML reads it back as a
                // float, not an int.
                if float.fract() == 0.0 && float.is_finite() {
                    format!("{float:.1}")
                } else {
                    format!("{float}")
                }
            }
            SettingValue::Str(text) => {
                // A TOML basic string: backslashes, quotes and control
                // characters must be escaped, or a Windows path such as
                // C:\Users\... is read as invalid unicode escapes and the
                // whole config fails to parse.
                let mut out = String::with_capacity(text.len() + 2);
                out.push('"');
                for c in text.chars() {
                    match c {
                        '\\' => out.push_str("\\\\"),
                        '"' => out.push_str("\\\""),
                        '\n' => out.push_str("\\n"),
                        '\r' => out.push_str("\\r"),
                        '\t' => out.push_str("\\t"),
                        c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04X}", c as u32)),
                        c => out.push(c),
                    }
                }
                out.push('"');
                out
            }
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

/// Persist (or clear) the NVD API key. Top-level, so it never lands inside a
/// strict `[collector]`/`[discovery]` section, and validated to the same shape
/// as the CrUX key for the same reason: an arbitrary string quoted into a file
/// the whole app parses at startup is an injection.
pub fn save_nvd_api_key(key: Option<&str>, path: Option<&Path>) -> Result<PathBuf, SettingsError> {
    let key = key.map(str::trim).filter(|text| !text.is_empty());
    if let Some(text) = key {
        let shape_ok = (10..=200).contains(&text.len())
            && text
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
        if !shape_ok {
            return Err(SettingsError(
                "That does not look like an NVD API key (letters, digits, - and _ only). \
                 Nothing was saved."
                    .to_string(),
            ));
        }
    }
    save_setting(
        "nvd_api_key",
        key.map(|text| SettingValue::Str(text.to_string())),
        None,
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

/// Persist whether reports carry WP Rocket remediation suggestions. Written
/// top-level, matching `probe_enabled`: a bare key inside a strict section
/// would be rejected on the next load. The value is always written (true or
/// false) so the Settings screen can flip a stored `false` back on.
pub fn save_wp_rocket_suggestions(
    enabled: bool,
    path: Option<&Path>,
) -> Result<PathBuf, SettingsError> {
    save_setting(
        "wp_rocket_suggestions",
        Some(SettingValue::Bool(enabled)),
        None,
        path,
    )
}

/// Persist whether reports carry each finding's "How to fix" advice. Written
/// top-level and always written, for the same reasons as
/// `save_wp_rocket_suggestions`.
pub fn save_fix_advice(enabled: bool, path: Option<&Path>) -> Result<PathBuf, SettingsError> {
    save_setting("fix_advice", Some(SettingValue::Bool(enabled)), None, path)
}

/// Persist the Lighthouse coverage mode (`[lighthouse] scope`). The
/// `[lighthouse]` section is the lenient one (unknown keys are ignored), so an
/// older app version reading the same config is unaffected by the key.
pub fn save_lighthouse_scope(
    scope: crate::schema::LighthouseScope,
    path: Option<&Path>,
) -> Result<PathBuf, SettingsError> {
    save_setting(
        "scope",
        Some(SettingValue::Str(scope.as_str().to_string())),
        Some("lighthouse"),
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
    fn defaults_match_the_shipped_defaults() {
        let collector = CollectorConfig::default();
        assert_eq!(collector.http_concurrency, 20);
        assert_eq!(collector.crux_rate_per_second, 2.0);
        assert_eq!(collector.max_body_bytes, 4_000_000);
        let lighthouse = LighthouseConfig::default();
        assert!(lighthouse.enabled, "New audit starts with Lighthouse ticked");
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
             enabled = false\n\
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
            !settings.lighthouse.enabled,
            "the file's choice is read, and unknown lighthouse keys are ignored"
        );
        assert_eq!(settings.config_path.as_deref(), Some(config.as_path()));
    }

    #[test]
    fn lighthouse_scope_defaults_to_sampled_and_round_trips() {
        use crate::schema::LighthouseScope;
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.toml");

        // Absent: sampled, the default that keeps a batch to its old budget.
        assert_eq!(
            LighthouseConfig::default().scope(),
            LighthouseScope::Sampled
        );

        // A hand-edited typo falls back rather than refusing to start.
        write(&config, "[lighthouse]\nscope = \"every-pages\"\n");
        let settings = Settings::load(Some(&config)).unwrap();
        assert_eq!(settings.lighthouse.scope(), LighthouseScope::Sampled);

        // Saved through the surgical writer, it reads back, and the user's
        // other lighthouse keys survive.
        write(&config, "[lighthouse]\nenabled = false\n");
        save_lighthouse_scope(LighthouseScope::EveryPage, Some(&config)).unwrap();
        let settings = Settings::load(Some(&config)).unwrap();
        assert_eq!(settings.lighthouse.scope(), LighthouseScope::EveryPage);
        assert!(!settings.lighthouse.enabled, "a key set away from its default survives");

        // The concurrency cap holds whatever the file says.
        write(&config, "[lighthouse]\nconcurrency = 16\n");
        let settings = Settings::load(Some(&config)).unwrap();
        assert_eq!(settings.lighthouse.effective_concurrency(), 4);
    }

    #[test]
    fn an_unknown_collector_key_is_an_error_matching_strict_replace() {
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

    #[test]
    fn data_dir_relocates_the_saved_files() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.toml");
        let data = dir.path().join("elsewhere");
        // Backslashes must be escaped inside a TOML basic string on Windows.
        let quoted = data.display().to_string().replace('\\', "\\\\");
        write(&config, &format!("data_dir = \"{quoted}\"\n"));
        let s = Settings::load(Some(&config)).unwrap();
        assert_eq!(s.data_dir, data);
        assert_eq!(s.report_dir, data.join("reports"));
        assert_eq!(s.artifact_dir, data.join("artifacts"));
        assert_eq!(s.vulndb_path, data.join("vulndb.json"));
    }

    #[test]
    fn an_explicit_path_still_wins_over_data_dir() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.toml");
        let data = dir.path().join("elsewhere");
        let custom = dir.path().join("myreports");
        let q = |p: &Path| p.display().to_string().replace('\\', "\\\\");
        write(
            &config,
            &format!("data_dir = \"{}\"\nreport_dir = \"{}\"\n", q(&data), q(&custom)),
        );
        let s = Settings::load(Some(&config)).unwrap();
        assert_eq!(s.report_dir, custom, "explicit report_dir beats data_dir");
        assert_eq!(
            s.artifact_dir,
            data.join("artifacts"),
            "the ones left unset still follow data_dir"
        );
    }

    #[test]
    fn the_nvd_key_saves_top_level_and_the_environment_overrides_it() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.toml");
        // Saved top-level, above any section, so it never lands in a strict one.
        write(&config, "[collector]\nhttp_concurrency = 12\n");
        save_nvd_api_key(Some("nvd-key-abc123"), Some(&config)).unwrap();
        let parsed: toml::Table = std::fs::read_to_string(&config).unwrap().parse().unwrap();
        assert_eq!(parsed.get("nvd_api_key").and_then(|v| v.as_str()), Some("nvd-key-abc123"));
        assert!(parsed["collector"].get("nvd_api_key").is_none());
        let s = Settings::load(Some(&config)).unwrap();
        assert_eq!(s.nvd_api_key.as_deref(), Some("nvd-key-abc123"));
        // Environment wins, matching the CrUX convention.
        std::env::set_var("NVD_API_KEY", "nvd-from-env-99");
        let s = Settings::load(Some(&config)).unwrap();
        std::env::remove_var("NVD_API_KEY");
        assert_eq!(s.nvd_api_key.as_deref(), Some("nvd-from-env-99"));
    }

    #[test]
    fn a_windows_style_path_round_trips_through_save_setting() {
        // Backslashes in a path must be escaped for TOML, or the file fails to
        // parse and save_setting's read-back guard rejects the write. This is
        // the shape set_data_dir writes on Windows.
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.toml");
        let winpath = r"C:\Users\Someone\AppData\Local\slap-data";
        save_setting(
            "data_dir",
            Some(SettingValue::Str(winpath.to_string())),
            None,
            Some(&config),
        )
        .expect("a path with backslashes must save");
        let parsed: toml::Table = std::fs::read_to_string(&config).unwrap().parse().unwrap();
        assert_eq!(parsed.get("data_dir").and_then(|v| v.as_str()), Some(winpath));
    }

    #[test]
    fn wp_rocket_suggestions_default_on_and_toggle_round_trips() {
        // Default is on, and absent from a config leaves it on.
        assert!(Settings::default().wp_rocket_suggestions);
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.toml");
        write(&config, "[collector]\nhttp_concurrency = 12\n");
        assert!(
            Settings::load(Some(&config)).unwrap().wp_rocket_suggestions,
            "absent means on"
        );
        // Turning it off writes a top-level key, never inside [collector].
        save_wp_rocket_suggestions(false, Some(&config)).unwrap();
        let parsed: toml::Table = std::fs::read_to_string(&config).unwrap().parse().unwrap();
        assert_eq!(
            parsed.get("wp_rocket_suggestions"),
            Some(&toml::Value::Boolean(false))
        );
        assert!(parsed["collector"].get("wp_rocket_suggestions").is_none());
        assert!(!Settings::load(Some(&config)).unwrap().wp_rocket_suggestions);
        // And back on again overrides the stored false.
        save_wp_rocket_suggestions(true, Some(&config)).unwrap();
        assert!(Settings::load(Some(&config)).unwrap().wp_rocket_suggestions);
    }

    #[test]
    fn fix_advice_defaults_on_and_toggle_round_trips() {
        assert!(Settings::default().fix_advice);
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.toml");
        write(&config, "[collector]\nhttp_concurrency = 12\n");
        assert!(Settings::load(Some(&config)).unwrap().fix_advice, "absent means on");
        save_fix_advice(false, Some(&config)).unwrap();
        let parsed: toml::Table = std::fs::read_to_string(&config).unwrap().parse().unwrap();
        assert_eq!(parsed.get("fix_advice"), Some(&toml::Value::Boolean(false)));
        assert!(parsed["collector"].get("fix_advice").is_none(), "never inside a strict section");
        let settings = Settings::load(Some(&config)).unwrap();
        assert!(!settings.fix_advice);
        assert!(settings.wp_rocket_suggestions, "the two switches are independent");
        save_fix_advice(true, Some(&config)).unwrap();
        assert!(Settings::load(Some(&config)).unwrap().fix_advice);
    }
}
