//! The findings engine: rules are data, not code.
//!
//! The rules were carried across the rewrite as data, not ported as code,
//! and that is the design paying off: `rules/rules.yaml` beside this crate
//! is the file every engine version has interpreted. While app versions
//! shared one copy, a differential test proved they agreed
//! finding-for-finding, rendered text included; agreement on the conditions
//! is what makes findings written into the database by any version
//! comparable. The wording has since been rewritten for clients, and the
//! report renders a finding's words from the current file.
//!
//! Conditions are evaluated by a small declarative interpreter rather than
//! anything eval-like: rule files are the thing most likely to be edited
//! casually, and an engine that executes them turns a typo in a config file
//! into arbitrary code.
//!
//! Supported condition operators:
//!
//! ```yaml
//! {metric: http.ttfb, gt: 800}
//! {metric: sec.csp, missing: true}
//! {metric: tls.protocol, in: [TLSv1, TLSv1.1]}
//! {all: [...]}   {any: [...]}   {none: [...]}
//! ```

use std::collections::HashMap;
use std::fmt;
use std::path::Path;
use std::sync::OnceLock;

use regex::{Regex, RegexBuilder};
use serde_yaml::Value as Yaml;

use crate::schema::{format_value, Finding, Severity, Value};

/// The shipped rules, embedded at compile time. A custom `rules_path` in
/// settings overrides it at runtime.
pub const RULES_YAML: &str = include_str!("../rules/rules.yaml");

#[derive(Debug)]
pub struct RuleError(pub String);

impl fmt::Display for RuleError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str(&self.0)
    }
}
impl std::error::Error for RuleError {}

fn template_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\{([a-zA-Z][\w.]*)\}").expect("a valid literal pattern"))
}

/// Substitute `{metric.key}` placeholders. Unknown keys become 'n/a'.
///
/// Values are formatted through the metric registry's declared unit, so
/// `{http.content_bytes}` renders as "402 KB" rather than "412000". Rule
/// text therefore must NOT append its own unit after a placeholder: write
/// `{http.ttfb}`, never `{http.ttfb}ms`.
pub fn render_template(text: &str, values: &HashMap<String, Value>) -> String {
    template_re()
        .replace_all(text, |captures: &regex::Captures<'_>| {
            let key = &captures[1];
            format_value(key, values.get(key))
        })
        .into_owned()
}

// ---------------------------------------------------------------------------
// Condition evaluation
// ---------------------------------------------------------------------------

const LEAF_OPS: &[&str] = &[
    "is",
    "eq",
    "ne",
    "gt",
    "gte",
    "lt",
    "lte",
    "in",
    "not_in",
    "contains",
    "not_contains",
    "matches",
    "missing",
    "present",
];

/// Truthiness for a YAML operand (`missing: true`, but also the odd
/// `missing: 1` a hand-edited file might carry).
fn yaml_truthy(operand: &Yaml) -> bool {
    match operand {
        Yaml::Null => false,
        Yaml::Bool(b) => *b,
        Yaml::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Yaml::String(s) => !s.is_empty(),
        Yaml::Sequence(seq) => !seq.is_empty(),
        Yaml::Mapping(map) => !map.is_empty(),
        Yaml::Tagged(tagged) => yaml_truthy(&tagged.value),
    }
}

/// Render a YAML operand the way the substring operators compare it.
fn yaml_as_string(operand: &Yaml) -> String {
    match operand {
        Yaml::String(s) => s.clone(),
        Yaml::Bool(b) => (if *b { "True" } else { "False" }).to_string(),
        Yaml::Number(n) => {
            if let Some(int) = n.as_i64() {
                int.to_string()
            } else {
                let f = n.as_f64().unwrap_or(f64::NAN);
                if f.fract() == 0.0 && f.is_finite() {
                    format!("{f:.1}")
                } else {
                    format!("{f}")
                }
            }
        }
        other => serde_yaml::to_string(other)
            .unwrap_or_default()
            .trim()
            .to_string(),
    }
}

fn yaml_as_f64(operand: &Yaml) -> Option<f64> {
    match operand {
        Yaml::Number(n) => n.as_f64(),
        Yaml::Bool(b) => Some(if *b { 1.0 } else { 0.0 }),
        Yaml::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

/// Equality between an observation value and a YAML operand: numbers
/// compare numerically (a boolean against a number becomes 1.0/0.0),
/// strings compare as strings, and cross-type comparisons are unequal.
fn value_eq(value: &Value, operand: &Yaml) -> bool {
    match (value, operand) {
        (Value::Text(text), Yaml::String(s)) => text == s,
        (Value::Num(n), Yaml::Number(_)) => yaml_as_f64(operand) == Some(*n),
        (Value::Bool(b), Yaml::Number(_)) => {
            yaml_as_f64(operand) == Some(if *b { 1.0 } else { 0.0 })
        }
        (Value::Num(n), Yaml::Bool(b)) => *n == if *b { 1.0 } else { 0.0 },
        (Value::Bool(a), Yaml::Bool(b)) => a == b,
        _ => false,
    }
}

fn compare(value: Option<&Value>, op: &str, operand: &Yaml) -> bool {
    if op == "missing" {
        return value.is_none() == yaml_truthy(operand);
    }
    if op == "present" {
        return value.is_some() == yaml_truthy(operand);
    }
    let Some(value) = value else {
        return false;
    };
    match op {
        "is" | "eq" => {
            if let Yaml::Bool(wanted) = operand {
                value.truthy() == *wanted
            } else {
                value_eq(value, operand)
            }
        }
        "ne" => !value_eq(value, operand),
        "in" => match operand {
            Yaml::Sequence(items) => items.iter().any(|item| value_eq(value, item)),
            _ => false,
        },
        "not_in" => match operand {
            Yaml::Sequence(items) => !items.iter().any(|item| value_eq(value, item)),
            _ => false,
        },
        "contains" => value
            .to_plain_string()
            .to_lowercase()
            .contains(&yaml_as_string(operand).to_lowercase()),
        "not_contains" => !value
            .to_plain_string()
            .to_lowercase()
            .contains(&yaml_as_string(operand).to_lowercase()),
        "matches" => RegexBuilder::new(&yaml_as_string(operand))
            .case_insensitive(true)
            .build()
            .map(|re| re.is_match(&value.to_plain_string()))
            .unwrap_or(false),
        "gt" | "gte" | "lt" | "lte" => {
            let (Some(left), Some(right)) = (value.as_f64(), yaml_as_f64(operand)) else {
                return false;
            };
            match op {
                "gt" => left > right,
                "gte" => left >= right,
                "lt" => left < right,
                _ => left <= right,
            }
        }
        _ => false,
    }
}

/// Evaluate one condition node against a flattened observation dict.
pub fn evaluate(condition: &Yaml, values: &HashMap<String, Value>) -> Result<bool, RuleError> {
    let Yaml::Mapping(map) = condition else {
        return Err(RuleError(format!(
            "condition must be a mapping, got: {condition:?}"
        )));
    };

    for combinator in ["all", "any", "none"] {
        if let Some(children) = map.get(Yaml::String(combinator.to_string())) {
            let Yaml::Sequence(children) = children else {
                return Err(RuleError(format!("{combinator} needs a list")));
            };
            let mut any_true = false;
            let mut all_true = true;
            for child in children {
                let hit = evaluate(child, values)?;
                any_true |= hit;
                all_true &= hit;
            }
            // Empty lists keep the classic semantics: all([]) is true,
            // any([]) is false, none of [] is true.
            return Ok(match combinator {
                "all" => all_true,
                "any" => any_true,
                _ => !any_true,
            });
        }
    }

    let metric = map
        .get(Yaml::String("metric".to_string()))
        .and_then(|value| value.as_str())
        .ok_or_else(|| RuleError(format!("condition needs a 'metric' key: {condition:?}")))?;
    let ops: Vec<(&str, &Yaml)> = LEAF_OPS
        .iter()
        .filter_map(|op| {
            map.get(Yaml::String((*op).to_string()))
                .map(|operand| (*op, operand))
        })
        .collect();
    if ops.is_empty() {
        return Err(RuleError(format!(
            "condition on {metric:?} has no operator: {condition:?}"
        )));
    }
    let value = values.get(metric);
    Ok(ops.iter().all(|(op, operand)| compare(value, op, operand)))
}

/// Every metric key a condition tree touches, for default evidence.
fn referenced_metrics(condition: &Yaml, found: &mut Vec<String>) {
    match condition {
        Yaml::Mapping(map) => {
            if let Some(metric) = map
                .get(Yaml::String("metric".to_string()))
                .and_then(|value| value.as_str())
            {
                found.push(metric.to_string());
            }
            for key in ["all", "any", "none"] {
                if let Some(Yaml::Sequence(children)) = map.get(Yaml::String(key.to_string())) {
                    for child in children {
                        referenced_metrics(child, found);
                    }
                }
            }
        }
        Yaml::Sequence(children) => {
            for child in children {
                referenced_metrics(child, found);
            }
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Rule {
    pub id: String,
    pub severity: Severity,
    pub title: String,
    pub detail: String,
    pub when: Yaml,
    pub remediation: Option<String>,
    pub wp_rocket_setting: Option<String>,
    pub effort: Option<String>,
    pub impact_ms_from: Option<String>,
    pub evidence: Option<Vec<String>>,
}

fn str_field(map: &serde_yaml::Mapping, key: &str) -> Option<String> {
    map.get(Yaml::String(key.to_string()))
        .and_then(|value| value.as_str())
        .map(str::to_string)
}

impl Rule {
    pub fn from_yaml(raw: &Yaml) -> Result<Self, RuleError> {
        let Yaml::Mapping(map) = raw else {
            return Err(RuleError("a rule must be a mapping".to_string()));
        };
        let id = str_field(map, "id");
        let missing: Vec<&str> = [
            ("id", id.is_some()),
            (
                "severity",
                map.contains_key(Yaml::String("severity".into())),
            ),
            ("title", str_field(map, "title").is_some()),
            ("when", map.contains_key(Yaml::String("when".into()))),
        ]
        .iter()
        .filter(|(_, present)| !present)
        .map(|(name, _)| *name)
        .collect();
        if !missing.is_empty() {
            return Err(RuleError(format!(
                "rule {} missing keys: {missing:?}",
                id.as_deref().unwrap_or("?")
            )));
        }
        let id = id.expect("checked above");
        let severity_text = str_field(map, "severity")
            .ok_or_else(|| RuleError(format!("rule {id}: severity must be a string")))?;
        let severity = Severity::parse(&severity_text)
            .ok_or_else(|| RuleError(format!("rule {id}: {severity_text:?} is not a severity")))?;
        let evidence = map
            .get(Yaml::String("evidence".to_string()))
            .and_then(|value| value.as_sequence())
            .map(|seq| {
                seq.iter()
                    .filter_map(|item| item.as_str().map(str::to_string))
                    .collect()
            });
        Ok(Rule {
            severity,
            title: str_field(map, "title").expect("checked above"),
            detail: str_field(map, "detail").unwrap_or_default(),
            when: map
                .get(Yaml::String("when".to_string()))
                .cloned()
                .expect("checked above"),
            remediation: str_field(map, "remediation"),
            wp_rocket_setting: str_field(map, "wp_rocket_setting"),
            effort: str_field(map, "effort"),
            impact_ms_from: str_field(map, "impact_ms_from"),
            evidence,
            id,
        })
    }

    pub fn fires(&self, values: &HashMap<String, Value>) -> Result<bool, RuleError> {
        evaluate(&self.when, values)
    }

    pub fn to_finding(&self, values: &HashMap<String, Value>) -> Finding {
        let evidence_keys: Vec<String> = self.evidence.clone().unwrap_or_else(|| {
            let mut found = Vec::new();
            referenced_metrics(&self.when, &mut found);
            found
        });
        let mut evidence = serde_json::Map::new();
        for key in evidence_keys {
            if let Some(value) = values.get(&key) {
                let json = match value {
                    Value::Num(n) => serde_json::json!(n),
                    Value::Bool(b) => serde_json::json!(b),
                    Value::Text(t) => serde_json::json!(t),
                };
                evidence.insert(key, json);
            }
        }
        // A boolean impact source counts as 1.0/0.0 (bool coerces to a
        // number); any non-numeric source yields no impact.
        let impact_ms = self
            .impact_ms_from
            .as_ref()
            .and_then(|key| match values.get(key) {
                Some(Value::Num(n)) => Some(*n),
                Some(Value::Bool(b)) => Some(if *b { 1.0 } else { 0.0 }),
                _ => None,
            });
        Finding {
            rule_id: self.id.clone(),
            severity: self.severity,
            title: render_template(&self.title, values),
            detail: render_template(&self.detail, values),
            evidence,
            impact_ms,
            effort: self.effort.clone(),
            remediation: self
                .remediation
                .as_ref()
                .map(|text| render_template(text, values)),
            wp_rocket_setting: self.wp_rocket_setting.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// The engine
// ---------------------------------------------------------------------------

/// Loads rules once, applies them to any number of pages.
pub struct FindingsEngine {
    pub rules: Vec<Rule>,
}

impl FindingsEngine {
    pub fn new(rules: Vec<Rule>) -> Result<Self, RuleError> {
        let mut seen = std::collections::HashSet::new();
        for rule in &rules {
            if !seen.insert(rule.id.clone()) {
                return Err(RuleError(format!("duplicate rule id: {}", rule.id)));
            }
        }
        Ok(Self { rules })
    }

    /// Load from a file, or from the embedded shipped rules when `path` is
    /// None (the normal case; a custom `rules_path` in settings overrides).
    pub fn load(path: Option<&Path>) -> Result<Self, RuleError> {
        let text = match path {
            Some(path) => std::fs::read_to_string(path)
                .map_err(|error| RuleError(format!("cannot read {}: {error}", path.display())))?,
            None => RULES_YAML.to_string(),
        };
        Self::parse(&text)
    }

    pub fn parse(text: &str) -> Result<Self, RuleError> {
        let raw: Yaml = serde_yaml::from_str(text)
            .map_err(|error| RuleError(format!("rules file is not valid YAML: {error}")))?;
        let rules = raw
            .get("rules")
            .and_then(|value| value.as_sequence())
            .map(|seq| {
                seq.iter()
                    .map(Rule::from_yaml)
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?
            .unwrap_or_default();
        Self::new(rules)
    }

    /// Apply every rule to one page's flattened observations. Sorted by
    /// severity, then impact (largest first), then rule id. Never capped:
    /// the first report render buried a high-severity finding under a
    /// top-5 cap, and "never cap by count what you have ranked by
    /// severity" is the lesson.
    pub fn run(&self, values: &HashMap<String, Value>) -> Result<Vec<Finding>, RuleError> {
        let mut findings = Vec::new();
        for rule in &self.rules {
            if rule.fires(values)? {
                findings.push(rule.to_finding(values));
            }
        }
        findings.sort_by(|a, b| {
            a.severity
                .order()
                .cmp(&b.severity.order())
                .then(
                    b.impact_ms
                        .unwrap_or(0.0)
                        .partial_cmp(&a.impact_ms.unwrap_or(0.0))
                        .unwrap_or(std::cmp::Ordering::Equal),
                )
                .then(a.rule_id.cmp(&b.rule_id))
        });
        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn values(pairs: &[(&str, Value)]) -> HashMap<String, Value> {
        pairs
            .iter()
            .map(|(key, value)| (key.to_string(), value.clone()))
            .collect()
    }

    fn yaml(text: &str) -> Yaml {
        serde_yaml::from_str(text).unwrap()
    }

    // -- templating, pinned line for line ------------------------------------

    #[test]
    fn render_template_formats_by_the_registry_unit() {
        // A rule writes {http.ttfb}; the formatter supplies 'ms' or 's'
        // itself. Rule text appending its own unit gives '412msms'.
        let v = values(&[("http.ttfb", Value::Num(412.0))]);
        assert_eq!(render_template("TTFB {http.ttfb}", &v), "TTFB 412ms");
        let v = values(&[("http.ttfb", Value::Num(1340.0))]);
        assert_eq!(render_template("TTFB {http.ttfb}", &v), "TTFB 1.3s");
    }

    #[test]
    fn render_template_humanises_byte_counts() {
        let v = values(&[("http.content_bytes", Value::Num(412_000.0))]);
        assert_eq!(render_template("{http.content_bytes}", &v), "402 KB");
    }

    #[test]
    fn render_template_does_not_percentage_cls() {
        let v = values(&[("crux.cls.p75", Value::Num(0.06))]);
        assert_eq!(render_template("{crux.cls.p75}", &v), "0.06");
        let v = values(&[("crux.lcp.good", Value::Num(0.38))]);
        assert_eq!(render_template("{crux.lcp.good}", &v), "38%");
    }

    #[test]
    fn render_template_marks_unknown_keys_rather_than_crashing() {
        assert_eq!(
            render_template("v={wprocket.version}", &values(&[])),
            "v=n/a"
        );
    }

    #[test]
    fn render_template_leaves_non_placeholder_braces_alone() {
        assert_eq!(render_template("{not a key}", &values(&[])), "{not a key}");
    }

    #[test]
    fn no_shipped_rule_appends_a_unit_after_a_placeholder() {
        // Guards the '412msms' regression across the whole rules file.
        let offender = Regex::new(r"\{[a-z][\w.]*\}\s*(?:ms|bytes|seconds|days)\b").unwrap();
        let hits: Vec<&str> = offender.find_iter(RULES_YAML).map(|m| m.as_str()).collect();
        assert!(
            hits.is_empty(),
            "rule text appends units the formatter supplies: {hits:?}"
        );
    }

    // -- conditions --------------------------------------------------------

    #[test]
    fn operators_behave_like_a_declarative_interpreter() {
        let v = values(&[
            ("http.ttfb", Value::Num(900.0)),
            ("tls.protocol", Value::Text("TLSv1.1".into())),
            ("http.server", Value::Text("Apache/2.4.62".into())),
            ("crux.cwv_pass", Value::Bool(false)),
        ]);
        for (condition, expected) in [
            ("{metric: http.ttfb, gt: 800}", true),
            ("{metric: http.ttfb, lte: 800}", false),
            ("{metric: tls.protocol, in: [TLSv1, TLSv1.1]}", true),
            ("{metric: tls.protocol, not_in: [TLSv1, TLSv1.1]}", false),
            ("{metric: http.server, contains: apache}", true),
            ("{metric: http.server, matches: '[0-9]+\\.[0-9]+'}", true),
            ("{metric: crux.cwv_pass, is: false}", true),
            ("{metric: sec.csp, missing: true}", true),
            ("{metric: http.ttfb, missing: true}", false),
            ("{metric: http.ttfb, present: true}", true),
            // A missing value fails every comparison operator.
            ("{metric: sec.csp, gt: 5}", false),
            (
                "{all: [{metric: http.ttfb, gt: 800}, {metric: crux.cwv_pass, is: false}]}",
                true,
            ),
            (
                "{any: [{metric: http.ttfb, gt: 5000}, {metric: crux.cwv_pass, is: false}]}",
                true,
            ),
            ("{none: [{metric: http.ttfb, gt: 5000}]}", true),
            ("{none: [{metric: http.ttfb, gt: 800}]}", false),
        ] {
            assert_eq!(
                evaluate(&yaml(condition), &v).unwrap(),
                expected,
                "condition: {condition}"
            );
        }
    }

    #[test]
    fn a_condition_with_no_operator_is_a_rule_error() {
        assert!(evaluate(&yaml("{metric: a}"), &values(&[("a", Value::Num(1.0))])).is_err());
    }

    #[test]
    fn a_condition_without_metric_is_a_rule_error() {
        assert!(evaluate(&yaml("{gt: 5}"), &values(&[])).is_err());
    }

    // -- rules and the engine ----------------------------------------------

    #[test]
    fn a_rule_rejects_unknown_severity() {
        let raw = yaml("{id: x, severity: catastrophic, title: t, when: {}}");
        assert!(Rule::from_yaml(&raw).is_err());
    }

    #[test]
    fn duplicate_rule_ids_are_refused() {
        let rule = yaml("{id: x, severity: high, title: t, when: {metric: a, gt: 1}}");
        let rules = vec![
            Rule::from_yaml(&rule).unwrap(),
            Rule::from_yaml(&rule).unwrap(),
        ];
        assert!(FindingsEngine::new(rules).is_err());
    }

    #[test]
    fn the_shipped_rules_load_and_count() {
        let engine = FindingsEngine::load(None).unwrap();
        // 63 rules carried forward unchanged, plus the desktop-era
        // https-unreachable rule that flags an http-fallback audit.
        assert_eq!(engine.rules.len(), 65, "rules.yaml rule count drifted");
    }

    #[test]
    fn shipped_rules_fire_against_real_shaped_observations() {
        let engine = FindingsEngine::load(None).unwrap();
        let v = values(&[
            ("crux.available", Value::Bool(true)),
            ("crux.cwv_pass", Value::Bool(false)),
            ("crux.lcp.p75", Value::Num(4500.0)),
            ("crux.inp.p75", Value::Num(150.0)),
            ("crux.cls.p75", Value::Num(0.05)),
        ]);
        let findings = engine.run(&v).unwrap();
        let ids: Vec<&str> = findings.iter().map(|f| f.rule_id.as_str()).collect();
        assert!(ids.contains(&"cwv-fail"), "verdict rule fired: {ids:?}");
        assert!(ids.contains(&"lcp-poor"), "threshold rule fired: {ids:?}");

        // Severity orders the list, and placeholders rendered with units.
        assert_eq!(findings[0].severity, Severity::Critical);
        let lcp = findings.iter().find(|f| f.rule_id == "lcp-poor").unwrap();
        assert!(
            lcp.title.contains("4.5s"),
            "formatted through the registry: {}",
            lcp.title
        );
        assert_eq!(lcp.impact_ms, Some(4500.0));
        assert!(lcp.evidence.contains_key("crux.lcp.p75"));
    }

    #[test]
    fn the_https_unreachable_rule_fires_and_renders_the_error() {
        // The engine (run.rs) records https.unreachable when it falls back to
        // http://; this pins the rule that turns that into a client-facing
        // critical, and that {https.error} is substituted from the observation.
        let engine = FindingsEngine::load(None).unwrap();
        let v = values(&[
            ("https.unreachable", Value::Bool(true)),
            (
                "https.error",
                Value::from("error sending request (invalid peer certificate)"),
            ),
        ]);
        let findings = engine.run(&v).unwrap();
        let hit = findings
            .iter()
            .find(|f| f.rule_id == "https-unreachable")
            .expect("https-unreachable fired");
        assert_eq!(hit.severity, Severity::Critical);
        assert!(
            hit.detail.contains("invalid peer certificate"),
            "the transport error is rendered into the detail: {}",
            hit.detail
        );
    }

    #[test]
    fn findings_sort_by_severity_then_impact_then_id() {
        let rules = ["{id: b-small, severity: high, title: t, when: {metric: x, gt: 0}, impact_ms_from: small}",
                     "{id: a-big, severity: high, title: t, when: {metric: x, gt: 0}, impact_ms_from: big}",
                     "{id: c-crit, severity: critical, title: t, when: {metric: x, gt: 0}}"]
            .iter()
            .map(|text| Rule::from_yaml(&yaml(text)).unwrap())
            .collect();
        let engine = FindingsEngine::new(rules).unwrap();
        let v = values(&[
            ("x", Value::Num(1.0)),
            ("small", Value::Num(10.0)),
            ("big", Value::Num(900.0)),
        ]);
        let ordered: Vec<String> = engine
            .run(&v)
            .unwrap()
            .into_iter()
            .map(|f| f.rule_id)
            .collect();
        assert_eq!(ordered, vec!["c-crit", "a-big", "b-small"]);
    }
}
