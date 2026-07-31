"""The findings engine: rules are data, not code.

Rules live in ``rules.yaml``. Tuning a severity threshold must never
require a code change, so conditions are evaluated by a small declarative
interpreter rather than ``eval``. That is a deliberate choice: rule files
are the thing most likely to be edited casually, and an eval-based engine
turns a typo in a config file into arbitrary code execution.

Supported condition operators::

    {metric: http.ttfb, gt: 800}
    {metric: sec.csp, missing: true}
    {metric: tls.protocol, in: [TLSv1, TLSv1.1]}
    {all: [...]}   {any: [...]}   {none: [...]}
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from ..schema import Finding, Severity, format_value

RULES_PATH = Path(__file__).with_name("rules.yaml")

_TEMPLATE_RE = re.compile(r"\{([a-zA-Z][\w.]*)\}")

_MISSING = object()


class RuleError(ValueError):
    """A rule file is malformed."""


def render_template(text: str, values: dict[str, Any]) -> str:
    """Substitute ``{metric.key}`` placeholders. Unknown keys become 'n/a'.

    Values are formatted through the metric registry's declared unit, so
    ``{http.content_bytes}`` renders as "402 KB" rather than "412000".
    Rule text must therefore NOT append its own unit after a placeholder:
    write ``{http.ttfb}``, never ``{http.ttfb}ms``.
    """

    def replace(match: re.Match[str]) -> str:
        key = match.group(1)
        value = values.get(key, _MISSING)
        if value is _MISSING or value is None:
            return "n/a"
        return format_value(key, value)

    return _TEMPLATE_RE.sub(replace, text)


def _compare(value: Any, op: str, operand: Any) -> bool:
    if op == "missing":
        return (value is None) is bool(operand)
    if op == "present":
        return (value is not None) is bool(operand)
    if value is None:
        return False
    if op == "is" or op == "eq":
        if isinstance(operand, bool):
            return bool(value) is operand
        return value == operand
    if op == "ne":
        return value != operand
    if op == "in":
        return value in operand
    if op == "not_in":
        return value not in operand
    if op == "contains":
        return str(operand).lower() in str(value).lower()
    if op == "not_contains":
        return str(operand).lower() not in str(value).lower()
    if op == "matches":
        return re.search(str(operand), str(value), re.I) is not None
    # Numeric comparisons
    try:
        left, right = float(value), float(operand)
    except (TypeError, ValueError):
        return False
    return {
        "gt": left > right,
        "gte": left >= right,
        "lt": left < right,
        "lte": left <= right,
    }[op]


_LEAF_OPS = {
    "is", "eq", "ne", "gt", "gte", "lt", "lte", "in", "not_in",
    "contains", "not_contains", "matches", "missing", "present",
}


def evaluate(condition: dict[str, Any], values: dict[str, Any]) -> bool:
    """Evaluate one condition node against a flattened observation dict."""
    if not isinstance(condition, dict):
        raise RuleError(f"condition must be a mapping, got {type(condition).__name__}")

    if "all" in condition:
        return all(evaluate(c, values) for c in condition["all"])
    if "any" in condition:
        return any(evaluate(c, values) for c in condition["any"])
    if "none" in condition:
        return not any(evaluate(c, values) for c in condition["none"])

    metric = condition.get("metric")
    if metric is None:
        raise RuleError(f"condition needs a 'metric' key: {condition!r}")
    ops = [k for k in condition if k in _LEAF_OPS]
    if not ops:
        raise RuleError(f"condition on {metric!r} has no operator: {condition!r}")
    value = values.get(metric)
    return all(_compare(value, op, condition[op]) for op in ops)


@dataclass(frozen=True, slots=True)
class Rule:
    id: str
    severity: Severity
    title: str
    detail: str
    when: dict[str, Any]
    remediation: str | None = None
    wp_rocket_setting: str | None = None
    effort: str | None = None
    impact_ms_from: str | None = None
    evidence: list[str] | None = None

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "Rule":
        missing = [k for k in ("id", "severity", "title", "when") if k not in raw]
        if missing:
            raise RuleError(f"rule {raw.get('id', '?')} missing keys: {missing}")
        try:
            severity = Severity(raw["severity"])
        except ValueError as exc:
            raise RuleError(f"rule {raw['id']}: {exc}") from exc
        return cls(
            id=raw["id"],
            severity=severity,
            title=raw["title"],
            detail=raw.get("detail", ""),
            when=raw["when"],
            remediation=raw.get("remediation"),
            wp_rocket_setting=raw.get("wp_rocket_setting"),
            effort=raw.get("effort"),
            impact_ms_from=raw.get("impact_ms_from"),
            evidence=raw.get("evidence"),
        )

    def fires(self, values: dict[str, Any]) -> bool:
        return evaluate(self.when, values)

    def to_finding(self, values: dict[str, Any]) -> Finding:
        evidence_keys = self.evidence or _referenced_metrics(self.when)
        evidence = {k: values[k] for k in evidence_keys if k in values}
        impact = values.get(self.impact_ms_from) if self.impact_ms_from else None
        return Finding(
            rule_id=self.id,
            severity=self.severity,
            title=render_template(self.title, values),
            detail=render_template(self.detail, values),
            evidence=evidence,
            impact_ms=float(impact) if isinstance(impact, (int, float)) else None,
            effort=self.effort,
            remediation=render_template(self.remediation, values) if self.remediation else None,
            wp_rocket_setting=self.wp_rocket_setting,
        )


def _referenced_metrics(condition: Any) -> list[str]:
    """Every metric key a condition tree touches, for default evidence."""
    found: list[str] = []
    if isinstance(condition, dict):
        if "metric" in condition:
            found.append(condition["metric"])
        for key in ("all", "any", "none"):
            for child in condition.get(key, []):
                found.extend(_referenced_metrics(child))
    elif isinstance(condition, list):
        for child in condition:
            found.extend(_referenced_metrics(child))
    return found


_SEVERITY_ORDER = {
    Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2,
    Severity.LOW: 3, Severity.INFO: 4,
}


class FindingsEngine:
    """Loads rules once, applies them to any number of pages."""

    def __init__(self, rules: list[Rule]) -> None:
        self.rules = rules
        seen: set[str] = set()
        for rule in rules:
            if rule.id in seen:
                raise RuleError(f"duplicate rule id: {rule.id}")
            seen.add(rule.id)

    @classmethod
    def load(cls, path: str | Path | None = None) -> "FindingsEngine":
        path = Path(path) if path else RULES_PATH
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        rules = [Rule.from_dict(r) for r in raw.get("rules", [])]
        return cls(rules)

    def run(self, values: dict[str, Any]) -> list[Finding]:
        findings = [
            rule.to_finding(values) for rule in self.rules if rule.fires(values)
        ]
        findings.sort(key=lambda f: (_SEVERITY_ORDER[f.severity],
                                     -(f.impact_ms or 0.0), f.rule_id))
        return findings
