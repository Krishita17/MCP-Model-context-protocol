"""Security report generation — Markdown, HTML, and JSON output."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any

from defenselab.simulator import SimulationResult, MatrixResult

# ---------------------------------------------------------------------------
# Compliance framework reference data
# ---------------------------------------------------------------------------

COMPLIANCE_FRAMEWORKS: dict[str, dict[str, str]] = {
    "GDPR": {
        "Art. 5(1)(f)": "Integrity and confidentiality of personal data",
        "Art. 25": "Data protection by design and by default",
        "Art. 32": "Security of processing",
        "Art. 33": "Notification of a personal data breach (72 hours)",
        "Art. 35": "Data protection impact assessment",
        "Art. 83": "Administrative fines (up to EUR 20M / 4% turnover)",
    },
    "EU AI Act": {
        "Art. 9": "Risk management system",
        "Art. 15": "Accuracy, robustness and cybersecurity",
        "Art. 52": "Transparency obligations",
        "Art. 62": "Reporting of serious incidents",
    },
    "NIST": {
        "CSF PR.AC": "Access control",
        "CSF PR.DS": "Data security",
        "CSF DE.AE": "Anomalies and events",
        "CSF DE.CM": "Security continuous monitoring",
        "CSF RS.AN": "Analysis of detected incidents",
    },
    "OWASP": {
        "LLM01": "Prompt injection",
        "LLM02": "Insecure output handling",
        "LLM03": "Training data poisoning / supply chain",
        "LLM06": "Sensitive information disclosure",
        "LLM08": "Excessive agency",
    },
}


@dataclass
class DefenseScore:
    """Effectiveness score for one defense layer."""

    layer_name: str
    detections: int
    total_attacks: int

    @property
    def effectiveness(self) -> float:
        return self.detections / self.total_attacks if self.total_attacks else 0.0


@dataclass
class GapAnalysisEntry:
    """One gap identified in the defense stack."""

    attack_name: str
    attack_variant: str
    missed_layers: list[str]
    severity: str
    recommendation: str


class SecurityReportGenerator:
    """Generates comprehensive security reports from simulation results."""

    def __init__(
        self,
        results: list[SimulationResult] | None = None,
        matrix_result: MatrixResult | None = None,
        title: str = "MCP Security Assessment Report",
    ) -> None:
        self._results: list[SimulationResult] = results or []
        self._matrix = matrix_result
        self._title = title
        self._generated_at = datetime.now(timezone.utc).isoformat()

        if matrix_result and not results:
            self._results = matrix_result.results

    # ------------------------------------------------------------------
    # Markdown
    # ------------------------------------------------------------------

    def generate_markdown_report(self) -> str:
        sections = [
            self._md_header(),
            self._md_executive_summary(),
            self._md_attack_coverage_matrix(),
            self._md_defense_effectiveness(),
            self._md_gap_analysis(),
            self._md_recommendations(),
            self._md_compliance_mapping(),
            self._md_footer(),
        ]
        return "\n\n".join(sections)

    # ------------------------------------------------------------------
    # HTML
    # ------------------------------------------------------------------

    def generate_html_report(self) -> str:
        md = self.generate_markdown_report()
        # Lightweight HTML wrapper with inline styles
        rows_html = self._html_results_table()
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>{self._title}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
         max-width: 960px; margin: 2rem auto; padding: 0 1rem; color: #1a1a2e; }}
  h1 {{ color: #16213e; border-bottom: 3px solid #0f3460; padding-bottom: .5rem; }}
  h2 {{ color: #0f3460; margin-top: 2rem; }}
  h3 {{ color: #533483; }}
  table {{ border-collapse: collapse; width: 100%; margin: 1rem 0; }}
  th, td {{ border: 1px solid #ccc; padding: .5rem .75rem; text-align: left; }}
  th {{ background: #0f3460; color: #fff; }}
  tr:nth-child(even) {{ background: #f4f4f8; }}
  .blocked {{ color: #27ae60; font-weight: bold; }}
  .passed {{ color: #e74c3c; font-weight: bold; }}
  .score {{ font-size: 2rem; font-weight: bold; }}
  .footer {{ margin-top: 3rem; font-size: 0.85rem; color: #888; }}
</style>
</head>
<body>
<h1>{self._title}</h1>
<p><em>Generated: {self._generated_at}</em></p>

<h2>Executive Summary</h2>
{self._html_executive_summary()}

<h2>Attack Coverage Matrix</h2>
{rows_html}

<h2>Defense Effectiveness</h2>
{self._html_defense_scores()}

<h2>Gap Analysis</h2>
{self._html_gap_analysis()}

<h2>Recommendations</h2>
{self._html_recommendations()}

<h2>Compliance Mapping</h2>
{self._html_compliance()}

<div class="footer">
  <p>Report generated by DefenseLab Security Report Generator</p>
</div>
</body>
</html>"""

    # ------------------------------------------------------------------
    # JSON
    # ------------------------------------------------------------------

    def generate_json_report(self) -> str:
        data: dict[str, Any] = {
            "title": self._title,
            "generated_at": self._generated_at,
            "summary": self._summary_dict(),
            "results": [self._result_to_dict(r) for r in self._results],
            "defense_scores": [
                {"layer": s.layer_name, "detections": s.detections,
                 "total": s.total_attacks, "effectiveness": round(s.effectiveness, 4)}
                for s in self._compute_defense_scores()
            ],
            "gaps": [
                {"attack": g.attack_name, "variant": g.attack_variant,
                 "missed_layers": g.missed_layers, "severity": g.severity,
                 "recommendation": g.recommendation}
                for g in self._compute_gaps()
            ],
            "compliance_mapping": self._compliance_dict(),
        }
        return json.dumps(data, indent=2)

    # ------------------------------------------------------------------
    # Markdown section builders
    # ------------------------------------------------------------------

    def _md_header(self) -> str:
        return (
            f"# {self._title}\n\n"
            f"**Generated:** {self._generated_at}  \n"
            f"**Total simulations:** {len(self._results)}"
        )

    def _md_executive_summary(self) -> str:
        s = self._summary_dict()
        return (
            "## Executive Summary\n\n"
            f"| Metric | Value |\n"
            f"|--------|-------|\n"
            f"| Total attacks simulated | {s['total']} |\n"
            f"| Attacks blocked | {s['blocked']} |\n"
            f"| Attacks passed through | {s['passed']} |\n"
            f"| Overall block rate | {s['block_rate']:.1%} |\n"
            f"| Unique attack types | {s['unique_attack_types']} |\n"
            f"| Average detection time | {s['avg_detection_ms']:.2f} ms |"
        )

    def _md_attack_coverage_matrix(self) -> str:
        lines = [
            "## Attack Coverage Matrix\n",
            "| Attack | Variant | Blocked | Layers Triggered | Detection ms |",
            "|--------|---------|---------|-----------------|-------------|",
        ]
        for r in self._results:
            blocked = "YES" if not r.passed_through else "NO"
            layers = ", ".join(r.layers_triggered) if r.layers_triggered else "none"
            lines.append(
                f"| {r.attack_name} | {r.attack_variant} | {blocked} "
                f"| {layers} | {r.detection_time_ms:.2f} |"
            )
        return "\n".join(lines)

    def _md_defense_effectiveness(self) -> str:
        scores = self._compute_defense_scores()
        lines = [
            "## Defense Effectiveness\n",
            "| Layer | Detections | Total | Effectiveness |",
            "|-------|-----------|-------|--------------|",
        ]
        for s in scores:
            lines.append(
                f"| {s.layer_name} | {s.detections} | {s.total_attacks} "
                f"| {s.effectiveness:.1%} |"
            )
        return "\n".join(lines)

    def _md_gap_analysis(self) -> str:
        gaps = self._compute_gaps()
        if not gaps:
            return "## Gap Analysis\n\nNo gaps identified — all attacks were detected."
        lines = [
            "## Gap Analysis\n",
            "| Attack | Variant | Missed Layers | Severity | Recommendation |",
            "|--------|---------|--------------|----------|----------------|",
        ]
        for g in gaps:
            missed = ", ".join(g.missed_layers) if g.missed_layers else "all"
            lines.append(
                f"| {g.attack_name} | {g.attack_variant} | {missed} "
                f"| {g.severity} | {g.recommendation} |"
            )
        return "\n".join(lines)

    def _md_recommendations(self) -> str:
        recs = self._aggregate_recommendations()
        if not recs:
            return "## Recommendations\n\nNo additional recommendations."
        lines = ["## Recommendations\n"]
        for i, rec in enumerate(recs, 1):
            lines.append(f"{i}. {rec}")
        return "\n".join(lines)

    def _md_compliance_mapping(self) -> str:
        mapping = self._compliance_dict()
        lines = ["## Compliance Mapping\n"]
        for framework, articles in mapping.items():
            lines.append(f"### {framework}\n")
            lines.append("| Article | Description | Triggered |")
            lines.append("|---------|-------------|-----------|")
            for article, info in articles.items():
                lines.append(
                    f"| {article} | {info['description']} | "
                    f"{'YES' if info['triggered'] else 'no'} |"
                )
            lines.append("")
        return "\n".join(lines)

    def _md_footer(self) -> str:
        return (
            "---\n\n"
            "*Report generated by DefenseLab Security Report Generator.*"
        )

    # ------------------------------------------------------------------
    # HTML helpers
    # ------------------------------------------------------------------

    def _html_executive_summary(self) -> str:
        s = self._summary_dict()
        return (
            f"<p>Simulated <strong>{s['total']}</strong> attack scenarios. "
            f"<span class='score'>{s['block_rate']:.0%}</span> blocked.</p>"
            f"<ul>"
            f"<li>Blocked: {s['blocked']}</li>"
            f"<li>Passed: {s['passed']}</li>"
            f"<li>Unique attack types: {s['unique_attack_types']}</li>"
            f"<li>Avg detection time: {s['avg_detection_ms']:.2f} ms</li>"
            f"</ul>"
        )

    def _html_results_table(self) -> str:
        rows = []
        for r in self._results:
            cls = "blocked" if not r.passed_through else "passed"
            label = "BLOCKED" if not r.passed_through else "PASSED"
            layers = ", ".join(r.layers_triggered) if r.layers_triggered else "none"
            rows.append(
                f"<tr><td>{r.attack_name}</td><td>{r.attack_variant}</td>"
                f"<td class='{cls}'>{label}</td><td>{layers}</td>"
                f"<td>{r.detection_time_ms:.2f}</td></tr>"
            )
        return (
            "<table><thead><tr><th>Attack</th><th>Variant</th><th>Result</th>"
            "<th>Layers</th><th>Detection ms</th></tr></thead><tbody>"
            + "\n".join(rows)
            + "</tbody></table>"
        )

    def _html_defense_scores(self) -> str:
        scores = self._compute_defense_scores()
        rows = "".join(
            f"<tr><td>{s.layer_name}</td><td>{s.detections}</td>"
            f"<td>{s.total_attacks}</td><td>{s.effectiveness:.1%}</td></tr>"
            for s in scores
        )
        return (
            "<table><thead><tr><th>Layer</th><th>Detections</th>"
            "<th>Total</th><th>Effectiveness</th></tr></thead><tbody>"
            + rows + "</tbody></table>"
        )

    def _html_gap_analysis(self) -> str:
        gaps = self._compute_gaps()
        if not gaps:
            return "<p>No gaps identified.</p>"
        rows = "".join(
            f"<tr><td>{g.attack_name}</td><td>{g.attack_variant}</td>"
            f"<td>{', '.join(g.missed_layers)}</td><td>{g.severity}</td>"
            f"<td>{g.recommendation}</td></tr>"
            for g in gaps
        )
        return (
            "<table><thead><tr><th>Attack</th><th>Variant</th>"
            "<th>Missed Layers</th><th>Severity</th><th>Recommendation</th>"
            "</tr></thead><tbody>" + rows + "</tbody></table>"
        )

    def _html_recommendations(self) -> str:
        recs = self._aggregate_recommendations()
        if not recs:
            return "<p>No additional recommendations.</p>"
        items = "".join(f"<li>{r}</li>" for r in recs)
        return f"<ol>{items}</ol>"

    def _html_compliance(self) -> str:
        mapping = self._compliance_dict()
        parts: list[str] = []
        for framework, articles in mapping.items():
            rows = "".join(
                f"<tr><td>{art}</td><td>{info['description']}</td>"
                f"<td>{'YES' if info['triggered'] else 'no'}</td></tr>"
                for art, info in articles.items()
            )
            parts.append(
                f"<h3>{framework}</h3>"
                f"<table><thead><tr><th>Article</th><th>Description</th>"
                f"<th>Triggered</th></tr></thead><tbody>{rows}</tbody></table>"
            )
        return "\n".join(parts)

    # ------------------------------------------------------------------
    # Computation helpers
    # ------------------------------------------------------------------

    def _summary_dict(self) -> dict[str, Any]:
        total = len(self._results)
        blocked = sum(1 for r in self._results if not r.passed_through)
        passed = total - blocked
        detection_times = [r.detection_time_ms for r in self._results]
        avg_ms = sum(detection_times) / len(detection_times) if detection_times else 0.0
        unique_types = len({r.attack_name for r in self._results})
        return {
            "total": total,
            "blocked": blocked,
            "passed": passed,
            "block_rate": blocked / total if total else 0.0,
            "unique_attack_types": unique_types,
            "avg_detection_ms": avg_ms,
        }

    def _compute_defense_scores(self) -> list[DefenseScore]:
        all_layers = [
            "static_scanner",
            "runtime_monitor",
            "policy_engine",
            "crypto_verification",
        ]
        total = len(self._results)
        scores: list[DefenseScore] = []
        for layer in all_layers:
            detections = sum(
                1 for r in self._results if layer in r.layers_triggered
            )
            scores.append(DefenseScore(layer_name=layer, detections=detections, total_attacks=total))
        return scores

    def _compute_gaps(self) -> list[GapAnalysisEntry]:
        gaps: list[GapAnalysisEntry] = []
        all_layers = {
            "static_scanner",
            "runtime_monitor",
            "policy_engine",
            "crypto_verification",
        }
        for r in self._results:
            if r.passed_through:
                missed = sorted(all_layers - set(r.layers_triggered))
                gaps.append(
                    GapAnalysisEntry(
                        attack_name=r.attack_name,
                        attack_variant=r.attack_variant,
                        missed_layers=missed,
                        severity="HIGH" if not r.layers_triggered else "MEDIUM",
                        recommendation=(
                            f"Enhance detection for {r.attack_name}/{r.attack_variant}. "
                            f"Layers that missed: {', '.join(missed)}."
                        ),
                    )
                )
        return gaps

    def _aggregate_recommendations(self) -> list[str]:
        seen: set[str] = set()
        recs: list[str] = []
        for r in self._results:
            for rec in r.recommendations:
                if rec not in seen:
                    seen.add(rec)
                    recs.append(rec)

        # Add strategic recommendations based on gaps
        gaps = self._compute_gaps()
        if gaps:
            recs.append(
                "Conduct focused hardening on attack variants that bypassed all layers."
            )
        scores = self._compute_defense_scores()
        for s in scores:
            if s.total_attacks > 0 and s.effectiveness < 0.5:
                recs.append(
                    f"Improve {s.layer_name} — current effectiveness is only "
                    f"{s.effectiveness:.0%}."
                )
        return recs

    def _compliance_dict(self) -> dict[str, dict[str, dict[str, Any]]]:
        """Build triggered/untriggered mapping for each compliance article."""
        # Collect all compliance refs mentioned in findings
        triggered_refs: set[str] = set()
        for r in self._results:
            for rec in r.recommendations:
                if "Compliance:" in rec:
                    ref = rec.split("Compliance:")[-1].strip()
                    triggered_refs.add(ref)

        mapping: dict[str, dict[str, dict[str, Any]]] = {}
        for framework, articles in COMPLIANCE_FRAMEWORKS.items():
            mapping[framework] = {}
            for article, description in articles.items():
                triggered = any(article in ref for ref in triggered_refs)
                mapping[framework][article] = {
                    "description": description,
                    "triggered": triggered,
                }
        return mapping

    @staticmethod
    def _result_to_dict(r: SimulationResult) -> dict[str, Any]:
        return {
            "attack_name": r.attack_name,
            "attack_variant": r.attack_variant,
            "layers_triggered": r.layers_triggered,
            "passed_through": r.passed_through,
            "detection_time_ms": r.detection_time_ms,
            "findings": r.findings,
            "recommendations": r.recommendations,
            "crypto_valid": r.crypto_valid,
            "audit_entry_hash": r.audit_entry_hash,
        }
