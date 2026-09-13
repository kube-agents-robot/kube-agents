#!/usr/bin/env python3
"""Compare the chart's hand-maintained webhook template with k8s-operator/config/webhook.

`hack/sync-chart-manifests.sh` regenerates the chart's CRD, ClusterRole and admission-policy
copies from `k8s-operator/config/`, but `charts/kube-agents/templates/operator-webhooks.yaml`
is written by hand: the chart wraps the same two webhooks in values gates and adds the
cert-manager objects, so a splice would fight the template. This script is the check that
replaces the splice. It renders that one template with `helm template`, loads the kustomize
source (`config/webhook/manifests.yaml` and `service.yaml`), reduces both sides to the
fields the API server acts on, and fails with a unified diff when they differ.

Compared, per configuration kind and webhook `name`: `clientConfig.service.path`, `rules`
(order-insensitive), `sideEffects`, `admissionReviewVersions`, and `matchPolicy` /
`timeoutSeconds` whenever either side sets them. Also the webhook Service's `targetPort`
per `port`. Dropped before comparison: object and webhook metadata, annotations,
`clientConfig.service.name` / `namespace` (release-specific), `caBundle` (injected), and
`failurePolicy` (templated from values; .github/workflows/validate.yml covers it).

A webhook present on one side only is a failure. Nothing is generated.

Run:  python3 hack/check_chart_webhooks.py      (also: make chart-check)
"""

from __future__ import annotations

import difflib
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterable

# Exit codes. Drift is 1; a missing tool or a failed render is 2, so the caller
# (hack/sync-chart-manifests.sh) can tell "the template drifted" from "the check
# could not run" and does not prescribe a hand edit for a missing dependency.
DRIFT_EXIT_CODE = 1
TOOLING_EXIT_CODE = 2

try:
    import yaml
except ImportError:
    print(
        "check_chart_webhooks needs PyYAML: python3 -m pip install pyyaml (or make test-python-deps)",
        file=sys.stderr,
    )
    sys.exit(TOOLING_EXIT_CODE)

REPO_ROOT = Path(__file__).resolve().parent.parent

CHART_DIR = REPO_ROOT / "charts" / "kube-agents"
# Relative to the chart root, the form `--show-only` expects.
CHART_WEBHOOK_TEMPLATE = "templates/operator-webhooks.yaml"
WEBHOOK_SRC = REPO_ROOT / "k8s-operator" / "config" / "webhook" / "manifests.yaml"
SERVICE_SRC = REPO_ROOT / "k8s-operator" / "config" / "webhook" / "service.yaml"

HELM_BINARY = "helm"
HELM_RELEASE_NAME = "chart-check"
# The three harness values are required by the chart's schema; their content does not reach
# the webhook template. Webhooks are off by default in the chart, so the template renders
# nothing without the last --set.
HELM_RENDER_ARGS: tuple[str, ...] = (
    "template",
    HELM_RELEASE_NAME,
    str(CHART_DIR),
    "--set",
    "platformAgent.harness.clusterName=x",
    "--set",
    "platformAgent.harness.location=x",
    "--set",
    "platformAgent.harness.projectId=x",
    "--set",
    "operator.webhooks.enabled=true",
    "--show-only",
    CHART_WEBHOOK_TEMPLATE,
)

WEBHOOK_KINDS: frozenset[str] = frozenset(
    {"MutatingWebhookConfiguration", "ValidatingWebhookConfiguration"}
)
SERVICE_KIND = "Service"
# Key of the Service entry in the normalised structure, alongside the webhook keys.
SERVICE_KEY = "Service"

# Webhook fields copied verbatim when present. `admissionReviewVersions` keeps its order:
# it is a preference list, so a reordering is a real change.
WEBHOOK_FIELDS: tuple[str, ...] = (
    "sideEffects",
    "admissionReviewVersions",
    "matchPolicy",
    "timeoutSeconds",
)
# Rule fields, each a list the API server treats as a set, so each is sorted.
RULE_FIELDS: tuple[str, ...] = ("apiGroups", "apiVersions", "operations", "resources")
PATH_KEY = "path"
RULES_KEY = "rules"
SERVICE_PORTS_KEY = "ports"

DIFF_FROM_LABEL = f"chart ({CHART_WEBHOOK_TEMPLATE}, rendered)"
DIFF_TO_LABEL = "k8s-operator/config/webhook (manifests.yaml + service.yaml)"
JSON_INDENT = 2


def _tooling_failure(message: str) -> None:
    print(message, file=sys.stderr)
    sys.exit(TOOLING_EXIT_CODE)


def render_chart_webhooks() -> str:
    """Render the chart's webhook template, or exit with a one-line reason."""
    helm = shutil.which(HELM_BINARY)
    if helm is None:
        _tooling_failure(
            f"check_chart_webhooks needs {HELM_BINARY} on PATH to render {CHART_WEBHOOK_TEMPLATE}"
        )
    result = subprocess.run(
        [helm, *HELM_RENDER_ARGS], capture_output=True, text=True, check=False
    )
    if result.returncode != 0:
        _tooling_failure(f"helm template failed:\n{result.stderr.strip()}")
    return result.stdout


def load_documents(text: str) -> list[dict[str, Any]]:
    """Every non-empty YAML document in `text`, in order."""
    return [doc for doc in yaml.safe_load_all(text) if isinstance(doc, dict)]


def load_source_documents() -> list[dict[str, Any]]:
    docs: list[dict[str, Any]] = []
    for path in (WEBHOOK_SRC, SERVICE_SRC):
        docs.extend(load_documents(path.read_text(encoding="utf-8")))
    return docs


def _sorted_rule(rule: dict[str, Any]) -> dict[str, Any]:
    return {field: sorted(rule.get(field) or []) for field in RULE_FIELDS}


def _normalise_webhook(webhook: dict[str, Any]) -> dict[str, Any]:
    service = (webhook.get("clientConfig") or {}).get("service") or {}
    rules = [_sorted_rule(rule) for rule in webhook.get(RULES_KEY) or []]
    normalised: dict[str, Any] = {
        PATH_KEY: service.get(PATH_KEY),
        RULES_KEY: sorted(rules, key=lambda rule: json.dumps(rule, sort_keys=True)),
    }
    for field in WEBHOOK_FIELDS:
        if field in webhook:
            normalised[field] = webhook[field]
    return normalised


def _normalise_service(service: dict[str, Any]) -> dict[str, Any]:
    ports = [
        {"port": entry.get("port"), "targetPort": entry.get("targetPort")}
        for entry in (service.get("spec") or {}).get(SERVICE_PORTS_KEY) or []
    ]
    return {SERVICE_PORTS_KEY: sorted(ports, key=lambda entry: str(entry["port"]))}


def normalise(documents: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Reduce webhook configurations and the webhook Service to the compared fields.

    Keys are `<kind>/<webhook name>` for webhooks and `Service` for the Service, so a
    webhook present on one side only shows up as a key the other side lacks.
    """
    normalised: dict[str, Any] = {}
    for doc in documents:
        kind = doc.get("kind")
        if kind in WEBHOOK_KINDS:
            for webhook in doc.get("webhooks") or []:
                normalised[f"{kind}/{webhook.get('name')}"] = _normalise_webhook(webhook)
        elif kind == SERVICE_KIND:
            normalised[SERVICE_KEY] = _normalise_service(doc)
    return normalised


def _dump(structure: dict[str, Any]) -> list[str]:
    return json.dumps(structure, indent=JSON_INDENT, sort_keys=True).splitlines()


def compare(
    chart_documents: Iterable[dict[str, Any]], source_documents: Iterable[dict[str, Any]]
) -> list[str]:
    """Lines describing the drift between the two sides; empty when they agree.

    The first lines name each key that differs; the rest is a unified diff of the two
    normalised structures, chart first, so `+` is what the source has and the chart lacks.
    """
    chart = normalise(chart_documents)
    source = normalise(source_documents)
    if chart == source:
        return []
    drifted = sorted(
        key for key in chart.keys() | source.keys() if chart.get(key) != source.get(key)
    )
    lines = [f"webhook drift: {key}" for key in drifted]
    lines.extend(
        line.rstrip("\n")
        for line in difflib.unified_diff(
            _dump(chart), _dump(source), DIFF_FROM_LABEL, DIFF_TO_LABEL, lineterm=""
        )
    )
    return lines


def main() -> int:
    chart_documents = load_documents(render_chart_webhooks())
    if not normalise(chart_documents):
        _tooling_failure(f"helm rendered no webhook objects from {CHART_WEBHOOK_TEMPLATE}")
    drift = compare(chart_documents, load_source_documents())
    if drift:
        print("\n".join(drift), file=sys.stderr)
        return DRIFT_EXIT_CODE
    print(f"Chart {CHART_WEBHOOK_TEMPLATE} matches k8s-operator/config/webhook.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
