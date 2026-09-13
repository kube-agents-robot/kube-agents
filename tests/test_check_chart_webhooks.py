"""Tests for hack/check_chart_webhooks.py.

    python3 -m unittest discover -s tests -p 'test_check_chart_webhooks.py'

The comparison is exercised on in-memory documents shaped like the two real inputs: the
chart's rendered `operator-webhooks.yaml` and `k8s-operator/config/webhook/{manifests,service}.yaml`.
What matters is that a drift the API server would act on fails and names what moved, and
that differences the check promises to ignore (metadata, service name and namespace,
caBundle, failurePolicy, rule ordering) do not.

The one end-to-end case renders the real chart with `helm` and skips where the binary is
absent; the `python-tests` runner has none, and `make chart-check` in the `validate` job is
where that render runs for real.
"""

from __future__ import annotations

import copy
import importlib.util
import io
import pathlib
import shutil
import sys
import unittest
import unittest.mock
from contextlib import redirect_stderr, redirect_stdout

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
_MODULE_PATH = REPO_ROOT / "hack" / "check_chart_webhooks.py"
_spec = importlib.util.spec_from_file_location("check_chart_webhooks", _MODULE_PATH)
ccw = importlib.util.module_from_spec(_spec)
sys.modules["check_chart_webhooks"] = ccw
_spec.loader.exec_module(ccw)

SYNC_SCRIPT = REPO_ROOT / "hack" / "sync-chart-manifests.sh"
CHART_TEMPLATE = REPO_ROOT / "charts" / "kube-agents" / "templates" / "operator-webhooks.yaml"


def webhook(name, path, operations, **extra):
    hook = {
        "admissionReviewVersions": ["v1"],
        "clientConfig": {
            "service": {"name": "webhook-service", "namespace": "system", "path": path}
        },
        "failurePolicy": "Fail",
        "name": name,
        "rules": [
            {
                "apiGroups": ["kubeagents.x-k8s.io"],
                "apiVersions": ["v1alpha1"],
                "operations": list(operations),
                "resources": ["platformagents"],
            }
        ],
        "sideEffects": "None",
    }
    hook.update(extra)
    return hook


def source_documents():
    """The kustomize side, as config/webhook/manifests.yaml + service.yaml read today."""
    return [
        {
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "MutatingWebhookConfiguration",
            "metadata": {"name": "mutating-webhook-configuration"},
            "webhooks": [
                webhook(
                    "mplatformagent.kb.io",
                    "/mutate-kubeagents-x-k8s-io-v1alpha1-platformagent",
                    ["CREATE", "UPDATE"],
                )
            ],
        },
        {
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "ValidatingWebhookConfiguration",
            "metadata": {"name": "validating-webhook-configuration"},
            "webhooks": [
                webhook(
                    "vplatformagent.kb.io",
                    "/validate-kubeagents-x-k8s-io-v1alpha1-platformagent",
                    ["CREATE", "UPDATE", "DELETE"],
                )
            ],
        },
        {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {"name": "webhook-service", "namespace": "system"},
            "spec": {
                "ports": [{"port": 443, "protocol": "TCP", "targetPort": 10250}],
                "selector": {"control-plane": "controller-manager"},
            },
        },
    ]


def chart_documents():
    """The chart side: same webhooks under release-specific names, plus cert-manager objects."""
    docs = copy.deepcopy(source_documents())
    for doc in docs:
        doc["metadata"] = {
            "name": "chart-check-" + doc["metadata"]["name"],
            "namespace": "default",
            "labels": {"app.kubernetes.io/instance": "chart-check"},
            "annotations": {"cert-manager.io/inject-ca-from": "default/chart-check-serving-cert"},
        }
        for hook in doc.get("webhooks", []):
            hook["clientConfig"]["service"]["name"] = "chart-check-webhook-service"
            hook["clientConfig"]["service"]["namespace"] = "default"
            hook["clientConfig"]["caBundle"] = "Cg=="
            hook["failurePolicy"] = "Ignore"
    docs.append({"apiVersion": "cert-manager.io/v1", "kind": "Issuer", "metadata": {}})
    docs.append({"apiVersion": "cert-manager.io/v1", "kind": "Certificate", "metadata": {}})
    return docs


def validating(docs):
    return next(d for d in docs if d["kind"] == "ValidatingWebhookConfiguration")


def service(docs):
    return next(d for d in docs if d["kind"] == "Service")


class CompareTest(unittest.TestCase):
    def assertDrift(self, drift, *fragments):
        self.assertTrue(drift, "expected a drift report, got none")
        text = "\n".join(drift)
        for fragment in fragments:
            self.assertIn(fragment, text)

    def test_identical_after_ignoring_release_specific_fields(self):
        self.assertEqual(ccw.compare(chart_documents(), source_documents()), [])

    def test_rule_list_order_does_not_matter(self):
        chart = chart_documents()
        rule = validating(chart)["webhooks"][0]["rules"][0]
        rule["operations"] = ["DELETE", "UPDATE", "CREATE"]
        self.assertEqual(ccw.compare(chart, source_documents()), [])

    def test_operation_removed_from_chart_fails_and_names_it(self):
        chart = chart_documents()
        validating(chart)["webhooks"][0]["rules"][0]["operations"].remove("DELETE")
        self.assertDrift(
            ccw.compare(chart, source_documents()),
            "webhook drift: ValidatingWebhookConfiguration/vplatformagent.kb.io",
            '+          "DELETE"',
        )

    def test_operation_removed_from_source_fails_and_names_it(self):
        source = source_documents()
        validating(source)["webhooks"][0]["rules"][0]["operations"].remove("DELETE")
        self.assertDrift(
            ccw.compare(chart_documents(), source),
            "webhook drift: ValidatingWebhookConfiguration/vplatformagent.kb.io",
            '-          "DELETE"',
        )

    def test_path_drift_fails(self):
        chart = chart_documents()
        validating(chart)["webhooks"][0]["clientConfig"]["service"]["path"] = "/validate-old"
        self.assertDrift(
            ccw.compare(chart, source_documents()),
            "vplatformagent.kb.io",
            "/validate-old",
            "/validate-kubeagents-x-k8s-io-v1alpha1-platformagent",
        )

    def test_webhook_missing_on_one_side_fails(self):
        chart = [d for d in chart_documents() if d["kind"] != "ValidatingWebhookConfiguration"]
        self.assertDrift(
            ccw.compare(chart, source_documents()),
            "webhook drift: ValidatingWebhookConfiguration/vplatformagent.kb.io",
        )
        source = [d for d in source_documents() if d["kind"] != "MutatingWebhookConfiguration"]
        self.assertDrift(
            ccw.compare(chart_documents(), source),
            "webhook drift: MutatingWebhookConfiguration/mplatformagent.kb.io",
        )

    def test_extra_webhook_in_a_configuration_fails(self):
        chart = chart_documents()
        validating(chart)["webhooks"].append(
            webhook("extra.kb.io", "/validate-extra", ["CREATE"])
        )
        self.assertDrift(
            ccw.compare(chart, source_documents()),
            "webhook drift: ValidatingWebhookConfiguration/extra.kb.io",
        )

    def test_target_port_drift_fails(self):
        chart = chart_documents()
        service(chart)["spec"]["ports"][0]["targetPort"] = 9443
        self.assertDrift(
            ccw.compare(chart, source_documents()), "webhook drift: Service", "9443", "10250"
        )

    def test_side_effects_and_review_versions_are_compared(self):
        chart = chart_documents()
        validating(chart)["webhooks"][0]["sideEffects"] = "NoneOnDryRun"
        self.assertDrift(ccw.compare(chart, source_documents()), "NoneOnDryRun")
        chart = chart_documents()
        validating(chart)["webhooks"][0]["admissionReviewVersions"] = ["v1", "v1beta1"]
        self.assertDrift(ccw.compare(chart, source_documents()), "v1beta1")

    def test_timeout_set_on_one_side_only_fails(self):
        chart = chart_documents()
        validating(chart)["webhooks"][0]["timeoutSeconds"] = 5
        self.assertDrift(ccw.compare(chart, source_documents()), "timeoutSeconds")
        source = source_documents()
        validating(source)["webhooks"][0]["matchPolicy"] = "Exact"
        self.assertDrift(ccw.compare(chart_documents(), source), "matchPolicy")

    def test_timeout_set_on_both_sides_to_the_same_value_passes(self):
        chart, source = chart_documents(), source_documents()
        validating(chart)["webhooks"][0]["timeoutSeconds"] = 5
        validating(source)["webhooks"][0]["timeoutSeconds"] = 5
        self.assertEqual(ccw.compare(chart, source), [])


class WiringTest(unittest.TestCase):
    """The check only runs if the sync script and the template still point at it."""

    def test_sync_script_runs_the_check_in_check_mode(self):
        script = SYNC_SCRIPT.read_text(encoding="utf-8")
        self.assertIn("hack/check_chart_webhooks.py", script)
        self.assertIn("k8s-operator/config/webhook", script)

    def test_template_comment_names_the_check(self):
        self.assertIn("hack/check_chart_webhooks.py", CHART_TEMPLATE.read_text(encoding="utf-8"))

    def test_source_files_exist(self):
        for path in (ccw.WEBHOOK_SRC, ccw.SERVICE_SRC, ccw.CHART_DIR / ccw.CHART_WEBHOOK_TEMPLATE):
            self.assertTrue(path.is_file(), path)

    def test_source_loads_to_both_webhooks_and_the_service(self):
        """No helm needed for the kustomize side, so its shape is pinned unconditionally."""
        normalised = ccw.normalise(ccw.load_source_documents())
        self.assertEqual(
            sorted(normalised),
            [
                "MutatingWebhookConfiguration/mplatformagent.kb.io",
                "Service",
                "ValidatingWebhookConfiguration/vplatformagent.kb.io",
            ],
        )
        self.assertEqual(normalised["Service"]["ports"], [{"port": 443, "targetPort": 10250}])


class EndToEndTest(unittest.TestCase):
    def test_main_passes_against_the_checked_in_chart(self):
        if shutil.which(ccw.HELM_BINARY) is None:
            self.skipTest("helm not installed")
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = ccw.main()
        self.assertEqual(rc, 0, err.getvalue())
        self.assertIn("matches", out.getvalue())

    def test_missing_helm_exits_with_a_named_message(self):
        with unittest.mock.patch.object(ccw.shutil, "which", return_value=None):
            err = io.StringIO()
            with redirect_stderr(err), self.assertRaises(SystemExit) as raised:
                ccw.render_chart_webhooks()
        self.assertEqual(raised.exception.code, ccw.TOOLING_EXIT_CODE)
        self.assertIn("helm", err.getvalue())


if __name__ == "__main__":
    unittest.main()
