"""
ArchShield Scanner (PoC)

Runs real HTTP requests against the target app (app/app.py) as different
tenant/role actors, compares actual results to expected policy, and produces
a Trust Boundary report: weighted Tenant Isolation Score, per-boundary
PASS/FAIL results, permission drift per role, and derived findings.

This is not mock data — every number in reports/report.json is computed
from live responses returned by the target app during this run.

Run:
    1) python app/app.py                     (in one terminal)
    2) python scanner/scanner.py             (in another terminal)
"""

import json
import os
import sys
from datetime import datetime, timezone

import requests

BASE_URL = "http://127.0.0.1:5001"
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

WEIGHTS = {"High": 3, "Medium": 2, "Low": 1}


def load_json(path):
    with open(path) as f:
        return json.load(f)


ACTORS = load_json(os.path.join(ROOT, "config", "actors.json"))
EXPECTED_PERMISSIONS = load_json(os.path.join(ROOT, "config", "expected_permissions.json"))

# ---------------------------------------------------------------------------
# Boundary test matrix
# Each test is one (actor, resource, action) probe with a stated expectation.
# ---------------------------------------------------------------------------
BOUNDARY_TESTS = [
    # -- Project Access: Cross-Tenant Access --------------------------------
    {"id": "BT-01", "boundary": "Project Access", "test_type": "Cross-Tenant Access",
     "sensitivity": "Medium", "actor": "t2-designer", "method": "GET",
     "path": "/api/projects/proj1", "expected": "DENY"},
    {"id": "BT-02", "boundary": "Project Access", "test_type": "Cross-Tenant Access",
     "sensitivity": "Medium", "actor": "t1-admin", "method": "GET",
     "path": "/api/projects/proj2", "expected": "DENY"},
    {"id": "BT-03", "boundary": "Project Access", "test_type": "Cross-Tenant Access",
     "sensitivity": "Medium", "actor": "t1-designer", "method": "GET",
     "path": "/api/projects/proj1", "expected": "ALLOW"},  # same-tenant, should succeed

    # -- File Access: Direct Object Reference (IDOR) ------------------------
    {"id": "BT-04", "boundary": "File Access", "test_type": "Direct Object Reference (IDOR)",
     "sensitivity": "High", "actor": "t2-designer", "method": "GET",
     "path": "/api/files/file1", "expected": "DENY"},
    {"id": "BT-05", "boundary": "File Access", "test_type": "Direct Object Reference (IDOR)",
     "sensitivity": "High", "actor": "t1-designer", "method": "GET",
     "path": "/api/files/file2", "expected": "DENY"},
    {"id": "BT-06", "boundary": "File Access", "test_type": "Direct Object Reference (IDOR)",
     "sensitivity": "High", "actor": "t1-admin", "method": "GET",
     "path": "/api/files/file2", "expected": "DENY"},

    # -- Task Access: Cross-Tenant Access ------------------------------------
    {"id": "BT-07", "boundary": "Task Access", "test_type": "Cross-Tenant Access",
     "sensitivity": "Low", "actor": "t2-admin", "method": "GET",
     "path": "/api/tasks/task1", "expected": "DENY"},
    {"id": "BT-08", "boundary": "Task Access", "test_type": "Cross-Tenant Access",
     "sensitivity": "Low", "actor": "t1-designer", "method": "GET",
     "path": "/api/tasks/task2", "expected": "DENY"},

    # -- Workspace Metadata: Cross-Tenant Access -----------------------------
    {"id": "BT-09", "boundary": "Workspace Metadata", "test_type": "Cross-Tenant Access",
     "sensitivity": "Low", "actor": "t1-designer", "method": "GET",
     "path": "/api/workspace/metadata?tenant=tenant2", "expected": "DENY"},
    {"id": "BT-10", "boundary": "Workspace Metadata", "test_type": "Cross-Tenant Access",
     "sensitivity": "Low", "actor": "t2-admin", "method": "GET",
     "path": "/api/workspace/metadata?tenant=tenant1", "expected": "DENY"},

    # -- Admin Action: Cross-Role Access -------------------------------------
    {"id": "BT-11", "boundary": "Admin Action", "test_type": "Cross-Role Access",
     "sensitivity": "High", "actor": "t1-designer", "method": "POST",
     "path": "/api/perform/delete_project", "expected": "DENY"},
    {"id": "BT-12", "boundary": "Admin Action", "test_type": "Cross-Role Access",
     "sensitivity": "High", "actor": "t2-designer", "method": "POST",
     "path": "/api/perform/invite_admin", "expected": "DENY"},
    {"id": "BT-13", "boundary": "Admin Action", "test_type": "Cross-Role Access",
     "sensitivity": "High", "actor": "t1-designer", "method": "POST",
     "path": "/api/perform/export_client_contract", "expected": "DENY"},
    {"id": "BT-14", "boundary": "Admin Action", "test_type": "Cross-Role Access",
     "sensitivity": "High", "actor": "t2-designer", "method": "POST",
     "path": "/api/perform/manage_billing", "expected": "DENY"},
    {"id": "BT-15", "boundary": "Admin Action", "test_type": "Cross-Role Access",
     "sensitivity": "Medium", "actor": "t1-admin", "method": "POST",
     "path": "/api/perform/delete_project", "expected": "ALLOW"},  # admin, should succeed

    # -- API: UI-vs-API Consistency ------------------------------------------
    # "Delete Project" is hidden from the UI for Designers, so the UI never
    # shows this action to them — but that only matters if the backend also
    # blocks it. This tests the backend directly, independent of the UI.
    {"id": "BT-16", "boundary": "API Access", "test_type": "UI-vs-API Consistency",
     "sensitivity": "High", "actor": "t1-designer", "method": "POST",
     "path": "/api/perform/delete_project", "expected": "DENY",
     "note": "Delete Project button is hidden in the UI for Designers"},
    {"id": "BT-17", "boundary": "API Access", "test_type": "UI-vs-API Consistency",
     "sensitivity": "Medium", "actor": "t2-designer", "method": "POST",
     "path": "/api/perform/manage_billing", "expected": "DENY",
     "note": "Billing settings are hidden in the UI for Designers"},
]


def call(actor_token, method, path):
    headers = {"Authorization": f"Bearer {actor_token}"}
    url = BASE_URL + path
    try:
        resp = requests.request(method, url, headers=headers, timeout=5)
        return resp.status_code
    except requests.exceptions.ConnectionError:
        print("\n[ArchShield] ERROR: could not reach the target app at "
              f"{BASE_URL}. Start it first with: python app/app.py\n")
        sys.exit(1)


def run_boundary_tests():
    results = []
    for test in BOUNDARY_TESTS:
        status = call(test["actor"], test["method"], test["path"])
        actual = "ALLOW" if status in (200, 201) else "DENY"
        passed = actual == test["expected"]
        results.append({
            **test,
            "actor_label": ACTORS[test["actor"]]["label"],
            "http_status": status,
            "actual": actual,
            "status": "PASS" if passed else "FAIL",
            "weight": WEIGHTS[test["sensitivity"]],
        })
    return results


def run_drift_check():
    all_actions = sorted({a for role_actions in EXPECTED_PERMISSIONS.values() for a in role_actions}
                          | {"delete_project", "invite_admin", "export_client_contract", "manage_billing"})
    drift_results = []
    role_to_actor = {"Designer": "t1-designer", "Admin": "t1-admin"}

    for role, actor_token in role_to_actor.items():
        expected = set(EXPECTED_PERMISSIONS[role])
        actual_allowed = set()
        for action in all_actions:
            status = call(actor_token, "POST", f"/api/perform/{action}")
            if status in (200, 201):
                actual_allowed.add(action)

        unexpected = sorted(actual_allowed - expected)
        missing = sorted(expected - actual_allowed)
        drift_results.append({
            "role": role,
            "expected_count": len(expected),
            "actual_count": len(actual_allowed),
            "drift": len(actual_allowed) - len(expected),
            "unexpected_permissions": unexpected,
            "missing_permissions": missing,
        })
    return drift_results


def build_trust_boundary_map(boundary_results):
    by_resource = {}
    for r in boundary_results:
        by_resource.setdefault(r["boundary"], {"tested": 0, "protected": 0})
        by_resource[r["boundary"]]["tested"] += 1
        if r["status"] == "PASS":
            by_resource[r["boundary"]]["protected"] += 1

    tree = []
    for resource, counts in by_resource.items():
        tree.append({
            "resource": resource,
            "boundaries_tested": counts["tested"],
            "protected": counts["protected"],
            "status": "Protected" if counts["protected"] == counts["tested"] else "Exposed",
        })
    return tree


def derive_findings(boundary_results):
    findings = []
    for r in boundary_results:
        if r["status"] != "FAIL":
            continue
        severity = "High" if r["weight"] == 3 else ("Medium" if r["weight"] == 2 else "Low")
        findings.append({
            "id": r["id"],
            "title": f"{r['boundary']} Violation — {r['test_type']}",
            "severity": severity,
            "actor": r["actor_label"],
            "path": r["path"],
            "description": (
                f"{r['actor_label']} performed {r['method']} {r['path']} "
                f"and received an unexpected {r['actual']} "
                f"(expected {r['expected']})."
                + (f" {r.get('note')}." if r.get("note") else "")
            ),
        })
    return findings


def compute_score(boundary_results):
    total_weight = sum(r["weight"] for r in boundary_results)
    passed_weight = sum(r["weight"] for r in boundary_results if r["status"] == "PASS")
    score = round((passed_weight / total_weight) * 100, 1) if total_weight else 0.0
    return score, total_weight, passed_weight


def main():
    print("[ArchShield] Running boundary tests against", BASE_URL, "...")
    boundary_results = run_boundary_tests()

    print("[ArchShield] Running permission drift check...")
    drift_results = run_drift_check()

    score, total_weight, passed_weight = compute_score(boundary_results)
    findings = derive_findings(boundary_results)
    trust_map = build_trust_boundary_map(boundary_results)

    violations_found = sum(1 for r in boundary_results if r["status"] == "FAIL")
    roles_with_drift = sum(1 for d in drift_results if d["drift"] != 0)

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "tenant_isolation_score": score,
            "score_formula": "sum(weight of PASSED boundaries) / sum(weight of ALL boundaries) * 100",
            "boundaries_tested": len(boundary_results),
            "violations_found": violations_found,
            "permission_drift_roles": roles_with_drift,
            "total_weight": total_weight,
            "passed_weight": passed_weight,
        },
        "boundary_results": boundary_results,
        "permission_drift": drift_results,
        "trust_boundary_map": trust_map,
        "findings": findings,
    }

    out_path = os.path.join(ROOT, "reports", "report.json")
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(report, f, indent=2)

    print(f"\n[ArchShield] Tenant Isolation Score: {score}%")
    print(f"[ArchShield] Boundaries tested: {len(boundary_results)}  |  Violations found: {violations_found}")
    print(f"[ArchShield] Roles with permission drift: {roles_with_drift}")
    print(f"[ArchShield] Full report written to {out_path}\n")


if __name__ == "__main__":
    main()
