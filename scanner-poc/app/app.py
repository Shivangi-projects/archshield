"""
ArchShield Test Target — a deliberately small multi-tenant app used ONLY
as a reference target for the ArchShield scanner PoC.

It contains 2 tenants, 2 roles each, and a handful of resources.
Some endpoints are correctly protected; a few have realistic, deliberately
planted authorization flaws (IDOR, missing role check, UI/API mismatch),
so the scanner has real things to find.

Run: python app.py   (serves on http://127.0.0.1:5001)
"""

from flask import Flask, request, jsonify

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Identity: token -> user
# ---------------------------------------------------------------------------
USERS = {
    "t1-admin":    {"user": "admin1",    "tenant": "tenant1", "role": "Admin"},
    "t1-designer": {"user": "designer1", "tenant": "tenant1", "role": "Designer"},
    "t2-admin":    {"user": "admin2",    "tenant": "tenant2", "role": "Admin"},
    "t2-designer": {"user": "designer2", "tenant": "tenant2", "role": "Designer"},
}

TENANTS = {
    "tenant1": {"name": "Acme Architecture"},
    "tenant2": {"name": "Northwind Studio"},
}

# ---------------------------------------------------------------------------
# Resources
# ---------------------------------------------------------------------------
PROJECTS = {
    "proj1": {"tenant": "tenant1", "name": "Riverside Tower"},
    "proj2": {"tenant": "tenant2", "name": "Harbor Pavilion"},
}
FILES = {
    "file1": {"tenant": "tenant1", "project": "proj1", "name": "structural-drawings.dwg"},
    "file2": {"tenant": "tenant2", "project": "proj2", "name": "client-contract.pdf"},
}
TASKS = {
    "task1": {"tenant": "tenant1", "name": "Submit BOQ for review"},
    "task2": {"tenant": "tenant2", "name": "Finalize vendor quote"},
}

# Actions and the role required to perform them (per the INTENDED policy).
# A few are deliberately under-enforced in the handler below to simulate
# realistic authorization bugs.
ACTION_REQUIRED_ROLE = {
    "view_project":            "Designer",
    "view_project_list":       "Designer",
    "view_file":                "Designer",
    "upload_file":              "Designer",
    "download_file":            "Designer",
    "view_task":                "Designer",
    "update_task":              "Designer",
    "create_task":               "Designer",
    "comment_task":              "Designer",
    "view_own_profile":          "Designer",
    "update_own_profile":        "Designer",
    "view_workspace_metadata":   "Designer",
    # Admin-only actions (per the INTENDED policy):
    "delete_project":            "Admin",
    "invite_admin":               "Admin",
    "export_client_contract":     "Admin",
    "manage_billing":             "Admin",
}

# Bug #2: these Admin-only actions are NOT actually role-checked in the
# handler below (only "is the caller authenticated" is checked) — a classic
# privilege-escalation / excessive-permission bug.
ACTIONS_MISSING_ROLE_CHECK = {"delete_project", "invite_admin", "export_client_contract"}


def authed_user():
    auth = request.headers.get("Authorization", "")
    token = auth.replace("Bearer ", "").strip()
    return USERS.get(token)


@app.route("/api/projects/<project_id>", methods=["GET"])
def get_project(project_id):
    """Correctly enforced: tenant ownership is checked."""
    user = authed_user()
    if not user:
        return jsonify({"error": "unauthenticated"}), 401
    project = PROJECTS.get(project_id)
    if not project:
        return jsonify({"error": "not found"}), 404
    if project["tenant"] != user["tenant"]:
        return jsonify({"error": "forbidden"}), 403
    return jsonify(project), 200


@app.route("/api/files/<file_id>", methods=["GET"])
def get_file(file_id):
    """
    Bug #1 (IDOR): checks that the caller is authenticated, but never
    checks that the file belongs to the caller's tenant. Any logged-in
    user from ANY tenant can fetch any file by guessing/incrementing IDs.
    """
    user = authed_user()
    if not user:
        return jsonify({"error": "unauthenticated"}), 401
    file = FILES.get(file_id)
    if not file:
        return jsonify({"error": "not found"}), 404
    # MISSING: tenant ownership check
    return jsonify(file), 200


@app.route("/api/tasks/<task_id>", methods=["GET"])
def get_task(task_id):
    """Correctly enforced: tenant ownership is checked."""
    user = authed_user()
    if not user:
        return jsonify({"error": "unauthenticated"}), 401
    task = TASKS.get(task_id)
    if not task:
        return jsonify({"error": "not found"}), 404
    if task["tenant"] != user["tenant"]:
        return jsonify({"error": "forbidden"}), 403
    return jsonify(task), 200


@app.route("/api/workspace/metadata", methods=["GET"])
def workspace_metadata():
    """Correctly enforced: returns only the caller's own tenant metadata."""
    user = authed_user()
    if not user:
        return jsonify({"error": "unauthenticated"}), 401
    requested_tenant = request.args.get("tenant", user["tenant"])
    if requested_tenant != user["tenant"]:
        return jsonify({"error": "forbidden"}), 403
    return jsonify(TENANTS[requested_tenant]), 200


@app.route("/api/perform/<action>", methods=["POST"])
def perform_action(action):
    """
    Generic action endpoint used for role-based / permission-drift testing.

    Bug #2 + Bug #3 live here:
      - For actions in ACTIONS_MISSING_ROLE_CHECK, the required-role check
        is skipped entirely (privilege escalation / permission drift).
      - "delete_project" is also the UI/API mismatch case: the frontend
        hides the Delete button for Designers, but this endpoint doesn't
        verify role, so a Designer can still call it directly.
    """
    user = authed_user()
    if not user:
        return jsonify({"error": "unauthenticated"}), 401
    if action not in ACTION_REQUIRED_ROLE:
        return jsonify({"error": "unknown action"}), 404

    required_role = ACTION_REQUIRED_ROLE[action]

    if action in ACTIONS_MISSING_ROLE_CHECK:
        # BUG: required_role is never actually checked here.
        return jsonify({"action": action, "result": "executed", "note": "role check missing"}), 200

    if required_role == "Admin" and user["role"] != "Admin":
        return jsonify({"error": "forbidden"}), 403

    return jsonify({"action": action, "result": "executed"}), 200


if __name__ == "__main__":
    app.run(port=5001, debug=False)
