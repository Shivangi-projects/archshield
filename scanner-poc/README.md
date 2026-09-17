# ArchShield Scanner — Proof of Concept

This is a **real, runnable** implementation of the ArchShield methodology —
not mock data. It contains:

1. **`app/app.py`** — a small multi-tenant reference app (2 tenants, 2 roles,
   projects/files/tasks) with 3 deliberately planted, realistic authorization
   bugs:
   - **IDOR** — `/api/files/<id>` checks that you're logged in, but never
     checks that the file belongs to your tenant.
   - **Missing role check** — `delete_project`, `invite_admin`, and
     `export_client_contract` are meant to be Admin-only, but the handler
     never actually checks the caller's role.
   - **UI/API mismatch** — the "Delete Project" button is hidden from
     Designers in a real UI, but the backend doesn't enforce that, so the
     action is still reachable by calling the API directly.

2. **`scanner/scanner.py`** — the ArchShield scanner. It logs in as 4
   different actors (2 tenants × 2 roles), fires 17 real boundary tests and
   a full permission-drift sweep against the running app, and computes:
   - a weighted **Tenant Isolation Score**
   - **PASS/FAIL** per boundary, by test type (Cross-Tenant, Cross-Role,
     IDOR, UI-vs-API Consistency)
   - **Permission drift** per role (expected vs. actually-accessible actions)
   - a derived **Trust Boundary Map** and **Findings** list

3. **`reports/report.json`** — the actual output from a real run. Every
   number in it came from a live HTTP response, not a random generator.

## How to run it yourself

```bash
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install flask requests

# terminal 1
python app/app.py

# terminal 2
python scanner/scanner.py
```

Output is written to `reports/report.json` and a summary is printed to the
console.

## What this run actually found

- **Tenant Isolation Score: 44.7%** (weighted: High=3, Medium=2, Low=1)
- **17 boundaries tested, 7 violations found**
- **3 planted flaws, all caught**: cross-tenant file IDOR, missing role
  checks on 3 Admin actions, and a UI/API enforcement mismatch
- **Permission drift on the Designer role**: expected 12 permissions,
  actually has 15 — the 3 extra (`delete_project`, `invite_admin`,
  `export_client_contract`) are exactly the missing-role-check bug,
  independently confirmed by a completely different test path

## Why the score isn't 94%

The dashboard mockup used 94% as an illustrative target state. This PoC
deliberately ships an app with real bugs so the scanner has something to
find — a 44.7% score with 7 real, explained violations is a stronger proof
of the framework than a clean 94% with nothing to show. Fix the 3 bugs in
`app.py` (add the missing tenant/role checks) and re-run the scanner — the
score should rise toward ~100%, which is itself a good live demo: "watch
the score change as we patch a real vulnerability."

## Mapping to the dashboard UI

`reports/report.json` is shaped so it can be dropped straight into the
ArchShield dashboard in place of the mock data — `summary` maps to the 4
metric cards, `boundary_results` maps to the Validation Results table,
`permission_drift` maps to the Permission Drift view, `trust_boundary_map`
maps to the Trust Boundary Map, and `findings` maps to the Findings panel.
