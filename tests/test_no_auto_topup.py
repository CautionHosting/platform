# SPDX-FileCopyrightText: 2025 Caution SEZC
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

from pathlib import Path
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]

# Historical database migrations and ledger entry-type constraints may continue to
# mention auto top-up so existing deployments can migrate and old ledger rows stay
# valid. The broken feature must not be exposed or triggered by active app code.
ALLOWED_PATHS = {
    Path("src/api/migrations/004_metering_tables.sql"),
    Path("src/api/migrations/015_auto_topup.sql"),
    Path("src/api/migrations/022_check_constraints.sql"),
    Path("tests/test_no_auto_topup.py"),
}


class AutoTopupRemovalTest(unittest.TestCase):
    def test_auto_topup_is_not_exposed_or_triggered_by_active_code(self):
        active_mentions = []

        for path in REPO_ROOT.rglob("*"):
            if not path.is_file():
                continue
            rel = path.relative_to(REPO_ROOT)
            if rel.parts[0] in {".git", "target", "node_modules", "caution-cache", "out"}:
                continue
            if len(rel.parts) >= 3 and rel.parts[:3] == ("tests", "e2e", "logs"):
                continue
            if rel in ALLOWED_PATHS:
                continue

            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue

            normalized = text.lower().replace("_", "-").replace(" ", "-")
            if "auto-topup" in normalized or "auto-top-up" in normalized:
                active_mentions.append(str(rel))

        self.assertEqual([], active_mentions)


if __name__ == "__main__":
    unittest.main()
