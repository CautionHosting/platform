-- SPDX-FileCopyrightText: 2026 Caution SEZC
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

-- Free-text note an organization keeps on an app (what it is, who owns it).
-- Additive and nullable; IF NOT EXISTS keeps re-runs a no-op
-- (utils/makefile-run-migrations.sh applies every file on each run).
ALTER TABLE compute_resources
  ADD COLUMN IF NOT EXISTS description TEXT;
