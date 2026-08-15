-- Migration: proposal pricing/approval workflow (Phase 2 — Proposal Editor)
-- Run this in Supabase SQL editor (Dashboard → SQL Editor → New Query)
-- Spec: docs/proposal-automation/BUILD_PLAN.md — Component 2: Proposal Editor

ALTER TABLE proposals ADD COLUMN IF NOT EXISTS priced_at        timestamptz;
ALTER TABLE proposals ADD COLUMN IF NOT EXISTS priced_by        uuid REFERENCES auth.users(id) ON DELETE SET NULL;
ALTER TABLE proposals ADD COLUMN IF NOT EXISTS priced_by_name   text;
ALTER TABLE proposals ADD COLUMN IF NOT EXISTS priced_by_email  text;

ALTER TABLE proposals ADD COLUMN IF NOT EXISTS approved_at       timestamptz;
ALTER TABLE proposals ADD COLUMN IF NOT EXISTS approved_by       uuid REFERENCES auth.users(id) ON DELETE SET NULL;
ALTER TABLE proposals ADD COLUMN IF NOT EXISTS approved_by_name  text;
ALTER TABLE proposals ADD COLUMN IF NOT EXISTS approved_by_email text;

-- ──────────────────────────────────────────────────────────────────────────────
-- Bruce's pricing access
--
-- The app has no dedicated "pricer" role yet — only user/admin. Until one
-- exists, this mirrors the existing is_admin() pattern with a hardcoded
-- email, matching the frontend's PRICING_EMAIL constant in index.html
-- (BuildProposalPage / ProposalEditorView).
--
-- PLACEHOLDER: itadbidbot@gmail.com was supplied as a stand-in for Bruce's
-- real email. Update BOTH this function and PRICING_EMAIL in index.html
-- when Bruce's real login email is known.
-- ──────────────────────────────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION is_pricer()
RETURNS boolean
LANGUAGE sql SECURITY DEFINER STABLE
AS $$
  SELECT (auth.jwt() ->> 'email') = 'itadbidbot@gmail.com';
$$;

DROP POLICY IF EXISTS proposals_select ON proposals;
DROP POLICY IF EXISTS proposals_update ON proposals;

CREATE POLICY proposals_select ON proposals FOR SELECT
  USING (submitted_by = auth.uid() OR is_admin() OR is_pricer());

CREATE POLICY proposals_update ON proposals FOR UPDATE
  USING (submitted_by = auth.uid() OR is_admin() OR is_pricer());
