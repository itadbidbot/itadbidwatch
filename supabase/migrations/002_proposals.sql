-- Migration: proposals table (TechReboot Proposal Automation — Build Proposal feature)
-- Run this in Supabase SQL editor (Dashboard → SQL Editor → New Query)
-- Spec: docs/proposal-automation/BUILD_PLAN.md

CREATE TABLE IF NOT EXISTS proposals (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),

  -- Organization (Phase 1: from HubSpot company search, editable)
  org_name            text NOT NULL,
  org_hubspot_id      text,
  address             text,
  city                text,
  state               text,
  zip                 text,

  -- Contact (Phase 1: from HubSpot contact search, editable)
  contact_name        text NOT NULL,
  contact_hubspot_id  text,
  contact_email       text,
  contact_phone       text,
  contact_title       text,

  -- Request details (Phase 1)
  devices             text NOT NULL,
  pickup_date         date,
  notes               text,

  -- Workflow status: pending_pricing -> review -> approved -> sent
  status              text NOT NULL DEFAULT 'pending_pricing',

  -- Pricing (Phase 2 — Bruce fills these in; nullable until then)
  pricing             jsonb,
  qualified_value      numeric,
  pdf_url             text,

  -- Submission metadata
  submitted_by         uuid REFERENCES auth.users(id) ON DELETE SET NULL,
  submitted_by_name    text,
  submitted_by_email   text,

  created_at          timestamptz NOT NULL DEFAULT now(),
  updated_at          timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS proposals_status_idx ON proposals(status);
CREATE INDEX IF NOT EXISTS proposals_submitted_by_idx ON proposals(submitted_by);

-- Keep updated_at current on every row change
CREATE OR REPLACE FUNCTION proposals_set_updated_at()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS proposals_updated_at ON proposals;
CREATE TRIGGER proposals_updated_at
  BEFORE UPDATE ON proposals
  FOR EACH ROW EXECUTE FUNCTION proposals_set_updated_at();

-- ──────────────────────────────────────────────────────────────────────────────
-- RLS
-- Phase 1: rep submits + sees their own proposals; admins see everything.
-- Phase 2 will need a Bruce-specific role/policy for pricing access.
-- ──────────────────────────────────────────────────────────────────────────────
ALTER TABLE proposals ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS proposals_select ON proposals;
DROP POLICY IF EXISTS proposals_insert ON proposals;
DROP POLICY IF EXISTS proposals_update ON proposals;
DROP POLICY IF EXISTS proposals_delete ON proposals;

CREATE POLICY proposals_select ON proposals FOR SELECT
  USING (submitted_by = auth.uid() OR is_admin());

CREATE POLICY proposals_insert ON proposals FOR INSERT
  WITH CHECK (submitted_by = auth.uid() OR is_admin());

CREATE POLICY proposals_update ON proposals FOR UPDATE
  USING (submitted_by = auth.uid() OR is_admin());

CREATE POLICY proposals_delete ON proposals FOR DELETE
  USING (submitted_by = auth.uid() OR is_admin());
