-- Migration: link proposals back to the HubSpot company record
-- Run this in Supabase SQL editor (Dashboard → SQL Editor → New Query)
-- Spec: docs/proposal-automation/BUILD_PLAN.md — Phase 4 checklist item
-- "Make org name link to HubSpot contact record"

ALTER TABLE proposals ADD COLUMN IF NOT EXISTS org_hubspot_url text;
