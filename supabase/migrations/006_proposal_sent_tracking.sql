-- Migration: track when the customer proposal PDF was actually sent
-- Run this in Supabase SQL editor (Dashboard → SQL Editor → New Query)
--
-- Completes the status lifecycle from BUILD_PLAN.md:
--   pending_pricing -> review -> approved -> sent
-- "approved" means the rep signed off; "sent" means the customer email
-- (with the PDF attached) actually went out. Kept separate so a failed
-- customer email doesn't silently look identical to a successful send --
-- the UI can show "approved but not yet sent" and offer a retry.

ALTER TABLE proposals ADD COLUMN IF NOT EXISTS customer_sent_at timestamptz;
