-- Migration: track how many times a proposal has been sent to the customer
-- Run this in Supabase SQL editor (Dashboard → SQL Editor → New Query)
--
-- HANDOFF.md's versioning rule: reps get up to 5 sends of the same
-- proposal (initial send + revisions); after that, clone into a new
-- proposal rather than keep revising the same record indefinitely.
-- Bruce's pricing edits don't count -- he's the pricing owner.

ALTER TABLE proposals ADD COLUMN IF NOT EXISTS send_count int NOT NULL DEFAULT 0;
