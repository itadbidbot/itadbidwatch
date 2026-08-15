-- Migration: structured device line items (Qty / Product / Condition)
-- Run this in Supabase SQL editor (Dashboard → SQL Editor → New Query)
--
-- Reps often paste a device list from a spreadsheet rather than typing
-- "200x Chromebook C204" by hand. This stores that as structured rows
-- against the proposal, instead of relying on regex-parsing the raw
-- `devices` text every time it's needed (e.g. by Bruce's pricing editor).
-- `devices` (raw text) is kept as-is for reference/backward compatibility.

ALTER TABLE proposals ADD COLUMN IF NOT EXISTS device_items jsonb;
