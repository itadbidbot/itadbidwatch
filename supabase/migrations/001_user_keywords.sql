-- Migration: user-scoped keywords and sources
-- Run this in Supabase SQL editor (Dashboard → SQL Editor → New Query)

-- ──────────────────────────────────────────────────────────────────────────────
-- 1. Admin helper (used in RLS policies)
-- ──────────────────────────────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION is_admin()
RETURNS boolean
LANGUAGE sql SECURITY DEFINER STABLE
AS $$
  SELECT EXISTS (
    SELECT 1 FROM profiles WHERE id = auth.uid() AND role = 'admin'
  );
$$;

-- ──────────────────────────────────────────────────────────────────────────────
-- 2. keywords table: add user_id column + composite unique indexes
-- ──────────────────────────────────────────────────────────────────────────────
ALTER TABLE keywords ADD COLUMN IF NOT EXISTS user_id uuid REFERENCES auth.users(id) ON DELETE CASCADE;

-- Drop old single-column unique constraint (it may be named differently; both attempts are safe)
ALTER TABLE keywords DROP CONSTRAINT IF EXISTS keywords_pillar_key_key;
ALTER TABLE keywords DROP CONSTRAINT IF EXISTS keywords_pkey_pillar_key;

-- Partial unique index for shared default rows (user_id IS NULL)
CREATE UNIQUE INDEX IF NOT EXISTS keywords_default_uk
  ON keywords(pillar_key)
  WHERE user_id IS NULL;

-- Partial unique index for per-user rows
CREATE UNIQUE INDEX IF NOT EXISTS keywords_user_uk
  ON keywords(user_id, pillar_key)
  WHERE user_id IS NOT NULL;

-- ──────────────────────────────────────────────────────────────────────────────
-- 3. keywords RLS
-- ──────────────────────────────────────────────────────────────────────────────
ALTER TABLE keywords ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS keywords_select  ON keywords;
DROP POLICY IF EXISTS keywords_insert  ON keywords;
DROP POLICY IF EXISTS keywords_update  ON keywords;
DROP POLICY IF EXISTS keywords_delete  ON keywords;

-- Everyone can read defaults (user_id IS NULL) and their own rows
CREATE POLICY keywords_select ON keywords FOR SELECT
  USING (user_id IS NULL OR user_id = auth.uid() OR is_admin());

-- Users insert only rows scoped to themselves; admins can insert anything
CREATE POLICY keywords_insert ON keywords FOR INSERT
  WITH CHECK (user_id = auth.uid() OR is_admin());

-- Users update only their own rows; admins can update defaults too
CREATE POLICY keywords_update ON keywords FOR UPDATE
  USING (user_id = auth.uid() OR is_admin());

-- Users delete only their own rows; admins can delete defaults
CREATE POLICY keywords_delete ON keywords FOR DELETE
  USING (user_id = auth.uid() OR is_admin());

-- ──────────────────────────────────────────────────────────────────────────────
-- 4. sources table: ensure user_id column exists + RLS
-- ──────────────────────────────────────────────────────────────────────────────
ALTER TABLE sources ADD COLUMN IF NOT EXISTS user_id uuid REFERENCES auth.users(id) ON DELETE SET NULL;

ALTER TABLE sources ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS sources_select ON sources;
DROP POLICY IF EXISTS sources_insert ON sources;
DROP POLICY IF EXISTS sources_update ON sources;
DROP POLICY IF EXISTS sources_delete ON sources;

-- Users see only their own sources; admins see all
CREATE POLICY sources_select ON sources FOR SELECT
  USING (user_id = auth.uid() OR is_admin());

CREATE POLICY sources_insert ON sources FOR INSERT
  WITH CHECK (user_id = auth.uid() OR is_admin());

CREATE POLICY sources_update ON sources FOR UPDATE
  USING (user_id = auth.uid() OR is_admin());

CREATE POLICY sources_delete ON sources FOR DELETE
  USING (user_id = auth.uid() OR is_admin());
