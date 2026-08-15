# Handoff: Build Proposal Feature for ITAD Bid Watch

## Start Here (Read This First)

You are building a "Build Proposal" sidebar feature for ITAD Bid Watch.

## What to Build

4 components over 5 phases (12 days):
1. Form (org/contact/devices/notes)
2. Proposal editor (Bruce prices, rep reviews)
3. Email notifications (5 templates)
4. Status tracking (table + history)

## Key Files

- **Spec:** `/docs/proposal-automation/BUILD_PLAN.md` (THE blueprint)
- **Checklist:** `/docs/proposal-automation/MVP_CHECKLIST.md` (phase tasks)
- **Tech questions:** `/docs/proposal-automation/START_HERE.md`

## Critical Business Rules

- ⚠️ Turnaround term: ONE field, reused everywhere
- ⚠️ Price increase >20%: Show warning, route to Bruce or reduce
- ⚠️ Versions: Track changes (who/what/when), archive after 5, can clone old versions
- ✅ Final version: PDF download only, rep sends via HubSpot
- ✅ Versioning: Max 5 edits, then create new proposal

## How to Start

1. Read `/docs/proposal-automation/BUILD_PLAN.md`
2. Read `/docs/proposal-automation/MVP_CHECKLIST.md`
3. Examine `index.html` for existing tab structure
4. Start Phase 1 (Form component)
5. Create GitHub issues for tracking
6. Test locally in Terminal
7. Commit back to GitHub

## Questions?

See BUILD_PLAN.md Technical Requirements section.
