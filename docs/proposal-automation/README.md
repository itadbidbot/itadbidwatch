# TechReboot Proposal Automation

**Status:** Specification complete. Ready to build.

## What This Does

Sales rep submits proposal request → Bruce adds pricing → Rep approves → PDF sent to customer.

Simple workflow, 4 components, 12 days to build.

## Quick Navigation

- **BUILD_PLAN.md** — How it works, what Claude Code builds (5 phases)
- **MVP_CHECKLIST.md** — Tasks for each phase
- **START_HERE.md** — For Claude Code (read this first)

## The Workflow

```
REP: Fill form (org, contact, devices, notes)
  ↓ Send to Bruce
  ↓
BRUCE: Add pricing
  ↓ Send back to rep
  ↓
REP: Review & approve
  ↓ Generate PDF
  ↓
CUSTOMER: Receives proposal PDF
```

## What Gets Built (4 Components)

1. **Form** — Rep enters org, contact, devices, notes, pickup date
2. **Editor** — Bruce adds pricing, rep reviews and approves
3. **Email** — 5 automated emails (Bruce request, pricing ready, approval, customer PDF, rep confirmation)
4. **Status Tracking** — Table showing all proposals, activity timeline

## For Claude Code

1. Read `BUILD_PLAN.md` (the full spec)
2. Read `MVP_CHECKLIST.md` (what to build each day)
3. Start Phase 1
4. Create GitHub issues for each phase
5. Commit code back to repo

**Timeline:** 12 days  
**Complexity:** Simple  
**Tech:** HubSpot API, Gmail/SendGrid, PDF generation, cloud storage

## Questions?

See `BUILD_PLAN.md` for detailed technical requirements and email templates.
