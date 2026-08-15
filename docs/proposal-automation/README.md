# TechReboot Proposal Automation

**Status:** Specification complete. Ready for implementation.

## What This Is
Complete operational blueprint for automating conditional guaranteed buyback proposals from ITAD Bid Watch data (bid → company/contact → equipment list → pricing → proposal generation).

## Quick Navigation
- **Full Spec:** `docs/PROPOSAL_AUTOMATION_BUILD_PLAN.md` (5 parts: workflow, landing page, data model, automation rules, build plan)
- **Start Here:** Part 5A - Minimum Viable Version (4-6 weeks)
- **Tech Stack (MVP):** HubSpot, Google Sheets, Make.com, Google Docs

## For Claude Code
1. Clone this repo
2. Read `docs/PROPOSAL_AUTOMATION_BUILD_PLAN.md` 
3. Follow Part 5A step-by-step (Phases 1-7)
4. Create GitHub issues for each week
5. Commit code back to `src/` folder

## Current Status
- [x] Part 1: Operational Workflow (10 stages)
- [x] Part 2: Landing Page Spec (all form sections)
- [x] Part 3: Data Model (10 objects + HubSpot properties)
- [x] Part 4: Automation Rules (pricing, qualification, proposal generation)
- [x] Part 5: Build Plan (MVP 4-6 weeks, Better 8-12 weeks, Fully Automated 12-16 weeks)
- [ ] Phase 1: HubSpot Setup & Pricing Table
- [ ] Phase 2: Proposal Template & Merge Fields
- [ ] Phase 3: Make.com Workflows
- [ ] Phase 4: Testing
- [ ] Phase 5: Launch

## Key Business Logic (DO NOT SKIP)
- **Turnaround term** is ONE authoritative field — reused in ALL proposal sections (exec summary, timeline, terms)
- **Qualification rules:** Device qualifies for guaranteed buyback ONLY if ALL criteria met (model specific, quantity known, powers on, unlocked, no damage, condition explicit)
- **Pricing exceptions** (servers, networking, AV, category not in pricing table) → Route to Bruce Manssuer
- **Value approvals** (>$15,000) → Route to Michael Stott (VP)

## Questions Before Starting?
See `docs/PROPOSAL_AUTOMATION_BUILD_PLAN.md` Appendix for example data flow (Pompton Lakes Schools).
