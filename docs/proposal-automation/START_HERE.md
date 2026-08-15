# For Claude Code: Start Here

## Before You Touch Code

1. **Read the spec (required):**
   - `BUILD_PLAN.md` — Full 5-part operational specification

2. **Know the checklist:**
   - `MVP_CHECKLIST.md` — Phases 1-5, what to build when

3. **Understand the business logic (CRITICAL):**
   - Part 1: 10-stage workflow (bid → proposal → outcome)
   - Part 4: Turnaround term is ONE field reused everywhere
   - Part 4: Qualification rules (device qualifies ONLY if ALL criteria met)
   - Part 5A: MVP tech stack (HubSpot, Google Sheets, Make.com, Google Docs)

## Your Starting Point

**Phase 1 (Week 1):** HubSpot Setup & Data Foundation
- Create HubSpot custom properties (list in Part 5A, "HubSpot Property Setup for MVP")
- Build pricing reference in Google Sheets
- Create HubSpot landing form with field mapping (Part 5A, "Landing Form Field Mapping")

See Part 5A step-by-step for detailed instructions.

## Key Constraints (Don't Skip)

- **Turnaround term:** Must be single field (`turnaround_days`) reused in ALL proposal sections
- **Pricing exceptions:** Devices not in pricing table → Route to Bruce Manssuer
- **Value approvals:** Deals > $15,000 → Route to Michael Stott
- **QA validation:** No proposal generated without passing all checks (Part 4E)

## Questions?

- "Where's the pricing table structure?" → Part 3, Object 9
- "What are merge fields?" → Part 4D, Merge Field Reference
- "How does Make workflow work?" → Part 5A, Phase 3 step-by-step
- "What's the data model?" → Part 3, Objects 1-10

## Next Action

1. Read BUILD_PLAN.md (especially Part 5A)
2. Create GitHub issue for Phase 1
3. Start with HubSpot property creation
4. Commit progress back to this repo
