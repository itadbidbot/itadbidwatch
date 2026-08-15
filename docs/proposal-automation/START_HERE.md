# For Claude Code: Start Here

## Before You Code

Read these files in order:

1. **BUILD_PLAN.md** — How the system works (the flow, 4 components, 5 phases)
2. **MVP_CHECKLIST.md** — Detailed tasks for each phase
3. **This file** — Questions to answer before starting

---

## The Simple Flow

```
Rep fills form → Send to Bruce
Bruce adds pricing → Send back to rep
Rep approves → PDF sent to customer
```

That's it. 4 components. 12 days.

---

## Questions Before You Start

**Q: Where do organization/contact lookups come from?**  
A: HubSpot API. Search by name, return address/email/phone.

**Q: Where does the PDF proposal template come from?**  
A: Use the existing Pompton Lakes template: `Pompton_Lakes_Schools_Proposal_7-15-2026.docx`

**Q: Where are proposals stored?**  
A: Cloud storage (Google Drive or AWS S3). Get shareable URL.

**Q: Who can do what?**  
A: Rep submits form + approves proposals. Bruce adds pricing only. Customer views PDF only.

**Q: What if Bruce doesn't add pricing?**  
A: Status stays "Pending pricing". Rep gets reminded after 2 days.

**Q: What if customer doesn't confirm?**  
A: Status stays "Sent". Rep can manually follow up or resend after 5 days.

---

## Your Starting Point

**Phase 1: Form Component (Days 1-2)**

See MVP_CHECKLIST.md for detailed tasks.

Quick summary:
- Build form with org/contact search (HubSpot autocomplete)
- Auto-fill address, city, state, zip from org
- Auto-fill contact email/phone/title from contact
- Add fields: devices (textarea), pickup date (optional), notes (optional)
- Add "Send to Bruce" button
- Save data, send email to Bruce

---

## How to Commit Your Work

After each phase:
1. Push code to GitHub
2. Create GitHub issue: "Phase X complete"
3. Link to PR/commits
4. Wait for feedback

---

## Questions Not Answered Here?

See BUILD_PLAN.md for:
- Technical requirements (HubSpot API, PDF generation, email system)
- All 5 email templates
- Database schema (what to store)
- Testing checklist

---

## Go

Read BUILD_PLAN.md now. Start Phase 1.
