# MVP Implementation Checklist

## Phase 1: Form Component (Days 1-2)

- [ ] Build form with fields (org, contact, devices, pickup date, notes)
- [ ] Add HubSpot autocomplete for organization search
- [ ] Add HubSpot autocomplete for contact search
- [ ] Auto-fill address, city, state, zip when org selected
- [ ] Auto-fill contact email, phone, title when contact selected
- [ ] Add "Send to Bruce" button
- [ ] Create proposal record in database
- [ ] Send email to Bruce
- [ ] Show confirmation message to rep

**Testing:**
- [ ] Search org, verify auto-fill works
- [ ] Search contact, verify auto-fill works
- [ ] Submit form, verify data saved
- [ ] Bruce receives email with correct data

**Output:** Working form in ITAD Bid Watch

---

## Phase 2: Proposal Editor (Days 3-5)

- [ ] Build proposal template display (read-only fields from rep)
- [ ] Build editable pricing fields for Bruce
  - [ ] Unit price field for each device type
  - [ ] Quantity field
  - [ ] Auto-calculate subtotals
- [ ] Add total qualified value field (Bruce enters)
- [ ] Build rep view (pricing locked, can't edit)
- [ ] Add "Send Back to Rep" button (Bruce only)
- [ ] Add "Approve & Send to Customer" button (rep only)
- [ ] Show activity timeline
- [ ] Display status badge (Pending, Review, Approved, Sent)

**Testing:**
- [ ] Fill form as rep, submit
- [ ] Open as Bruce, add pricing, send back
- [ ] Open as rep, verify pricing is locked
- [ ] Rep can approve and move to next step
- [ ] Status changes throughout workflow

**Output:** Working editor/viewer in ITAD Bid Watch

---

## Phase 3: Email Notifications (Days 6-7)

- [ ] Set up email system (Gmail API or SendGrid)
- [ ] Build 5 email templates
  - [ ] Email 1: Bruce (pricing request)
  - [ ] Email 2: Rep (pricing ready)
  - [ ] Email 3: Bruce (proposal approved & sent)
  - [ ] Email 4: Customer (your proposal PDF)
  - [ ] Email 5: Rep (congratulations)
- [ ] Trigger emails on correct actions
- [ ] Include dynamic merge fields in emails
- [ ] Attach PDF to customer email
- [ ] Include links to proposals in emails

**Testing:**
- [ ] Submit form, Bruce receives email
- [ ] Bruce adds pricing, rep receives email
- [ ] Rep approves, all 3 emails sent (Bruce, customer, rep)
- [ ] Links in emails work
- [ ] PDF attachment is correct

**Output:** All 5 emails sending with correct data

---

## Phase 4: Status Tracking & History (Days 8-9)

- [ ] Build status tracking view (table of all proposals)
- [ ] Add columns: org name, contact, status, value, submitted by, last action
- [ ] Make org name link to HubSpot contact record
- [ ] Build activity timeline (inside each proposal)
- [ ] Log every action (rep submit, Bruce pricing, rep approve, email sent)
- [ ] Add filters (by status, by rep, by date)
- [ ] Show who did what and when in timeline

**Testing:**
- [ ] Create proposal, verify appears in table
- [ ] Add pricing, verify timeline shows action
- [ ] Approve, verify timeline updates
- [ ] Filter by status, verify filtering works
- [ ] Click org name, verify HubSpot link works

**Output:** Tracking view + activity history working

---

## Phase 5: Testing & Polish (Days 10-12)

- [ ] End-to-end test with real data (Pompton Lakes example)
- [ ] Test form submission
- [ ] Test Bruce adding pricing
- [ ] Test rep approval
- [ ] Test PDF generation and download
- [ ] Test all 5 emails send correctly
- [ ] Test HubSpot integration (org/contact lookups)
- [ ] Test error scenarios (missing fields, invalid email, etc.)
- [ ] Fix bugs found during testing
- [ ] Create training notes for reps

**Full Testing Checklist:**
- [ ] Form submits successfully
- [ ] Email to Bruce received with correct data
- [ ] Bruce can add pricing without errors
- [ ] Email to rep received
- [ ] Rep can approve
- [ ] PDF generated correctly (branded, all fields present)
- [ ] Customer email sent with PDF
- [ ] Rep confirmation email received
- [ ] Status tracking shows all proposals
- [ ] Activity timeline is accurate
- [ ] All links in emails work
- [ ] HubSpot org/contact lookup works

**Output:** Live, working system ready for reps to use

---

## Current Status

- [x] Specification complete (BUILD_PLAN.md)
- [ ] Phase 1 — Form component
- [ ] Phase 2 — Proposal editor
- [ ] Phase 3 — Email notifications
- [ ] Phase 4 — Status tracking
- [ ] Phase 5 — Testing & launch
