# TechReboot Proposal Automation: Simple MVP Build Plan

**Status:** Ready to build  
**Timeline:** 12 days (5 phases)  
**Token Budget:** ~150K tokens  
**Scope:** 4 components, 1 workflow, HubSpot integration

---

## The Flow (What Happens)

```
SALES REP
↓ Fills card form (org, contact, devices, notes)
↓ CTA: "Send to Bruce for Pricing"
↓ Email to Bruce with link
↓
BRUCE (in ITAD Bid Watch)
↓ Opens proposal, sees template with rep data
↓ Enters pricing for each device
↓ Enters total qualified value
↓ CTA: "Send Back to Rep"
↓ Email to rep with link
↓
SALES REP (Review)
↓ Opens proposal, sees pricing from Bruce
↓ Reviews pricing and qualified value
↓ CTA: "Approve & Send to Customer"
↓ System generates PDF
↓ Emails:
  • To Bruce: "Proposal for [Company] at [Address], [City], [State], [ZIP]"
             "Contact: [Name] [Email] [Phone]"
             "Approved by [Rep Name] and sent to customer"
  • To Customer: PDF proposal attached
  • To Rep: "Congrats! Proposal sent to [Company]. Track status [here]"
↓
STATUS TRACKING
↓ In ITAD Bid Watch, rep can see:
  • Status: Pending pricing → Review → Approved → Sent
  • Who did what and when
  • Link to HubSpot contact
  • Link to PDF proposal
```

---

## What Claude Code Builds (4 Components)

### COMPONENT 1: Proposal Form
**Location:** ITAD Bid Watch (new tab or modal)  
**User:** Sales reps only  
**Action:** Submit to Bruce

**Fields:**
- Organization name (text input + HubSpot search)
  - On selection, auto-fills: address, city, state, zip, main contact
- Contact name (text input + HubSpot search)
  - On selection, auto-fills: email, phone, title
- Address (auto-filled from org, editable)
- City (auto-filled from org, editable)
- State (auto-filled from org, editable)
- ZIP (auto-filled from org, editable)
- Devices (textarea)
  - Example: "200x ASUS Chromebook C204, 25x Dell Latitude 3120, 200x HP ProBook x360"
- Pickup date (date picker, optional)
- Notes (textarea, optional)
- CTA Button: "Send to Bruce for Pricing"

**On Submit:**
- Create proposal record (status: "Pending pricing")
- Save all data
- Send email to Bruce (see Email section below)
- Show confirmation: "Sent to Bruce. You'll be notified when pricing is ready."

---

### COMPONENT 2: Proposal Proposal Editor
**Location:** ITAD Bid Watch  
**User:** Bruce (editing), Sales Rep (viewing), Customer (viewing PDF)  
**Action:** Add pricing (Bruce), Approve (Rep), View (Customer)

**Read-Only Fields (Pre-filled by rep):**
- Organization name
- Contact (name, email, phone, title)
- Address, city, state, zip
- Device list (formatted nicely)
- Pickup date (if provided)
- Notes (if provided)
- Submitted by: [Rep name]
- Submitted date: [Date/time]

**Bruce's Editable Fields:**
- For each device type:
  - Unit price: $___
  - Quantity: ___
  - Subtotal: (auto-calculated)
- Total qualified value: $___
- CTA: "Send Back to Rep"

**Rep's View (After Bruce adds pricing):**
- All above fields (locked, can't edit)
- Status badge: "Ready for Review"
- CTA: "Approve & Send to Customer"

**Customer's View (PDF):**
- TechReboot branded template (from existing proposal docs)
- All org/contact info
- Device list with pricing
- Total qualified value
- Standard terms & conditions boilerplate
- Signature line

---

### COMPONENT 3: Email Notifications
**Triggered by actions, sent automatically**

**Email 1: Bruce (Pricing Request)**
```
Subject: Pricing Request — [Organization Name]

Hi Bruce,

[Sales Rep Name] submitted a new proposal request for [Organization Name].

Organization: [Organization Name]
Address: [Address], [City], [State] [ZIP]
Contact: [Contact Name] | [Email] | [Phone]
Devices: [Device list]
Pickup: [Date if provided]
Notes: [Any notes]

Please review and add pricing:
[Link to proposal in ITAD Bid Watch]

Thanks,
ITAD Bid Watch
```

**Email 2: Sales Rep (Pricing Ready)**
```
Subject: Pricing Ready — [Organization Name]

Hi [Rep Name],

Bruce has added pricing to your proposal for [Organization Name].

Please review the pricing and confirm:
[Link to proposal in ITAD Bid Watch]

Once approved, it will be sent to [Contact Email].

Thanks,
ITAD Bid Watch
```

**Email 3: Bruce (Proposal Approved & Sent)**
```
Subject: Proposal Approved & Sent — [Organization Name]

Hi Bruce,

[Rep Name] approved and sent the proposal to [Organization Name].

Organization: [Organization Name]
Address: [Address], [City], [State] [ZIP]
Contact: [Contact Name] | [Contact Email] | [Contact Phone]
Approved by: [Rep Name]
Sent: [Date/time]

No action needed. Waiting for customer confirmation.

—
ITAD Bid Watch
```

**Email 4: Customer (Your Proposal)**
```
Subject: Your TechReboot Buyback Proposal — [Organization Name]

Hi [Contact Name],

Attached is your conditional guaranteed buyback proposal.

Organization: [Organization Name]
Address: [Address], [City], [State] [ZIP]
Total Qualified Value: $[Value]
Turnaround: 7 calendar days after pickup

Please review and let us know if you have any questions.

To confirm and schedule pickup, reply to this email or contact:
[Sales Rep Name]
[Rep Email]
[Rep Phone]

Thank you for choosing TechReboot!

—
TechReboot, Inc.
```

**Email 5: Sales Rep (Congratulations)**
```
Subject: Congrats! Proposal Sent — [Organization Name]

Hi [Rep Name],

Your proposal for [Organization Name] has been approved and sent to [Contact Email].

Track status here:
[Link to HubSpot contact record]

Waiting for customer confirmation.

—
ITAD Bid Watch
```

---

### COMPONENT 4: Status Tracking
**Location:** ITAD Bid Watch (table or list view)  
**User:** All (reps, Bruce, admins)

**Columns:**
- Organization name (link to HubSpot)
- Contact name
- Status badge (Pending pricing / Review / Approved / Sent)
- Qualified value (when available)
- Submitted by (rep name)
- Last action (who, when)
- Actions (View proposal, Edit, Delete)

**Activity Timeline (Inside Each Proposal):**
```
[Rep Name] submitted proposal on [Date] at [Time]
  • To: [Organization Name]
  • Devices: [Count]

[Bruce] added pricing on [Date] at [Time]
  • Qualified value: $[Amount]

[Rep Name] approved on [Date] at [Time]
  • Status changed to "Approved"

[System] sent PDF to customer on [Date] at [Time]
  • Email: [Contact Email]
```

---

## Technical Requirements (For Claude Code)

### HubSpot Integration
**API calls needed:**
1. Search companies by name (autocomplete)
   - Return: name, address, city, state, zip, phone
2. Search contacts by name + company (autocomplete)
   - Return: first name, last name, email, phone, title, company_id
3. Create/Update custom properties (status, qualified_value, submitted_by, etc.)
4. Log activities (timeline of actions)

### PDF Generation
**Input:**
- All proposal data (org, contact, devices, pricing, qualified value)
- Use existing TechReboot branded template (from project docs)
- Merge fields: org name, contact info, device table, pricing, total value

**Output:**
- Save PDF to cloud storage (Google Drive or AWS S3)
- Get shareable URL
- Attach to email

**Note:** Use existing template from `Pompton_Lakes_Schools_Proposal_7-15-2026.docx` as reference

### Email System
**Requirements:**
- Send emails programmatically (Gmail API or SendGrid)
- Dynamic content (merge fields)
- PDF attachments
- User notifications (in-app if possible)

### Database/Storage
**What needs to be stored:**
- Proposal records (org, contact, devices, pricing, status)
- Activity log (who did what when)
- PDF URLs
- User roles (rep, Bruce, admin)

**Options:**
- Use existing Supabase project if available
- Or use HubSpot custom objects + Google Drive

---

## Build Phases (12 Days)

### Phase 1: Form Component (Days 1-2)
**Owner:** Claude Code

- Build form with HubSpot autocomplete for org/contact
- Auto-fill address, city, state, zip from org
- Auto-fill contact info from contact record
- Text areas for devices and notes
- Date picker for pickup
- Submit button that creates proposal record
- Confirmation message

**Testing:**
- Search for org, verify auto-fill works
- Search for contact, verify auto-fill works
- Submit form, verify data saved

**Output:**
- Working form in ITAD Bid Watch
- Proposal record created in backend

---

### Phase 2: Proposal Editor (Days 3-5)
**Owner:** Claude Code

- Build template display (read-only fields for rep data)
- Build editable fields for Bruce (pricing)
- Auto-calculate subtotals
- Change status based on who's viewing
- Add buttons:
  - "Send Back to Rep" (Bruce)
  - "Approve & Send to Customer" (Rep)
- Show activity timeline

**Testing:**
- Fill form as rep, submit
- Open as Bruce, add pricing, send back
- Open as rep, verify pricing locked, approve
- Verify status changes throughout

**Output:**
- Working editor/viewer in ITAD Bid Watch
- Proper role-based access (Bruce can edit, rep can only approve)

---

### Phase 3: Email Notifications (Days 6-7)
**Owner:** Claude Code

- Set up email system (Gmail API or SendGrid)
- Build 5 email templates (see Email section above)
- Trigger emails on:
  - Rep submits form → email to Bruce
  - Bruce completes pricing → email to rep
  - Rep approves → emails to Bruce + Customer + Rep
- Verify emails send with correct data

**Testing:**
- Submit form, check Bruce gets email with correct data
- Add pricing, check rep gets email
- Approve, check Bruce, customer, and rep all get emails
- Verify links in emails work

**Output:**
- All 5 emails sending correctly with dynamic content

---

### Phase 4: Status Tracking & History (Days 8-9)
**Owner:** Claude Code

- Build status tracking view (table of all proposals)
- Build activity timeline (inside each proposal)
- Add columns: org, contact, status, value, submitted by, last action
- Add filters (by status, by rep, by date)
- Log every action (rep submit, Bruce pricing, rep approve, email sent)

**Testing:**
- Create proposal, verify appears in table
- Complete workflow, verify timeline shows all actions
- Filter by status, verify filtering works

**Output:**
- Admin/tracking view showing all proposals
- Activity history visible inside each proposal

---

### Phase 5: Testing & Polish (Days 10-12)
**Owner:** Claude Code + You

- End-to-end test with real data (Pompton Lakes example)
- Test error scenarios (missing fields, bad email, etc.)
- Test PDF generation and download
- Test HubSpot integration (org/contact lookup)
- Fix bugs
- Train reps on how to use

**Testing Checklist:**
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
- [ ] Links in emails work

**Output:**
- Live, working system
- Rep training completed
- Ready for go-live

---

## What's NOT Included (On Purpose)

- Auto-pricing lookup (Bruce enters manually)
- Auto-qualification rules (Bruce decides)
- Complex approval routing (simple: submit → Bruce → rep → customer)
- Multi-site pickup logistics (kept simple for MVP)
- Custom compliance language (use standard boilerplate)
- Supabase custom objects (use HubSpot native + Google Drive for files)

---

## Success Metrics

| Metric | Target |
|--------|--------|
| Time to generate & send proposal | <30 min (rep enters form, Bruce adds pricing, rep approves, PDF sent) |
| Email delivery success | 100% |
| PDF quality (all fields present, formatted correctly) | 100% |
| Rep satisfaction | >8/10 ("Easy to use? Saves time?") |
| Proposal acceptance rate | >70% (customers accept & schedule pickup) |

---

## Questions for Claude Code

**Before starting, make sure Code knows:**

1. **Where do org/contact lookups come from?** HubSpot API
2. **Where does PDF template come from?** Existing `Pompton_Lakes_Schools_Proposal_7-15-2026.docx`
3. **Where are proposals stored?** Cloud storage (Google Drive or S3)
4. **Who has access to what?**
   - Rep: submit form, approve proposals
   - Bruce: add pricing, nothing else
   - Customer: view PDF only
5. **What if Bruce doesn't add pricing?** Stay in "Pending pricing" status, rep gets reminder after 2 days (can add manual reminder or auto-email)
6. **What if customer doesn't confirm?** Status stays "Sent", rep can manually follow up or resend after 5 days

---

## Next Steps

1. Claude Code clones repo
2. Reads this file
3. Creates GitHub issues for each phase (5 issues)
4. Starts Phase 1
5. Commits code back to repo after each phase
6. You review, give feedback
7. Phase 5 done → Live

---

**Timeline:** 12 working days  
**Complexity:** Simple (form → editor → email → status tracking)  
**Cost:** ~150K tokens (~$0.45)  
**Go-live:** Ready immediately after Phase 5 (no additional setup needed)
