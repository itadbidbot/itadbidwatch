# TechReboot ITAD Bid Watch: Proposal Automation Build Plan
## Complete Operational Specification (5 Parts)

**Project Objective:**  
Automate the creation of conditional guaranteed buyback proposals from ITAD Bid Watch data, contact intelligence, equipment lists, and logistics requirements into a structured CRM record, proposal-ready dataset, and generated Tech Reboot buyback proposal.

**Canonical Reference:**  
Pompton Lakes Schools conditional guaranteed buyback proposal (July 14, 2026) — includes all sections, terms, and structure to replicate.

**Critical QA Fix:**  
The Pompton Lakes source docs contained a timeline inconsistency (7 days vs. 14 days turnaround). This build plan establishes one authoritative turnaround field, reused consistently throughout all proposal sections.

---

# PART 1: OPERATIONAL WORKFLOW

## End-to-End Process: From Bid Discovery to Proposal Delivery

```
STAGE 1: BID DISCOVERY & INTAKE
  ↓
STAGE 2: ACCOUNT & CONTACT MATCHING
  ↓
STAGE 3: EQUIPMENT DATA CAPTURE
  ↓
STAGE 4: PRICING & QUALIFICATION
  ↓
STAGE 5: PICKUP & LOGISTICS PLANNING
  ↓
STAGE 6: COMPLIANCE & DATA REQUIREMENTS
  ↓
STAGE 7: INTERNAL REVIEW
  ↓
STAGE 8: PROPOSAL GENERATION
  ↓
STAGE 9: DELIVERY & FOLLOW-UP
  ↓
STAGE 10: OUTCOME TRACKING
```

---

## STAGE 1: BID DISCOVERY & INTAKE

**Trigger:** Bid appears in ITAD Bid Watch, RFP School Watch, or entered via direct inbound/referral.

**Actions:**
1. Bid data captured: title, source URL, bid number, bid due date, platform, institution name, state
2. Source data tagged: `bid_watch`, `direct_inbound`, `referral`, `hubspot_outbound`, `existing_customer`
3. Initial qualification check: Is this a school district, municipality, or institutional buyback opportunity?
   - YES → Proceed to Stage 2
   - NO (e.g., construction, landscaping) → Close with reason, tag as disqualified

**Decision Point 1:**
- Is this organization already in HubSpot?
  - YES → Go to Stage 2 (match contact)
  - NO → Go to Stage 2 (create company record first)

**Outcome:** Bid source record created in system, linked to company (existing or new).

---

## STAGE 2: ACCOUNT & CONTACT MATCHING

**Actions:**
1. **Company/Account Matching:**
   - Match by domain first (extract domain from bid URL or organization website)
   - Match by organization name (exact or fuzzy)
   - Match by HubSpot Company ID if already known
   - If no match → Create new company record with:
     - Organization name
     - Website/domain
     - Organization type (K-12 district, municipality, higher ed, etc.)
     - State
     - Main address

2. **Contact Matching:**
   - Extract contact name, email, phone, title from bid source (if available)
   - Match by email first (exact match in HubSpot)
   - Match by name + company (if email unavailable)
   - If no match → Create new contact record with available details
   - Flag contact as primary decision-maker or secondary (e.g., IT contact vs. procurement lead)

3. **Primary Contact Confirmation:**
   - Is the matched/created contact the decision-maker or a referral?
   - If referral → Use intake form to get primary decision-maker info (see Part 2)
   - If decision-maker → Proceed to Stage 3

**Decision Point 2:**
- Do we have a primary decision-maker email confirmed?
  - YES → Proceed to Stage 3
  - NO → Mark opportunity as "Contact verification needed," schedule follow-up task

**Outcome:** Company and contact records established in HubSpot, linked to bid source and opportunity.

---

## STAGE 3: EQUIPMENT DATA CAPTURE

**Trigger:** Landing page/intake form OR CSV spreadsheet upload of equipment list.

**Actions:**
1. **Intake Method Selection:**
   - Option A: Fill landing page form (repeatable line-item blocks) → Real-time entry
   - Option B: Upload CSV/Excel with device list → Parse and normalize

2. **For Each Equipment Line Item, Capture:**
   - Asset category (Chromebook, laptop, desktop, tablet, iPad, MacBook, monitor, server, networking, AV, charging cart, mixed)
   - Manufacturer (ASUS, Dell, HP, Apple, Lenovo, etc.)
   - Model name and number
   - Generation/year if known
   - Processor/CPU tier if known (i3, i5, i7, M1, M2, etc.)
   - RAM and storage if known
   - Quantity (confirmed, estimated, rough count, unknown)
   - Condition (excellent, good, fair, poor, mixed, unknown)
   - Power-on status (yes, no, mixed, unknown)
   - Locked/MDM status (unlocked, locked, mixed, unknown)
   - Cracked screens? (yes, no, mixed, unknown)
   - Missing components? (yes, no, mixed, unknown)
   - Chargers included? (yes, no, partial, not required, unknown)
   - Cases included? (yes, no, partial, unknown)
   - Asset tags removed? (yes, no, unknown)
   - Serial numbers available? (yes, no, partial, unknown)
   - Photos uploaded? (yes, no)
   - Line-item notes
   - Confidence level in data (high, medium, low)

3. **Data Normalization:**
   - Standardize model names (trim whitespace, correct common misspellings, normalize "C204" vs "Chromebook C204")
   - Map to known device database if possible (e.g., "ASUS Chromebook C204" → category=Chromebook, manufacturer=ASUS, model=C204)
   - Flag models not found in database for manual review
   - Ensure quantity is numeric
   - Parse condition into a 5-point scale (1=poor, 5=excellent)

**Decision Point 3:**
- Are device models specific enough to price?
  - YES (e.g., "Dell Latitude 3120 Laptop, i5") → Proceed to Stage 4
  - NO (e.g., "mixed electronics, condition unknown") → Flag for review, continue

- Are quantities reliable?
  - YES (confirmed count or counted photo) → Use as-is
  - NO (estimated, rough count) → Flag confidence, calculate range pricing

**Outcome:** Structured equipment line items created, linked to opportunity.

---

## STAGE 4: PRICING & QUALIFICATION

**Trigger:** Equipment line items captured.

**Actions:**
1. **Apply Pricing Rules:**
   - For each line item, match to pricing table by:
     - Asset category
     - Manufacturer
     - Model
     - CPU generation (if applicable)
     - Condition score
     - Locked/unlocked status
   - Retrieve unit buyback price from pricing table (or mark "requires review")
   - Calculate projected subtotal = quantity × unit price
   - Separate into three buckets:
     - **Guaranteed Buyback** (meets all qualification criteria)
     - **Review Required** (missing key info, ambiguous condition, locked status unclear)
     - **Recycling Value Only** (damaged, incomplete, locked, etc.)

2. **Apply Qualification Rules:**
   A device qualifies for guaranteed buyback pricing only when **ALL** are true:
   - Model is represented clearly enough to match pricing table
   - Quantity is known or estimated with documented confidence
   - Device powers on (or is reasonably assumed functional based on condition)
   - Device is unlocked (or unlock status is confirmed)
   - No severe damage is represented (cracked screens, missing major components)
   - No missing functional components (keys, hinges, ports)
   - Condition assumptions are explicit (not "unknown")

   If ANY criterion is missing/unknown:
   - Line item moves to **Review Required** or **Recycling Value**
   - Flag with specific reason (e.g., "model too generic," "condition unknown," "unlock status unclear")
   - Do NOT silently default to worst-case recycling value

3. **Calculate Totals:**
   - **Guaranteed Qualifying Subtotal** = sum of all guaranteed buyback line items
   - **Review Required Subtotal** = sum of line items needing review (show as range if applicable)
   - **Recycling-Only Subtotal** = sum of non-qualifying items (or leave blank if no pricing applied yet)
   - **Projected Total Qualifying Value** = Guaranteed + (midpoint of Review Required range if available)

**Decision Point 4:**
- Is the qualifying value > $0?
  - YES → Proceed to Stage 5
  - NO (recycling only, no buyback value) → Route to Bruce for disposal pricing, or close as low-value opportunity

- Does any line item require Bruce exception pricing?
  - YES (e.g., servers, networking, AV gear, category not in pricing table) → Flag for Stage 7
  - NO → Proceed to Stage 5

**Outcome:** Pricing applied, qualification status assigned, subtotals calculated.

---

## STAGE 5: PICKUP & LOGISTICS PLANNING

**Trigger:** Equipment data confirmed, pricing estimated.

**Actions:**
1. **Pickup Location Capture:**
   - Primary pickup address (from company record or form)
   - Is this a single-site or multi-site pickup?
     - Single site → Use address as-is
     - Multi-site → Capture separate location for each site, estimate separate pickup dates if needed
   - Loading access details:
     - Dock available? (yes, no, unknown)
     - Elevator access? (yes, no, stairs only)
     - Pallet jack/forklift available on-site? (yes, no, unknown)
   - Are items already boxed/palletized? (yes, no, partially)
   - Are charging carts included? (yes, no, unknown)
   - Preferred pickup window (date range, time of day)
   - Special access instructions (security, contact procedure, parking, building access)

2. **Estimate Logistics Requirements:**
   - Estimate pallet count based on item types and quantities
   - Estimate number of pallets/boxes needed for transport
   - Flag if multi-site pickup requires multiple trips
   - Estimate labor hours based on item count and access complexity
   - Identify any special handling (servers, delicate equipment, hazmat-adjacent items like batteries)

3. **Capture Turnaround & Service Terms:**
   - **Authoritative Turnaround Field:** Select ONE from: 7 days, 14 days, 21 days, custom
   - This single field is reused in ALL proposal sections (executive offer, timeline, commercial terms)
   - Confirm white-glove service included? (yes, no, review required)
   - Confirm data destruction / certification required? (yes, no)
   - Confirm itemized reconciliation report required? (yes, no)

**Decision Point 5:**
- Can this be picked up in one trip?
  - YES → Proceed to Stage 6
  - NO (multi-site, special handling required) → Flag for logistics review, may require quote adjustment

- Is the turnaround term selected and documented?
  - YES → Embed in all downstream proposal sections
  - NO → Default to 7 days, flag for rep confirmation

**Outcome:** Pickup location, logistics requirements, and turnaround term captured and validated.

---

## STAGE 6: COMPLIANCE & DATA REQUIREMENTS

**Trigger:** Equipment and logistics confirmed.

**Actions:**
1. **Capture Data Security Requirements:**
   - Is data-bearing equipment included? (yes, no, unknown)
     - If YES → Proceed with compliance capture
     - If NO (display-only devices, purely mechanical) → Mark as "no data security required," skip to Stage 7
   - Required data process: Data sanitization, physical destruction, recycling only, unknown
   - Required standard: NIST 800-88, NAID, certificate only, district-specific, unknown
   - Certificate of Data Destruction required? (yes, no)
   - Certificate of Recycling required? (yes, no)
   - Serialized/itemized reporting required? (yes, no)
   - Chain-of-custody receipt required? (yes, no)

2. **Capture Special Compliance / Indemnification:**
   - Special compliance requirements: FERPA, HIPAA, CJIS, internal policy, state regulations, unknown
   - Does client require indemnification language? (yes, no, unknown)
   - Does client require insurance documentation / certificate of insurance? (yes, no, unknown)

3. **Map to Proposal Language:**
   - Store these selections as structured fields (not free text)
   - Proposal generator will auto-populate the appropriate boilerplate sections
   - Example: If "NAIT 800-88" + "Certificate of Data Destruction" selected → Include NIST language + CDD section in proposal

**Decision Point 6:**
- Do compliance requirements exceed TechReboot's standard offerings?
  - YES (e.g., specialized HIPAA handling, state-specific data law) → Flag for Bruce review
  - NO → Proceed to Stage 7

**Outcome:** Compliance and data destruction requirements documented, mapped to proposal sections.

---

## STAGE 7: INTERNAL REVIEW

**Trigger:** All previous stages complete, opportunity ready for proposal generation.

**Actions:**
1. **Internal Validation Checklist:**
   - ✅ Company name present
   - ✅ Primary contact confirmed (name, email, phone, title)
   - ✅ Pickup address confirmed
   - ✅ At least one equipment line item with quantity > 0
   - ✅ Turnaround term selected (7/14/21 days)
   - ✅ Projected qualifying value > $0 (or explicitly recycling-only)
   - ✅ No internal contradictions (e.g., "no data security" selected but devices have SSD)
   - ✅ Any Review Required items flagged and explained

2. **Auto-Generated Review Tasks:**
   - **Pricing Approval Needed?** If Review Required subtotal > $X (e.g., > $2,000) → Create task for Bruce
   - **Exception Pricing?** If category not in pricing table (servers, networking, AV) → Create task for Bruce
   - **Management Approval?** If Projected Qualifying Value > $Y (e.g., > $15,000) → Create task for Michael Stott (VP)
   - **Compliance Review?** If special compliance flags raised → Create task for legal/compliance

3. **Risk Flags (Auto-Detected):**
   - ⚠️ "Quantity estimated, not confirmed" → Follow-up verification recommended
   - ⚠️ "Condition unknown for N devices" → Warehouse inspection may reduce value
   - ⚠️ "Turnaround term not confirmed" → Default to 7 days, rep should verify
   - ⚠️ "Multi-site pickup" → Logistics may be more complex/costly
   - ⚠️ "Mixed equipment, low confidence" → Suggest direct contact for clarification
   - ⚠️ "No contact confirmation" → Proposal should not be sent until contact validated

4. **Approval Decision:**
   - **Approve & Proceed to Generation** → All checkboxes passed, no unresolved flags
   - **Approve with Conditions** → Flag noted, approver accepts risk, proceed
   - **Request Changes** → Reassign back to data capture stage, request specific clarifications
   - **Route to Exception Workflow** → Pricing, compliance, or logistics requires special handling; route to Bruce or reviewer

**Decision Point 7:**
- Are all QA checks passed?
  - YES → Proceed to Stage 8 (generate proposal)
  - NO → Route back to appropriate stage for correction
  
- Does this opportunity need management approval?
  - YES → Create approval task, wait for response before Stage 8
  - NO → Auto-proceed to Stage 8

**Outcome:** Opportunity validated, risk flags documented, approvals obtained (if required).

---

## STAGE 8: PROPOSAL GENERATION

**Trigger:** Internal review passed, all approvals obtained.

**Actions:**
1. **Generate Proposal Document:**
   - Use proposal template with dynamic field population
   - Sections auto-populated from opportunity record:
     - Prepared for / Prepared by (organization, contact, tech reboot rep)
     - Executive offer (turnaround term from Stage 5)
     - Projected qualifying value (from Stage 4)
     - Client-specific turnaround (SINGLE AUTHORITATIVE VALUE from Stage 5)
     - Guaranteed rates for qualifying devices (from Stage 4, all qualified line items)
     - Pricing basis (standard template)
     - Included white-glove service (template + any client-specific exceptions)
     - Process and timeline (populated with turnaround term)
     - Commercial terms and assumptions (standard template + any flagged exceptions)
     - Why TechReboot (standard boilerplate)
     - Acceptance / signature block (organization name, contact name/title, preparer signature line)

2. **Generate Email Draft:**
   - Auto-populate email template:
     - To: Primary contact email
     - CC: Sales rep (optional)
     - Subject: "Conditional Guaranteed Buyback Proposal — [Organization Name] | [Turnaround Term] Turnaround"
     - Body: Executive summary (value, device count, turnaround, next steps)
     - Attachment: Proposal PDF or DOCX
   - Tone: Professional, action-oriented, clear next steps

3. **Generate CRM Record Linkage:**
   - Create/update HubSpot deal record:
     - Deal name: "[Organization] — Conditional Buyback | $[Value]"
     - Deal stage: "Proposal Sent"
     - Deal value: Projected Qualifying Value
     - Associated company: Company record from Stage 2
     - Associated contact: Primary contact from Stage 2
     - Custom fields:
       - Turnaround term
       - Equipment count
       - Projected qualifying value
       - Pickup location
       - Compliance requirements
       - Data source (bid_watch, direct, referral, etc.)
       - Proposal ID / document URL

**Decision Point 8:**
- Should the proposal be sent automatically?
  - YES (low-touch, high confidence) → Auto-send email, set next action task
  - NO (high-value, needs contact verification) → Generate proposal, queue for manual review before send

**Outcome:** Proposal document generated, email draft created, HubSpot deal record updated, ready for delivery.

---

## STAGE 9: DELIVERY & FOLLOW-UP

**Trigger:** Proposal generated, approved for delivery.

**Actions:**
1. **Send Proposal:**
   - Send email to primary contact with proposal attachment
   - Log email send in HubSpot activity
   - Mark deal stage as "Proposal Sent"
   - Set send timestamp

2. **Generate Follow-Up Task:**
   - Create task: "Follow up on [Organization] proposal"
   - Due date: 5 business days after send (or custom if rep specifies)
   - Task owner: Sales rep
   - Task description: "Check for questions, propose pickup date, confirm acceptance"
   - Template response options:
     - "Proposal accepted, needs adjustment to terms"
     - "Needs to discuss with committee/board"
     - "Concerned about value, wants to discuss"
     - "Ready to schedule pickup"
     - "No interest, moving forward with competitor"

3. **Set Up Automatic Escalation:**
   - If no response within 7 days → Auto-generate reminder task
   - If no response within 14 days → Auto-escalate to manager

**Outcome:** Proposal delivered, follow-up task scheduled, HubSpot deal moved to "Proposal Sent" stage.

---

## STAGE 10: OUTCOME TRACKING

**Trigger:** Response received or follow-up task completed.

**Actions:**
1. **Log Outcome:**
   - Outcome options:
     - **Accepted** → Proceed to pickup scheduling, set deal stage to "Negotiation"
     - **Accepted with Changes** → Capture requested changes, regenerate proposal, loop to Stage 8
     - **Declined** → Log reason, set deal stage to "Closed Lost," add reason to notes
     - **Stalled/On Hold** → Set deal stage to "On Hold," set follow-up date
     - **Closed Won** → Pickup completed, payment received, reconciliation report sent → Set deal stage to "Closed Won"
     - **Closed Lost** → No further action → Set deal stage to "Closed Lost"

2. **Update HubSpot Deal:**
   - Change deal stage based on outcome
   - Update deal status notes
   - Log all communication in activity timeline
   - Attach any follow-up emails, counterproposals, or agreements

3. **Reporting:**
   - Track proposal conversion rate (sent → accepted)
   - Track average value per opportunity
   - Track turnaround time from bid discovery to pickup
   - Monitor which device categories convert best
   - Flag opportunities stalled >30 days for review

**Outcome:** Final outcome recorded in HubSpot, deal closed or advanced, reporting updated.

---

## WORKFLOW SUMMARY TABLE

| Stage | Input | Process | Output | Decision Point |
|-------|-------|---------|--------|-----------------|
| 1 | Bid URL | Capture bid source, institution, state | Bid source record | Institutional buyer? |
| 2 | Bid source | Match/create company & contact in HubSpot | Company + contact record | Decision-maker confirmed? |
| 3 | Intake form or CSV | Normalize equipment data | Line items with specs | Models specific enough? |
| 4 | Line items | Apply pricing table, qualify devices | Subtotals by category | Value > $0? |
| 5 | Equipment + pricing | Capture pickup location, turnaround | Pickup + logistics plan | Single-site pickup? |
| 6 | Logistics | Capture data security, compliance | Compliance flags | Exceeds standard? |
| 7 | All data + flags | Validate, check QA, get approvals | Validated opportunity | All checks pass? |
| 8 | Validated data | Generate proposal, email, deal record | Proposal document + CRM record | Ready to send? |
| 9 | Generated proposal | Send email, schedule follow-up | Sent proposal + task | Auto-send or manual? |
| 10 | Response received | Log outcome, update deal | Closed deal or next action | Accepted/declined/stalled? |

---

# PART 2: LANDING PAGE & INTAKE FORM REQUIREMENTS

## Landing Page Goal

Allow either a Tech Reboot sales rep **or** a qualified external district contact to submit enough information to generate a conditional buyback proposal, or route the opportunity for specialist review.

Landing page should support both:
- **Internal rep flow:** Quick capture of bid data + equipment list, trigger immediate review
- **External district flow:** Self-service form to submit surplus equipment for quote

---

## LANDING PAGE STRUCTURE

### SECTION A: ORGANIZATION INFORMATION

**Purpose:** Establish which school/district/municipality this is.

| Field | Type | Required | Example | Validation |
|-------|------|----------|---------|------------|
| Organization Name | Text | YES | "Pompton Lakes Schools" | Non-empty, trim whitespace |
| Organization Type | Dropdown | YES | "K-12 District" | Enum: K-12 district, charter school, higher ed, municipality, county, government agency, enterprise, other |
| Website / Domain | Text | NO | "www.plps.org" | Valid domain format |
| Main Address | Text | YES | "237 Van Ave, Pompton Lakes, NJ 07442" | Standard address parsing |
| City | Text | YES | "Pompton Lakes" | Non-empty |
| State | Text (2-char) | YES | "NJ" | Valid US state code |
| ZIP Code | Text | YES | "07442" | 5-digit US ZIP |
| Number of Pickup Locations | Radio | YES | "1" / "2+" | If "2+", show location add button |

**Multi-Site Support:**
- If "2+" selected → Show "Add Pickup Location" button
- Each location captures:
  - Address
  - City, State, ZIP
  - Building name / site designation
  - Contact person at this site (name, phone, email)
  - Access instructions for this site

**Pickup Access Details (conditional, appears if 1+ location entered):**

| Field | Type | Required | Example | Validation |
|-------|------|----------|---------|------------|
| Loading Dock Available? | Radio | YES | "Yes" / "No" / "Unknown" | Affects logistics estimate |
| Elevator Access? | Radio | YES | "Yes" / "Stairs only" / "Unknown" | Affects labor estimate |
| Pallet Jack / Forklift On-Site? | Radio | YES | "Yes" / "No" / "Unknown" | Affects packing needs |
| Items Already Boxed / Palletized? | Radio | YES | "Yes" / "No" / "Partially" / "Unknown" | Affects labor and pallet estimate |
| Charging Carts Included? | Radio | YES | "Yes" / "No" / "Unknown" | Captured separately in pricing |
| Preferred Pickup Window | Date range + time | NO | "Week of July 20" / "After 2 PM" | Free text, non-binding |
| Special Access / Loading Notes | Textarea | NO | "Use side entrance, parking lot A, call ahead" | Max 500 chars |

---

### SECTION B: PRIMARY CONTACT INFORMATION

**Purpose:** Identify decision-maker for proposal and follow-up.

| Field | Type | Required | Example | Validation |
|-------|------|----------|---------|------------|
| First Name | Text | YES | "John" | Non-empty, trim |
| Last Name | Text | YES | "Briggs" | Non-empty, trim |
| Title / Job Role | Text | YES | "Technology Director" | Non-empty, trim |
| Email | Email | YES | "jbriggs@plps.org" | Valid email format, checked for duplicates in HubSpot |
| Phone | Phone | YES | "(973) 835-7100" | US phone format, strip to digits for matching |
| Extension | Text | NO | "1552" | Numeric only |
| Role in Process | Dropdown | YES | "IT/Technology" | Enum: IT/Technology, Procurement, Finance, Operations, Facilities, Superintendent/Admin, Other |
| Is This the Decision-Maker? | Radio | YES | "Yes" / "No" / "Not sure" | If "No," prompt for decision-maker info below |

**If "No" or "Not sure" to decision-maker:**

| Field | Type | Required | Example |
|-------|------|----------|---------|
| Decision-Maker First Name | Text | Conditional | "Jane" |
| Decision-Maker Last Name | Text | Conditional | "Smith" |
| Decision-Maker Title | Text | Conditional | "Superintendent" |
| Decision-Maker Email | Email | Conditional | "jsmith@plps.org" |
| Decision-Maker Phone | Phone | Conditional | "(973) 835-7100" |
| How Should We Contact Them? | Radio | Conditional | "Email" / "Phone" / "Both" |

**Additional Contacts (repeatable):**
- "Add Another Contact" button
- Captures: name, title, email, phone, role (e.g., "Finance Contact," "Facilities Contact")

**Preferred Communication Method:**
- Radio: "Email" / "Phone" / "Both" / "Coordinator will contact you"

---

### SECTION C: BID / ITAD BID WATCH SOURCE DATA

**Purpose:** Link opportunity back to source bid or inbound lead.

| Field | Type | Required | Example | Validation |
|-------|------|----------|---------|------------|
| How Did You Hear About Us? | Dropdown | YES | "ITAD Bid Watch" | Enum: ITAD Bid Watch, RFP School Watch, Direct inbound, HubSpot outbound, Referral, Website form, Existing customer, Other |
| Bid Title | Text | NO | "2026 Technology Refresh" | Max 200 chars |
| Bid Number / ID | Text | NO | "RFP-2026-07-015" | Max 50 chars |
| Bid Platform | Text | NO | "BonFire" | Enum: BonFire, PlanetBids, BidNetDirect, district portal, state portal, other |
| Bid / Source URL | URL | NO | "https://bidnetdirect.com/bids/..." | Valid URL format |
| Bid Due Date | Date | NO | "2026-07-21" | ISO format |
| Bid Awarded? | Radio | NO | "Yes" / "No" / "Unknown" | Indicates buyer urgency |
| Is This an Active Buying Event? | Radio | NO | "Yes" / "No" / "Unknown" | Affects follow-up timing |
| Disposition Method Currently Used | Dropdown | NO | "Auction" | Enum: Auction, Recycler, ITAD vendor, Internal handling, Storage, Unknown |
| Current Vendor Name (if applicable) | Text | NO | "GreenCycle Recycling" | Competitor tracking |
| Sales Status / Lead Stage | Dropdown | NO | "Active prospect" | Auto-mapped from HubSpot if company exists |

**Notes from Bid Source:**
- Textarea | NO | "District is looking to move 200 Chromebooks + 50 laptops within 30 days" | Max 1000 chars

---

### SECTION D: EQUIPMENT / ASSET LINE ITEMS

**Purpose:** Capture complete device inventory with pricing-relevant details.

**UI Pattern:** Repeatable card block ("Add Another Item" button)

**For Each Line Item:**

| Field | Type | Required | Example | Validation | Affects Pricing |
|-------|------|----------|---------|------------|---|
| Asset Category | Dropdown | YES | "Laptop" | Enum: Chromebook, Laptop, Desktop, Tablet, iPad, MacBook, Monitor, Server, Networking, AV/Smartboard, Charging cart, Mixed electronics, Other | YES |
| Manufacturer | Dropdown (searchable) | YES | "Dell" | Auto-complete from known manufacturers | YES |
| Model Name | Text | YES | "Latitude 3120" | Non-empty, max 100 chars | YES |
| Model Number (Optional) | Text | NO | "3120" | Max 50 chars | NO |
| Generation / Year | Text | NO | "2021" | Numeric, 4 digits | YES (for CPU tier) |
| Processor / CPU Tier | Dropdown | NO | "i5" | Enum: i3, i5, i7, i9, M1, M2, M3, Ryzen 3/5/7, other | YES |
| RAM | Text | NO | "8GB" | Format: number + GB/TB | NO (informational) |
| Storage | Text | NO | "256GB SSD" | Format: number + GB/TB + storage type | NO (informational) |
| **Quantity** | Number | YES | "25" | Integer > 0, required for pricing | YES |
| Quantity Type | Radio | YES | "Confirmed" | Enum: Confirmed, Estimated, Rough count, Unknown | Affects confidence score |
| **Condition** | Radio | YES | "Good" | Enum: Excellent, Good, Fair, Poor, Mixed, Unknown | YES |
| **Power-On Status** | Radio | YES | "Yes" | Enum: Yes, No, Mixed, Unknown | YES |
| **Locked/MDM Status** | Radio | YES | "Unlocked" | Enum: Unlocked, Locked, Mixed, Unknown | YES |
| Cracked Screens? | Radio | YES | "No" | Enum: Yes, No, Mixed, Unknown | YES (condition modifier) |
| Missing Keys / Components? | Radio | YES | "No" | Enum: Yes, No, Mixed, Unknown | YES (disqualifies) |
| Chargers Included? | Radio | YES | "Yes" | Enum: Yes, No, Partial, Not required, Unknown | NO (affects logistics) |
| Cases Included? | Radio | YES | "No" | Enum: Yes, No, Partial, Unknown | NO (affects logistics) |
| Asset Tags Removed? | Radio | NO | "Yes" | Enum: Yes, No, Unknown | NO (informational) |
| Serial Numbers Available? | Radio | NO | "Partial" | Enum: Yes, No, Partial, Unknown | NO (affects reconciliation effort) |
| Photos Uploaded? | File upload (multi) | NO | [image.jpg] | JPEG/PNG, max 5MB each | NO |
| **Line Item Notes** | Textarea | NO | "Devices are in good condition, currently in student use, ready for pickup end of July" | Max 500 chars | NO |
| **Confidence Level** | Radio | YES | "High" | Enum: High, Medium, Low | Affects qualification |

**For Each Line Item — Auto-Calculated Fields (Read-Only):**

| Field | Logic | Example |
|-------|-------|---------|
| **Pricing Status** | Match to pricing table; if no match, show "Review required" | "$35 per unit" or "Review required (not in pricing table)" |
| **Projected Unit Price** | Lookup from pricing table | "$35" |
| **Projected Subtotal** | Quantity × Unit Price | "$875" |
| **Qualifies for Buyback?** | Apply qualification rules (see Part 4) | "Yes" or "No — [reason]" |
| **Confidence Score** | Combine condition certainty + quantity certainty + power-on certainty | "85%" |

**Qualification Inline Messages:**
- ✅ "Qualifies for guaranteed buyback pricing"
- ⚠️ "Review required — model not found in pricing table"
- ⚠️ "Review required — condition unknown"
- ⚠️ "Likely recycling only — locked status unclear, damaged, or condition poor"

**Auto-Calculation:**

```
For each line item:
  IF model found in pricing table
    AND quantity is known (type = "Confirmed")
    AND power_on = "Yes"
    AND locked_status = "Unlocked"
    AND cracked_screens = "No"
    AND missing_components = "No"
    AND condition NOT in ["Poor", "Unknown"]
  THEN: Qualifies for buyback, show unit price + subtotal
  ELSE: Show "Review required" or "Recycling only"
```

**Totals Section (Auto-Populated After Each Line Item Entry):**

| Total | Calculation | Display |
|-------|-------------|---------|
| **Guaranteed Qualifying Subtotal** | Sum of all "Qualifies for buyback" items | "$3,875" |
| **Review Required Subtotal** | Sum of flagged items (show as range if applicable) | "$500–$1,500" |
| **Projected Total Qualifying Value** | Guaranteed + (midpoint of review range if exists) | **"UP TO $4,375.00"** |
| **Device Count** | Sum of all quantities | "250 devices" |

---

### SECTION E: DATA SECURITY & REPORTING REQUIREMENTS

**Purpose:** Capture regulatory, security, and certification needs.

**Conditional Display:** Only show if any line item contains "data-bearing" category (laptop, desktop, tablet, iPad, MacBook, server).

| Field | Type | Required | Example | Validation |
|-------|------|----------|---------|------------|
| **Is Data-Bearing Equipment Included?** | Radio | YES | "Yes" | If "No," skip to Section F |
| **Required Data Process** | Dropdown | YES | "Data sanitization" | Enum: Data sanitization, Physical destruction, Recycling only, Unknown |
| **Required Standard** | Dropdown | YES | "NIST 800-88" | Enum: NIST 800-88, NAID, Certificate only, District-specific, Unknown |
| **Certificate of Data Destruction Required?** | Radio | YES | "Yes" | YES/NO |
| **Certificate of Recycling Required?** | Radio | YES | "Yes" | YES/NO |
| **Serialized / Itemized Reporting Required?** | Radio | YES | "Yes" | YES/NO (affects reconciliation effort) |
| **Chain-of-Custody Receipt Required?** | Radio | YES | "Yes" | YES/NO (standard for TechReboot) |
| **Special Compliance Requirements** | Dropdown (multi-select) | NO | "FERPA" | Enum: FERPA, HIPAA, CJIS, State data law, Internal policy, Other |
| **If Other, Specify** | Textarea | Conditional | "Student data must not leave state" | Max 300 chars |
| **Indemnification Language Required?** | Radio | NO | "Yes" | YES/NO/Unknown |
| **Insurance Documentation Required?** | Radio | NO | "Yes" | YES/NO/Unknown |

**Summary / Risk Flags (Auto-Displayed):**
- ✅ "Data destruction and certification per NIST 800-88 — standard TechReboot process"
- ⚠️ "HIPAA compliance required — review with compliance team before proposal"
- ⚠️ "State-specific data law — may require legal review"

---

### SECTION F: PROPOSAL TERMS & ASSUMPTIONS

**Purpose:** Define turnaround, payment method, and service scope.

| Field | Type | Required | Example | Validation | Affects Proposal |
|-------|------|----------|---------|------------|---|
| **Proposal Type** | Radio | YES | "Conditional guaranteed buyback" | Enum: Conditional guaranteed buyback, Recycling-only removal, Mixed buyback/recycling, Service-only quote | YES |
| **Turnaround Target** | Radio | YES | "7 days" | Enum: 7 days, 14 days, 21 days, Custom | YES (CRITICAL — reused in all sections) |
| **If Custom, Specify** | Text | Conditional | "30 days" | Max 50 chars | YES |
| **Payment Method** | Dropdown | YES | "Check" | Enum: Check, ACH, Credit card, Donation (nonprofit), No payment (recycling only), Unknown | NO (informational) |
| **Offer Validity Period** | Radio | YES | "30 days" | Enum: 30 days, 60 days, 90 days, Custom | YES |
| **Title Transfer Rule** | Radio | YES | "Upon payment" | Enum: Upon payment in full, Upon pickup, Upon signed agreement | YES |
| **Risk of Loss Transfer** | Radio | YES | "At pickup" | Enum: At pickup, At warehouse receipt, Upon payment | YES |
| **Pickup Cost** | Radio | YES | "No-cost pickup" | Enum: No-cost pickup (TechReboot absorbs), Quoted freight, Client pays freight, Unknown | YES |
| **White-Glove Service Included?** | Radio | YES | "Yes" | YES / NO / Review required | YES |
| **Labor Included?** | Radio | YES | "Yes" | YES / NO | YES |
| **Packing Materials Included?** | Radio | YES | "Yes" | YES / NO | YES |
| **Freight Included?** | Radio | YES | "Yes" | YES / NO | YES |
| **On-Site Inventory Required?** | Radio | YES | "No" | YES / NO (spot checks vs. full count) | YES |
| **Warehouse Reconciliation Required?** | Radio | YES | "Yes" | YES / NO | YES |
| **Client-Specific Terms / Exceptions** | Textarea | NO | "Client requests 10-day payment turnaround instead of standard 7 days" | Max 500 chars | YES |

**Auto-Validation:**
- ✅ "Turnaround term selected: 7 days — will be used consistently in all proposal sections"
- ⚠️ "White-glove service + No-cost pickup + Freight included — verify margin feasibility"
- ⚠️ "Warehouse reconciliation required — adds 2-3 days to turnaround"

---

### SECTION G: INTERNAL REVIEW & AUTOMATION CONTROLS

**Visibility:** Internal rep or HubSpot user only (not external district).

| Field | Type | Required | Example | Validation |
|-------|------|----------|---------|------------|
| Sales Owner | Dropdown (lookup) | YES | "Michael Stott" | Auto-complete from HubSpot users |
| Internal Reviewer | Dropdown (lookup) | NO | "Bruce Manssuer" | Auto-complete from HubSpot users |
| Pricing Approval Required? | Radio | Auto | "Yes" | If Review Required subtotal > $2,000 → auto-YES |
| Management Approval Required? | Radio | Auto | "No" | If Projected Value > $15,000 → auto-YES |
| Proposal Status | Dropdown | Auto | "Draft" | Enum: Draft, Needs review, Approved, Sent, Accepted, Declined, Closed won, Closed lost |
| Confidence Score | Read-only % | Auto | "85%" | Calculated from data completeness + quantity confidence + condition certainty |
| Missing Required Fields | Read-only list | Auto | "Pickup address" | Auto-populated if any YES field is empty |
| Risk Flags | Read-only list | Auto | "Quantity estimated, not confirmed" | Auto-populated based on data quality |
| Next Action | Auto-generated text | Auto | "Await pricing approval from Bruce" | Populated based on approvals needed |
| Follow-Up Date | Date | NO | "2026-07-21" | Optional manual override |

**HubSpot Linkage (Internal Use):**

| Field | Source | Mapping |
|-------|--------|---------|
| HubSpot Company ID | Auto-lookup or new record | Linked company |
| HubSpot Contact ID | Auto-lookup or new record | Linked contact |
| HubSpot Deal ID | Auto-create on form submit | Linked deal |
| Proposal Document ID | Auto-generate on form submit | URL to generated proposal |
| Generated Proposal URL | Auto-generate on form submit | Direct link to .docx or PDF |
| Last Synced Date | Auto-timestamp | When data last synced to HubSpot |
| Data Source Audit Trail | Auto-logged | "Form submitted 2026-07-15 by rep@techreboot.com" |

---

## LANDING PAGE WORKFLOW

### User Path 1: Internal Rep (Quick Capture)

```
Rep enters organization name + address
↓
System auto-lookup in HubSpot (company name, domain, phone)
↓
Rep confirms / corrects company info
↓
Rep enters contact info (may auto-fill if found in HubSpot)
↓
Rep enters equipment line items (from bid or supplied spreadsheet)
↓
System auto-prices, shows qualifying value
↓
Rep confirms turnaround term
↓
Rep hits "Generate Proposal"
↓
System validates, shows QA check results
↓
If all pass → Generate + Email Draft
↓
If flags → Show approval workflow ("Needs pricing review," etc.)
↓
Rep reviews proposal, sends or routes to approver
```

### User Path 2: External District (Self-Service)

```
District visits landing page link in outreach email
↓
System pre-fills organization name, primary contact from HubSpot (if known)
↓
District confirms/updates contact info
↓
District fills in equipment details (simple, friendly UI)
↓
System shows estimated value ("UP TO $4,000 based on your data")
↓
District confirms turnaround preference
↓
District clicks "Get Your Quote"
↓
System validates, sends confirmation email to district
↓
System routes to rep with flagged items ("Confirm if devices power on")
↓
Rep follows up with district for clarifications
↓
Rep generates final proposal, sends
```

---

## FORM SUBMISSION BEHAVIOR

**On Submit:**

1. **Validate all required fields** → If missing, highlight + show error message, don't submit
2. **Check for duplicates** in HubSpot:
   - If company exists → Link to existing record
   - If contact exists → Link to existing record
   - If both new → Create both in HubSpot
3. **Auto-calculate totals** and populate pricing fields
4. **Create HubSpot deal** with opportunity stage = "Proposal Draft"
5. **Trigger automation:**
   - If pricing approval needed → Create task for Bruce
   - If management approval needed → Create task for Michael Stott
   - If multi-site → Flag logistics team
6. **Generate proposal** (if all QA passes) or **queue for review** (if approvals needed)
7. **Send confirmation email** to rep (internal) or district contact (external)
8. **Redirect to confirmation page** with:
   - Proposal download link
   - Email draft preview
   - Next steps (send, route for approval, etc.)

---

## LANDING PAGE UI/UX NOTES

- **Responsive design:** Mobile-friendly (rep in field), desktop-optimized (rep at desk)
- **Smart defaults:** Auto-fill from HubSpot where possible
- **Progressive disclosure:** Show only relevant fields based on previous answers (e.g., don't show multi-site logistics if "1 location" selected)
- **Inline validation:** Show "Looks good ✅" or "Needs review ⚠️" as user fills in critical fields
- **Estimated value display:** Show running total as user adds line items ("UP TO $4,000")
- **Clear pricing transparency:** "This estimate is based on your data. Final value determined after warehouse inspection."
- **Save & resume:** Allow partial submission save (optional, for long forms)
- **API-first:** All form fields must be captured in structured format, ready for API calls to HubSpot, proposal generator, and downstream systems

---

# PART 3: DATA MODEL / FIELD SCHEMA

## Objects & Relationships

```
Company (1) ──→ (many) Contact
         ──→ (many) BidSource
         ──→ (many) Opportunity (Deal)

Opportunity (1) ──→ (many) AssetLineItem
            ──→ (many) PickupLocation
            ──→ (1) Proposal
            ──→ (many) ComplianceRequirement
            ──→ (many) Activity (Follow-up tasks)

Proposal (1) ──→ (many) ProposalTerm
         ──→ (1) PricingRule (summary)
         ──→ (1) WhiteGloveService (summary)

PricingTable (ref) ──→ (many) PricingRule
```

---

## OBJECT 1: COMPANY

**Canonical Business Record for Organization**

| Field Name | Type | Required | Example | Validation | HubSpot Map | In Proposal |
|------------|------|----------|---------|------------|-------------|------------|
| company_id | UUID | YES (auto) | "co_7a8b9c0d" | System-generated | companyId | NO |
| name | String (200) | YES | "Pompton Lakes Schools" | Non-empty, trim | name | YES |
| organization_type | Enum | YES | "K-12 District" | K-12 district, charter, higher ed, municipality, county, gov agency, enterprise, other | customObjectProperties.organization_type | NO |
| website | URL | NO | "https://www.plps.org" | Valid URL format | website | NO |
| domain | String (100) | NO | "plps.org" | Lowercase, no www | domain | NO |
| phone | Phone | NO | "(973) 835-7100" | US format | phone | NO |
| main_address_street | String (200) | YES | "237 Van Ave" | Non-empty | street | NO |
| main_address_city | String (100) | YES | "Pompton Lakes" | Non-empty | city | NO |
| main_address_state | String (2) | YES | "NJ" | Valid US state | state | NO |
| main_address_zip | String (5) | YES | "07442" | 5-digit US ZIP | zip | NO |
| state | String (2) | YES | "NJ" | Valid US state | state | NO (but stored) |
| region | String (50) | NO | "Northeast" | Auto-calculated from state | customObjectProperties.region | NO |
| hubspot_company_id | String | NO | "1234567890" | HubSpot ID if exists | companyId (HubSpot native) | NO |
| last_synced_hubspot | DateTime | Auto | "2026-07-15T14:32:00Z" | ISO 8601 | System timestamp | NO |
| created_date | DateTime | Auto | "2026-07-14T10:00:00Z" | ISO 8601 | createdate | NO |
| updated_date | DateTime | Auto | "2026-07-15T14:32:00Z" | ISO 8601 | hs_lastmodifieddate | NO |
| data_source | Enum | YES | "bid_watch" | bid_watch, direct_inbound, referral, hubspot_outbound, existing_customer | customObjectProperties.data_source | NO |
| notes | Text (1000) | NO | "District looking to refresh 200+ devices this summer" | Max 1000 chars | notes | NO |

---

## OBJECT 2: CONTACT

**Person at Company Who Influences Decision**

| Field Name | Type | Required | Example | Validation | HubSpot Map | In Proposal |
|------------|------|----------|---------|------------|-------------|------------|
| contact_id | UUID | YES (auto) | "ct_f3e4d5c6" | System-generated | contactId | NO |
| company_id | UUID | YES (FK) | "co_7a8b9c0d" | Foreign key to Company | associatedCompanyId | NO |
| first_name | String (100) | YES | "John" | Non-empty, trim | firstname | YES |
| last_name | String (100) | YES | "Briggs" | Non-empty, trim | lastname | YES |
| email | Email | YES | "jbriggs@plps.org" | Valid email, unique | email | YES |
| phone | Phone | NO | "(973) 835-7100" | US format | phone | YES |
| extension | String (10) | NO | "1552" | Numeric | customObjectProperties.extension | NO |
| title | String (200) | YES | "Technical Support Specialist" | Non-empty, trim | jobtitle | YES |
| role_in_process | Enum | YES | "IT/Technology" | IT/Technology, Procurement, Finance, Operations, Facilities, Superintendent/Admin, Other | customObjectProperties.role_in_process | NO |
| is_decision_maker | Boolean | YES | true | YES / NO | customObjectProperties.is_decision_maker | NO |
| is_primary_contact | Boolean | YES | true | YES / NO for opportunity | customObjectProperties.is_primary_contact | YES |
| preferred_contact_method | Enum | NO | "Email" | Email, Phone, Both | customObjectProperties.preferred_contact_method | NO |
| hubspot_contact_id | String | NO | "9876543210" | HubSpot ID if exists | contactId (HubSpot native) | NO |
| last_synced_hubspot | DateTime | Auto | "2026-07-15T14:32:00Z" | ISO 8601 | System timestamp | NO |
| created_date | DateTime | Auto | "2026-07-14T10:00:00Z" | ISO 8601 | createdate | NO |
| updated_date | DateTime | Auto | "2026-07-15T14:32:00Z" | ISO 8601 | hs_lastmodifieddate | NO |

---

## OBJECT 3: BID SOURCE

**Audit Trail Linking Opportunity to Bid Discovery**

| Field Name | Type | Required | Example | Validation | HubSpot Map | In Proposal |
|------------|------|----------|---------|------------|-------------|------------|
| bid_source_id | UUID | YES (auto) | "bs_1a2b3c4d" | System-generated | customObjectId | NO |
| company_id | UUID | YES (FK) | "co_7a8b9c0d" | Foreign key to Company | associatedCompanyId | NO |
| opportunity_id | UUID | NO (FK) | "opp_5f6e7d8c" | Foreign key to Opportunity (may link later) | dealId | NO |
| source_type | Enum | YES | "bid_watch" | bid_watch, direct_inbound, referral, hubspot_outbound, existing_customer, other | customObjectProperties.source_type | NO |
| bid_title | String (300) | NO | "2026 Technology Refresh" | Max 300 chars | customObjectProperties.bid_title | NO |
| bid_number | String (100) | NO | "RFP-2026-07-015" | Max 100 chars | customObjectProperties.bid_number | NO |
| bid_platform | String (100) | NO | "BonFire" | Enum or freetext | customObjectProperties.bid_platform | NO |
| bid_url | URL | NO | "https://bonfire.com/bids/..." | Valid URL | customObjectProperties.bid_url | NO |
| bid_due_date | Date | NO | "2026-07-21" | ISO format | customObjectProperties.bid_due_date | NO |
| bid_awarded | Enum | NO | "Unknown" | Yes, No, Unknown | customObjectProperties.bid_awarded | NO |
| active_buying_event | Boolean | NO | true | YES / NO | customObjectProperties.active_buying_event | NO |
| disposition_method_current | Enum | NO | "Auction" | Auction, Recycler, ITAD vendor, Internal handling, Storage, Unknown | customObjectProperties.disposition_method_current | NO |
| competitor_name | String (200) | NO | "GreenCycle Recycling" | Max 200 chars | customObjectProperties.competitor_name | NO |
| source_notes | Text (1000) | NO | "District prefers ITAD over recycling for tax incentive" | Max 1000 chars | customObjectProperties.source_notes | NO |
| created_date | DateTime | Auto | "2026-07-14T10:00:00Z" | ISO 8601 | createdate | NO |
| updated_date | DateTime | Auto | "2026-07-15T14:32:00Z" | ISO 8601 | hs_lastmodifieddate | NO |

---

## OBJECT 4: OPPORTUNITY (DEAL)

**Primary Business Opportunity Record**

| Field Name | Type | Required | Example | Validation | HubSpot Map | In Proposal |
|------------|------|----------|---------|------------|-------------|------------|
| opportunity_id | UUID | YES (auto) | "opp_5f6e7d8c" | System-generated | dealId | NO |
| company_id | UUID | YES (FK) | "co_7a8b9c0d" | Foreign key to Company | associatedCompanyId | YES |
| primary_contact_id | UUID | YES (FK) | "ct_f3e4d5c6" | Foreign key to Contact | associatedContactId | YES |
| bid_source_id | UUID | NO (FK) | "bs_1a2b3c4d" | Foreign key to BidSource | customObjectProperties.bid_source_id | NO |
| deal_name | String (300) | Auto | "Pompton Lakes Schools — $10,875 Buyback" | Generated from company + value | dealname | NO |
| deal_status | Enum | Auto | "Proposal Draft" | Proposal Draft, Proposal Sent, Negotiation, Closed Won, Closed Lost, On Hold | dealstage | NO |
| projected_qualifying_value | Currency | Auto | 10875.00 | Calculated sum | amount | YES |
| guaranteed_subtotal | Currency | Auto | 9875.00 | Sum of qualified items | customObjectProperties.guaranteed_subtotal | YES |
| review_required_subtotal | Currency | Auto | 1000.00 | Sum of flagged items | customObjectProperties.review_required_subtotal | NO |
| device_count_total | Integer | Auto | 425 | Sum of all quantities | customObjectProperties.device_count_total | YES |
| turnaround_days | Integer | YES | 7 | 7, 14, 21, or custom | customObjectProperties.turnaround_days | YES (CRITICAL — reused in all sections) |
| turnaround_custom | String (100) | NO | "30 days" | If custom turnaround | customObjectProperties.turnaround_custom | YES |
| proposal_type | Enum | YES | "Conditional guaranteed buyback" | Conditional guaranteed buyback, Recycling-only removal, Mixed, Service-only quote | customObjectProperties.proposal_type | YES |
| payment_method | Enum | NO | "Check" | Check, ACH, Credit card, Donation, No payment, Unknown | customObjectProperties.payment_method | YES |
| offer_validity_days | Integer | YES | 30 | 30, 60, 90, custom | customObjectProperties.offer_validity_days | YES |
| title_transfer_rule | Enum | YES | "Upon payment in full" | Upon payment, Upon pickup, Upon agreement | customObjectProperties.title_transfer_rule | YES |
| risk_of_loss_transfer | Enum | YES | "At pickup" | At pickup, At warehouse receipt, Upon payment | customObjectProperties.risk_of_loss_transfer | YES |
| pickup_cost | Enum | YES | "No-cost pickup" | No-cost, Quoted freight, Client pays, Unknown | customObjectProperties.pickup_cost | YES |
| white_glove_service_included | Boolean | YES | true | YES / NO | customObjectProperties.white_glove_service_included | YES |
| labor_included | Boolean | YES | true | YES / NO | customObjectProperties.labor_included | YES |
| packing_materials_included | Boolean | YES | true | YES / NO | customObjectProperties.packing_materials_included | YES |
| freight_included | Boolean | YES | true | YES / NO | customObjectProperties.freight_included | YES |
| on_site_inventory_required | Boolean | YES | false | YES / NO | customObjectProperties.on_site_inventory_required | YES |
| warehouse_reconciliation_required | Boolean | YES | true | YES / NO | customObjectProperties.warehouse_reconciliation_required | YES |
| sales_owner_id | String | YES | "rep_michael_stott" | HubSpot user ID | hubspotOwnerId | NO |
| internal_reviewer_id | String | NO | "rep_bruce_manssuer" | HubSpot user ID | customObjectProperties.internal_reviewer_id | NO |
| proposal_status | Enum | Auto | "Draft" | Draft, Needs review, Approved, Sent, Accepted, Declined, Closed won, Closed lost | customObjectProperties.proposal_status | NO |
| confidence_score | Integer | Auto | 85 | 0-100% | customObjectProperties.confidence_score | NO |
| missing_required_fields | Text (500) | Auto | "Pickup address" | Auto-populated | customObjectProperties.missing_required_fields | NO |
| risk_flags | Text (1000) | Auto | "Quantity estimated, not confirmed" | Auto-populated | customObjectProperties.risk_flags | NO |
| next_action | String (200) | Auto | "Await pricing approval from Bruce" | Auto-generated | customObjectProperties.next_action | NO |
| follow_up_date | Date | NO | "2026-07-21" | ISO format | customObjectProperties.follow_up_date | NO |
| hubspot_deal_id | String | YES | "1234567890" | HubSpot deal ID | dealId (HubSpot native) | NO |
| proposal_document_id | UUID | NO | "doc_abc123xyz" | Foreign key to Proposal | customObjectProperties.proposal_document_id | NO |
| generated_proposal_url | URL | NO | "https://storage.techreboot.com/proposals/opp_5f6e7d8c.docx" | Direct link to proposal file | customObjectProperties.generated_proposal_url | NO |
| last_synced_hubspot | DateTime | Auto | "2026-07-15T14:32:00Z" | ISO 8601 | System timestamp | NO |
| created_date | DateTime | Auto | "2026-07-14T10:00:00Z" | ISO 8601 | createdate | NO |
| updated_date | DateTime | Auto | "2026-07-15T14:32:00Z" | ISO 8601 | hs_lastmodifieddate | NO |
| data_source_audit_trail | Text (1000) | Auto | "Form submitted 2026-07-15 by rep@techreboot.com" | Auto-logged | customObjectProperties.data_source_audit_trail | NO |

---

## OBJECT 5: ASSET LINE ITEM

**Individual Device in Equipment List**

| Field Name | Type | Required | Example | Validation | HubSpot Map | In Proposal |
|------------|------|----------|---------|------------|-------------|------------|
| line_item_id | UUID | YES (auto) | "li_7h8i9j0k" | System-generated | customObjectId | NO |
| opportunity_id | UUID | YES (FK) | "opp_5f6e7d8c" | Foreign key to Opportunity | dealId | NO |
| asset_category | Enum | YES | "Laptop" | Chromebook, Laptop, Desktop, Tablet, iPad, MacBook, Monitor, Server, Networking, AV, Charging cart, Mixed, Other | customObjectProperties.asset_category | YES |
| manufacturer | String (100) | YES | "Dell" | Non-empty | customObjectProperties.manufacturer | YES |
| model_name | String (200) | YES | "Latitude 3120" | Non-empty, max 200 chars | customObjectProperties.model_name | YES |
| model_number | String (100) | NO | "3120" | Max 100 chars | customObjectProperties.model_number | NO |
| generation_year | String (50) | NO | "2021" | 4-digit year or generation | customObjectProperties.generation_year | NO |
| processor_cpu_tier | Enum | NO | "i5" | i3, i5, i7, i9, M1, M2, M3, Ryzen 3/5/7, other | customObjectProperties.processor_cpu_tier | NO |
| ram | String (50) | NO | "8GB" | Max 50 chars | customObjectProperties.ram | NO |
| storage | String (50) | NO | "256GB SSD" | Max 50 chars | customObjectProperties.storage | NO |
| quantity | Integer | YES | 25 | Integer > 0 | customObjectProperties.quantity | YES |
| quantity_type | Enum | YES | "Confirmed" | Confirmed, Estimated, Rough count, Unknown | customObjectProperties.quantity_type | NO |
| condition | Enum | YES | "Good" | Excellent, Good, Fair, Poor, Mixed, Unknown | customObjectProperties.condition | YES |
| condition_score | Integer | Auto | 3 | 1-5 scale (1=poor, 5=excellent) | customObjectProperties.condition_score | NO |
| power_on_status | Enum | YES | "Yes" | Yes, No, Mixed, Unknown | customObjectProperties.power_on_status | YES |
| locked_mdm_status | Enum | YES | "Unlocked" | Unlocked, Locked, Mixed, Unknown | customObjectProperties.locked_mdm_status | YES |
| cracked_screens | Enum | YES | "No" | Yes, No, Mixed, Unknown | customObjectProperties.cracked_screens | NO |
| missing_components | Enum | YES | "No" | Yes, No, Mixed, Unknown | customObjectProperties.missing_components | YES |
| chargers_included | Enum | YES | "Yes" | Yes, No, Partial, Not required, Unknown | customObjectProperties.chargers_included | NO |
| cases_included | Enum | YES | "No" | Yes, No, Partial, Unknown | customObjectProperties.cases_included | NO |
| asset_tags_removed | Enum | NO | "Yes" | Yes, No, Unknown | customObjectProperties.asset_tags_removed | NO |
| serial_numbers_available | Enum | NO | "Partial" | Yes, No, Partial, Unknown | customObjectProperties.serial_numbers_available | NO |
| photos_uploaded | Boolean | NO | true | YES / NO | customObjectProperties.photos_uploaded | NO |
| line_notes | Text (500) | NO | "Devices currently in student use, ready EOJ" | Max 500 chars | customObjectProperties.line_notes | NO |
| confidence_level | Enum | YES | "High" | High, Medium, Low | customObjectProperties.confidence_level | NO |
| pricing_status | Enum | Auto | "Qualified" | Qualified, Review required, Recycling only | customObjectProperties.pricing_status | NO |
| unit_price | Currency | Auto | 35.00 | Lookup from pricing table | customObjectProperties.unit_price | YES |
| projected_subtotal | Currency | Auto | 875.00 | Quantity × Unit Price | customObjectProperties.projected_subtotal | YES |
| qualifies_for_buyback | Boolean | Auto | true | YES / NO | customObjectProperties.qualifies_for_buyback | NO |
| qualification_reason | Text (300) | Auto | "Model found, quantity confirmed, power-on yes, unlocked, no damage" | Auto-populated | customObjectProperties.qualification_reason | NO |
| disqualification_reason | Text (300) | Auto | "Locked status unclear" | Auto-populated if disqualified | customObjectProperties.disqualification_reason | NO |
| pricing_override | Currency | NO | 40.00 | Manual override if allowed | customObjectProperties.pricing_override | NO |
| pricing_override_reason | Text (200) | NO | "Client damaged goods, approve reduced rate" | Max 200 chars | customObjectProperties.pricing_override_reason | NO |
| pricing_override_approved_by | String | NO | "bruce_manssuer" | HubSpot user ID | customObjectProperties.pricing_override_approved_by | NO |
| created_date | DateTime | Auto | "2026-07-14T10:00:00Z" | ISO 8601 | createdate | NO |
| updated_date | DateTime | Auto | "2026-07-15T14:32:00Z" | ISO 8601 | hs_lastmodifieddate | NO |

---

## OBJECT 6: PICKUP LOCATION

**Site-Specific Logistics Requirements**

| Field Name | Type | Required | Example | Validation | HubSpot Map | In Proposal |
|------------|------|----------|---------|------------|-------------|------------|
| location_id | UUID | YES (auto) | "pl_2k3l4m5n" | System-generated | customObjectId | NO |
| opportunity_id | UUID | YES (FK) | "opp_5f6e7d8c" | Foreign key to Opportunity | dealId | NO |
| location_type | Enum | YES | "Primary" | Primary, Secondary, Tertiary | customObjectProperties.location_type | YES |
| site_name | String (200) | NO | "Main Campus" | Building or site designation | customObjectProperties.site_name | YES |
| address_street | String (200) | YES | "237 Van Ave" | Non-empty | customObjectProperties.address_street | YES |
| address_city | String (100) | YES | "Pompton Lakes" | Non-empty | customObjectProperties.address_city | YES |
| address_state | String (2) | YES | "NJ" | Valid US state | customObjectProperties.address_state | YES |
| address_zip | String (5) | YES | "07442" | 5-digit US ZIP | customObjectProperties.address_zip | YES |
| latitude | Float | NO | 40.8844 | Valid GPS lat | customObjectProperties.latitude | NO |
| longitude | Float | NO | -74.2630 | Valid GPS lon | customObjectProperties.longitude | NO |
| location_contact_name | String (200) | NO | "John Briggs" | Max 200 chars | customObjectProperties.location_contact_name | NO |
| location_contact_phone | Phone | NO | "(973) 835-7100" | US format | customObjectProperties.location_contact_phone | NO |
| location_contact_email | Email | NO | "jbriggs@plps.org" | Valid email | customObjectProperties.location_contact_email | NO |
| loading_dock_available | Enum | YES | "Yes" | Yes, No, Unknown | customObjectProperties.loading_dock_available | YES |
| elevator_access | Enum | YES | "Yes" | Yes, Stairs only, Unknown | customObjectProperties.elevator_access | YES |
| pallet_jack_forklift | Enum | YES | "No" | Yes, No, Unknown | customObjectProperties.pallet_jack_forklift | YES |
| items_boxed_palletized | Enum | YES | "Partially" | Yes, No, Partially, Unknown | customObjectProperties.items_boxed_palletized | YES |
| charging_carts_included | Enum | YES | "No" | Yes, No, Unknown | customObjectProperties.charging_carts_included | NO |
| preferred_pickup_window | String (200) | NO | "Week of July 20, after 2 PM" | Max 200 chars | customObjectProperties.preferred_pickup_window | YES |
| access_instructions | Text (500) | NO | "Use side entrance, parking lot A, call 30 min before arrival" | Max 500 chars | customObjectProperties.access_instructions | YES |
| estimated_pallet_count | Integer | Auto | 3 | Auto-calculated based on quantity | customObjectProperties.estimated_pallet_count | NO |
| estimated_labor_hours | Float | Auto | 4.5 | Auto-calculated based on quantity + access | customObjectProperties.estimated_labor_hours | NO |
| created_date | DateTime | Auto | "2026-07-14T10:00:00Z" | ISO 8601 | createdate | NO |
| updated_date | DateTime | Auto | "2026-07-15T14:32:00Z" | ISO 8601 | hs_lastmodifieddate | NO |

---

## OBJECT 7: COMPLIANCE REQUIREMENT

**Data Security, Regulatory, and Reporting Requirements**

| Field Name | Type | Required | Example | Validation | HubSpot Map | In Proposal |
|------------|------|----------|---------|------------|-------------|------------|
| compliance_id | UUID | YES (auto) | "cr_6o7p8q9r" | System-generated | customObjectId | NO |
| opportunity_id | UUID | YES (FK) | "opp_5f6e7d8c" | Foreign key to Opportunity | dealId | NO |
| data_bearing_equipment | Boolean | YES | true | YES / NO | customObjectProperties.data_bearing_equipment | YES |
| data_process_required | Enum | YES | "Data sanitization" | Data sanitization, Physical destruction, Recycling only, Unknown | customObjectProperties.data_process_required | YES |
| data_standard | Enum | YES | "NIST 800-88" | NIST 800-88, NAID, Certificate only, District-specific, Unknown | customObjectProperties.data_standard | YES |
| certificate_of_destruction | Boolean | YES | true | YES / NO | customObjectProperties.certificate_of_destruction | YES |
| certificate_of_recycling | Boolean | YES | true | YES / NO | customObjectProperties.certificate_of_recycling | YES |
| serialized_reporting | Boolean | YES | true | YES / NO | customObjectProperties.serialized_reporting | YES |
| chain_of_custody_receipt | Boolean | YES | true | YES / NO | customObjectProperties.chain_of_custody_receipt | YES |
| special_compliance_required | Boolean | NO | true | YES / NO | customObjectProperties.special_compliance_required | NO |
| special_compliance_types | Enum (multi) | NO | ["FERPA", "HIPAA"] | FERPA, HIPAA, CJIS, State law, Internal policy, Other | customObjectProperties.special_compliance_types | YES |
| special_compliance_other | Text (300) | NO | "Student data cannot leave state" | Max 300 chars | customObjectProperties.special_compliance_other | YES |
| indemnification_required | Boolean | NO | false | YES / NO / Unknown | customObjectProperties.indemnification_required | YES |
| insurance_required | Boolean | NO | false | YES / NO / Unknown | customObjectProperties.insurance_required | YES |
| compliance_review_needed | Boolean | Auto | false | YES / NO | customObjectProperties.compliance_review_needed | NO |
| compliance_reviewer_id | String | NO | "legal_team" | HubSpot user ID | customObjectProperties.compliance_reviewer_id | NO |
| created_date | DateTime | Auto | "2026-07-14T10:00:00Z" | ISO 8601 | createdate | NO |
| updated_date | DateTime | Auto | "2026-07-15T14:32:00Z" | ISO 8601 | hs_lastmodifieddate | NO |

---

## OBJECT 8: PROPOSAL

**Generated Proposal Document Record**

| Field Name | Type | Required | Example | Validation | HubSpot Map | In Proposal |
|------------|------|----------|---------|------------|-------------|------------|
| proposal_id | UUID | YES (auto) | "doc_abc123xyz" | System-generated | customObjectId | NO |
| opportunity_id | UUID | YES (FK) | "opp_5f6e7d8c" | Foreign key to Opportunity | dealId | NO |
| proposal_version | Integer | Auto | 1 | Incremented on regeneration | customObjectProperties.proposal_version | NO |
| proposal_format | Enum | YES | "DOCX" | DOCX, PDF | customObjectProperties.proposal_format | NO |
| proposal_generated_date | DateTime | Auto | "2026-07-15T14:32:00Z" | ISO 8601 | customObjectProperties.proposal_generated_date | NO |
| proposal_url | URL | YES | "https://storage.techreboot.com/proposals/doc_abc123xyz.docx" | Valid URL to document | customObjectProperties.proposal_url | NO |
| proposal_downloaded_date | DateTime | NO | "2026-07-15T15:00:00Z" | ISO 8601, populated on download | customObjectProperties.proposal_downloaded_date | NO |
| proposal_sent_date | DateTime | NO | "2026-07-15T15:30:00Z" | ISO 8601, populated on send | customObjectProperties.proposal_sent_date | NO |
| proposal_status | Enum | Auto | "Generated" | Generated, Downloaded, Sent, Accepted, Declined, Stalled | customObjectProperties.proposal_status | NO |
| generated_by_user_id | String | YES | "rep_michael_stott" | HubSpot user ID | customObjectProperties.generated_by_user_id | NO |
| content_sections | JSON | Auto | { "company_name": "Pompton Lakes Schools", "turnaround_days": 7, ... } | All merge field values | customObjectProperties.content_sections | NO |
| created_date | DateTime | Auto | "2026-07-14T10:00:00Z" | ISO 8601 | createdate | NO |
| updated_date | DateTime | Auto | "2026-07-15T14:32:00Z" | ISO 8601 | hs_lastmodifieddate | NO |

---

## OBJECT 9: PRICING TABLE (REFERENCE)

**Lookup Table for Unit Prices**

| Field Name | Type | Required | Example | Validation |
|------------|------|----------|---------|------------|
| pricing_rule_id | UUID | YES (auto) | "pr_ast9b0c1d" | System-generated |
| asset_category | Enum | YES | "Laptop" | Chromebook, Laptop, Desktop, Tablet, iPad, MacBook, Monitor, Server, Networking, AV, other |
| manufacturer | String (100) | YES | "Dell" | Non-empty |
| model_name | String (200) | YES | "Latitude 3120" | Non-empty, max 200 |
| generation | String (50) | NO | "2021" | E.g., 10th Gen, M1, etc. |
| cpu_tier | Enum | NO | "i5" | i3, i5, i7, i9, M1, M2, M3, Ryzen, other |
| condition | Enum | YES | "Good" | Excellent, Good, Fair, Poor |
| locked_status | Enum | YES | "Unlocked" | Unlocked, Locked |
| unit_price_min | Currency | YES | 35.00 | Minimum price in range |
| unit_price_max | Currency | YES | 35.00 | Maximum price in range (same if single) |
| unit_price | Currency | YES | 35.00 | Standard price (midpoint if range) |
| effective_date | Date | YES | "2026-01-01" | When price became effective |
| end_date | Date | NO | "2026-12-31" | When price expires (null = ongoing) |
| notes | Text (500) | NO | "Updated per Bruce's June pricing review" | Max 500 chars |

---

## OBJECT 10: ACTIVITY / FOLLOW-UP TASK

**Track Actions, Communications, and Approvals**

| Field Name | Type | Required | Example | Validation | HubSpot Map |
|------------|------|----------|---------|------------|-------------|
| activity_id | UUID | YES (auto) | "act_cde2f3g4h" | System-generated | engagementId |
| opportunity_id | UUID | YES (FK) | "opp_5f6e7d8c" | Foreign key to Opportunity | dealId |
| activity_type | Enum | YES | "Email sent" | Email sent, Phone call, Task, Note, Meeting, Follow-up reminder | engagementType |
| task_owner_id | String | NO | "rep_michael_stott" | HubSpot user ID | ownerId |
| task_subject | String (200) | YES | "Follow up on Pompton Lakes proposal" | Max 200 chars | subject |
| task_description | Text (1000) | NO | "Check for questions, propose pickup date" | Max 1000 chars | body |
| task_due_date | Date | YES | "2026-07-21" | ISO format | duedate |
| task_status | Enum | Auto | "Open" | Open, In progress, Completed | status |
| associated_email | Email | NO | "jbriggs@plps.org" | Email address if task is email-related | associatedEmail |
| associated_contact_id | UUID | NO | "ct_f3e4d5c6" | Foreign key to Contact | associatedContactId |
| created_date | DateTime | Auto | "2026-07-15T14:32:00Z" | ISO 8601 | createdate |
| completed_date | DateTime | NO | "2026-07-16T10:00:00Z" | ISO 8601, populated on completion | customObjectProperties.completed_date |
| created_by_user_id | String | Auto | "system" or rep ID | HubSpot user ID or system | createdByUserId |
| notes | Text (1000) | NO | "Discussed pricing, client waiting on board approval" | Max 1000 chars | notes |

---

## HUBSPOT CUSTOM OBJECTS & PROPERTIES

**Properties to Create in HubSpot (if using HubSpot as CRM):**

### Contact Properties
- `is_decision_maker` (checkbox)
- `is_primary_contact` (checkbox)
- `role_in_process` (dropdown: IT, Procurement, Finance, Operations, Facilities, Superintendent, Other)
- `preferred_contact_method` (dropdown: Email, Phone, Both)
- `extension` (text)

### Company Properties
- `organization_type` (dropdown: K-12, Charter, Higher Ed, Municipality, County, Gov Agency, Enterprise, Other)
- `domain` (text, auto-populated from website)
- `region` (dropdown: Northeast, Southeast, Midwest, Southwest, West, auto-calculated from state)
- `data_source` (dropdown: bid_watch, direct, referral, hubspot_outbound, existing)

### Deal Properties
- `turnaround_days` (number — **CRITICAL**)
- `turnaround_custom` (text — if custom days)
- `proposal_type` (dropdown: Conditional guaranteed, Recycling-only, Mixed, Service-only)
- `guaranteed_subtotal` (currency)
- `review_required_subtotal` (currency)
- `device_count_total` (number)
- `payment_method` (dropdown: Check, ACH, Card, Donation, None, Unknown)
- `offer_validity_days` (number)
- `title_transfer_rule` (dropdown: Upon payment, Upon pickup, Upon agreement)
- `risk_of_loss_transfer` (dropdown: At pickup, At warehouse, Upon payment)
- `pickup_cost` (dropdown: No-cost, Quoted freight, Client pays, Unknown)
- `white_glove_service_included` (checkbox)
- `labor_included` (checkbox)
- `packing_materials_included` (checkbox)
- `freight_included` (checkbox)
- `on_site_inventory_required` (checkbox)
- `warehouse_reconciliation_required` (checkbox)
- `internal_reviewer_id` (text — HubSpot user ID)
- `proposal_status` (dropdown: Draft, Needs review, Approved, Sent, Accepted, Declined, Won, Lost)
- `confidence_score` (number 0-100)
- `missing_required_fields` (text)
- `risk_flags` (text)
- `next_action` (text)
- `proposal_document_id` (text — UUID)
- `generated_proposal_url` (text — URL)
- `bid_source_id` (text — reference to bid source)
- `data_source_audit_trail` (text)

### Custom Objects (if using HubSpot Custom Objects)
- `bid_source` object with fields: source_type, bid_title, bid_number, bid_platform, bid_url, bid_due_date, bid_awarded, active_buying_event, disposition_method_current, competitor_name, source_notes
- `asset_line_item` object with fields: all line item properties
- `pickup_location` object with fields: all location properties
- `compliance_requirement` object with fields: all compliance properties
- `proposal` object with fields: proposal_version, proposal_format, proposal_generated_date, proposal_url, proposal_status, etc.

---

# PART 4: AUTOMATION RULES & PROPOSAL GENERATION LOGIC

## A. MATCHING / DEDUPLICATION RULES

### Company Matching Algorithm

**Order of Matching (first match wins):**

1. **HubSpot Company ID Match (if provided):**
   - If `hubspot_company_id` is in the form → Query HubSpot, retrieve company record
   - Use existing company record, skip to Contact matching

2. **Domain Match:**
   - Extract domain from bid URL or organization website (e.g., "plps.org")
   - Normalize: lowercase, strip www, remove trailing slash
   - Query HubSpot companies by `domain` property
   - If exact match found → Use company record

3. **Organization Name Match:**
   - Query HubSpot companies by fuzzy match on `name` property
   - Use HubSpot's built-in company search (allows ~80% match threshold)
   - If exactly one match found → Use company record
   - If multiple matches or no match → Proceed to "Create New"

4. **Create New Company Record:**
   - If no matches in steps 1-3:
   - Create new company in HubSpot with:
     - `name` from form
     - `domain` (extracted or derived)
     - `website` from form
     - `phone` from form
     - `street`, `city`, `state`, `zip` from main address
     - `organization_type` from form
     - `region` (auto-calculated from state)
     - `data_source` from form

**Handling Blank Organization Names:**
- If company name is blank but company ID exists → Query HubSpot by ID, retrieve name, use existing company
- Never discard activity/bid data because company name is missing
- Log unresolved company records for manual review queue

### Contact Matching Algorithm

**Order of Matching (first match wins):**

1. **Email Match:**
   - If `email` provided → Query HubSpot contacts by exact email match
   - If exactly one match found → Use contact record
   - Verify company association (if company already matched, confirm contact belongs to company)

2. **Name + Company Match:**
   - If `email` not available but `first_name` + `last_name` + company ID provided:
   - Query HubSpot contacts by name + company
   - Use fuzzy matching (80%+ threshold)
   - If exactly one match found → Use contact record

3. **Create New Contact Record:**
   - If no matches in steps 1-2:
   - Create new contact in HubSpot with:
     - `firstname`, `lastname` from form
     - `email` from form
     - `phone` from form
     - `jobtitle` from form
     - Associated company ID from matched/created company
     - `is_decision_maker` from form
     - `is_primary_contact` = true (default for opportunity)
     - `role_in_process` from form

**Handling Partial Contact Data:**
- If only `email` available → Use email match, fill in other fields later via follow-up
- Log contacts with missing critical fields (name, email) as "Verification needed"

### Primary Contact Confirmation

**Decision:**
- Is the matched/created contact the decision-maker?
  - YES (e.g., Technology Director) → Use as primary contact, proceed to Stage 3
  - NO (e.g., IT help desk person) or UNCLEAR → Mark opportunity as "Contact verification needed," schedule follow-up task

**Follow-Up Task (Auto-Generated):**
- Task subject: "[Organization] — Confirm Decision-Maker Contact"
- Task description: "Reached out to [contact], need to confirm if [they are / provide contact for] decision-maker (Purchasing, Finance, or Superintendent)"
- Due date: 2 business days

---

## B. QUALIFICATION RULES

**A device line qualifies for guaranteed buyback pricing IF AND ONLY IF ALL of the following are true:**

| Rule | Condition | Failure = |
|------|-----------|-----------|
| **Model Specific** | Model is found in pricing table (category + manufacturer + model match) OR model is generic enough to assign a category-wide tier (e.g., "Dell i5 Laptop" maps to "$45–$75 i5 Laptop" tier) | "Review required — model not found" |
| **Quantity Known** | Quantity is "Confirmed" OR "Estimated" with documented confidence (not "Unknown" or "Rough count") | "Review required — quantity uncertain" |
| **Functional** | Power-on status = "Yes" OR can be reasonably assumed functional (e.g., "Good condition, chargers included") | "Review required — power-on unknown" |
| **Unlocked** | Locked/MDM status = "Unlocked" OR can be confirmed by client | "Review required — unlock status unclear" |
| **No Major Damage** | Cracked screens = "No" AND missing components = "No" | "Review required — damage confirmed" |
| **Condition Explicit** | Condition ≠ "Unknown" (must be one of Excellent, Good, Fair, Poor, or Mixed with explanation) | "Review required — condition unknown" |

**If ALL six conditions are met:** Line item qualifies for guaranteed buyback pricing. Pull unit price from pricing table, calculate subtotal.

**If ANY condition fails:** Line item moves to "Review required" or "Recycling value only" category. Do NOT silently default to worst-case price. Flag with specific reason.

---

## C. PRICING RULES

### Step 1: Lookup Pricing Table

**For each qualified line item:**

1. Match to pricing table by:
   - Asset category (e.g., "Laptop")
   - Manufacturer (e.g., "Dell")
   - Model (e.g., "Latitude 3120")
   - Generation/CPU tier (if applicable, e.g., "i5")
   - Condition (e.g., "Good")
   - Locked/unlocked status (e.g., "Unlocked")

2. Retrieve `unit_price` from pricing table (or `unit_price_min` and `unit_price_max` if range)

3. If exact match found → Use unit price
   - If price range (min/max) → Use midpoint
   - Example: "$45–$75 i5 Laptop, Good condition" → $60 per unit

4. If no exact match found → Flag as "Pricing review required," route to Bruce

### Step 2: Calculate Subtotals

**For each line item:**
- `projected_subtotal = quantity × unit_price`
- Example: 25 laptops × $35 each = $875

### Step 3: Categorize by Qualification Status

**Group line items into three buckets:**

| Bucket | Calculation | Example |
|--------|-----------|---------|
| **Guaranteed Buyback** | Sum of all qualified line items | ASUS Chromebook × 200 @ $15 = $3,000 + Dell Laptop × 25 @ $35 = $875 + HP Laptop × 200 @ $35 = $7,000 = **$10,875** |
| **Review Required** | Sum of flagged items; show as range if applicable | "Quantity estimated: 50 devices × $40–$50 range = $2,000–$2,500" |
| **Recycling Value Only** | Items that don't qualify (locked, damaged, etc.); can include scrap value or leave blank | "Damaged monitors, scrap pricing TBD" |

### Step 4: Calculate Totals

**Proposed Total Qualifying Value** calculation depends on data confidence:

**If all items qualified:**
```
Projected Qualifying Value = Guaranteed Qualifying Subtotal
Example: $10,875.00
```

**If some items require review:**
```
Projected Qualifying Value = Guaranteed Qualifying Subtotal + (Midpoint of Review Range if available)
Example: $10,875 (guaranteed) + $2,250 (midpoint of $2,000–$2,500 review range) = $13,125
```

**Presentation in Proposal:**
```
"...representing a projected qualifying value of UP TO $10,875.00"
(Use "UP TO" if any uncertainty, review required items, or condition flags exist)
```

### Step 5: Allow Manual Overrides (With Approval)

**Pricing Override Workflow:**

1. **Rep requests override** → "Unit price $60, client willing to negotiate to $55 per unit"
2. **System captures:**
   - `pricing_override` = $55
   - `pricing_override_reason` = "Client discount negotiation"
   - `pricing_override_requires_approval` = YES (if override is >20% below table price)
3. **If override requires approval:**
   - Create task: "Pricing override approval request — [Organization]"
   - Task owner: Bruce Manssuer
   - Include: original price, override price, reason, margin impact
4. **Bruce approves or rejects** → If approved, update line item price, recalculate totals
5. **If rejected** → Use original table price, note in proposal

### Step 6: Apply Condition-Based Modifiers (Optional)

**Example modifiers based on qualification flags:**

| Condition Flag | Adjustment | Example |
|---|---|---|
| Mixed condition (good/fair mix) | Move to lower end of range | "Good–$35, Fair–$25" → Use $30 midpoint |
| Cracked screen confirmed | Reduce price 20–40% | "$35 unit price → $20–$25 effective" |
| Lock status mixed/unclear | Price at review range | "Unlocked confirmed: $35, Mixed: $15–$25" |

---

## D. PROPOSAL CONTENT GENERATION

### Proposal Template Structure

**The proposal generator pulls from the opportunity record and produces these sections:**

#### 1. Header / Title Page
```
CONDITIONAL GUARANTEED BUYBACK PROPOSAL
Prepared for [Company Name]

Prepared for:                          |  Prepared by:
[Primary Contact]                      |  [Sales Rep Name]
[Title]                                |  VP Business Development
[Company]                              |  TechReboot, Inc.
[Address]                              |  300 Brogdon Road, Suite 100
[Phone]                                |  Suwanee, GA 30024
[Email]                                |  [Email]
                                       |  [Phone]
```

#### 2. Executive Offer
```
TechReboot is pleased to provide [Company Name] with guaranteed buyback rates 
for qualifying devices, representing a projected qualifying value of 
UP TO $[PROJECTED_QUALIFYING_VALUE] for the listed surplus technology equipment. 

Final value will be determined after warehouse inspection, grading, and reconciliation 
under the terms stated in this proposal.

PROJECTED QUALIFYING VALUE        |  CLIENT-SPECIFIC TURNAROUND
UP TO $[VALUE]                    |  Processing, reconciliation report, and payment 
                                  |  targeted within [TURNAROUND_DAYS] calendar days 
                                  |  after pickup
```

**Merge Fields:**
- `[PROJECTED_QUALIFYING_VALUE]` — from `opportunity.projected_qualifying_value`
- `[TURNAROUND_DAYS]` — from `opportunity.turnaround_days` (SINGLE SOURCE OF TRUTH)

#### 3. Guaranteed Rates for Qualifying Devices

**For each line item where `qualifies_for_buyback = true`:**

```
[MANUFACTURER] [MODEL NAME] - [QUANTITY] units at $[UNIT_PRICE] each; 
projected qualifying subtotal: $[PROJECTED_SUBTOTAL]
```

**Example:**
```
ASUS Chromebook C204 - 200 units at $15.00 each; projected qualifying subtotal: $3,000.00
Dell Latitude 3120 Laptop - 25 units at $35.00 each; projected qualifying subtotal: $875.00
HP ProBook x360 11 G5 EE Laptop - 200 units at $35.00 each; projected qualifying subtotal: $7,000.00

Projected Value if All Listed Devices Qualify: $10,875.00
```

#### 4. Pricing Basis (Boilerplate + Conditional Exceptions)

**Standard text:**
```
The quoted per-unit rates are guaranteed only for devices that match the represented 
models, power on, are unlocked, and are free from cracks, material damage, missing 
components, and other functional or cosmetic defects. Devices that do not satisfy 
these criteria will receive the applicable recycling value determined after processing. 
Final payment will be based on the completed warehouse reconciliation report.
```

**If review required items exist, add:**
```
[NUMBER] devices have been flagged for review due to [REASON]. These items will be 
valued after warehouse inspection based on actual condition and market factors.
```

#### 5. Included White-Glove Service

**Conditional: Include items based on `opportunity.white_glove_service_included` and sub-flags:**

```
TechReboot will provide a hands-free removal and processing program at 
[NO COST / QUOTED COST] to [Company Name]. The service includes:
```

**If `white_glove_service_included = true`:**
```
- Pickup from [PRIMARY_PICKUP_ADDRESS]
- All required labor, packing materials, pallets or containers, loading, 
  freight, and transportation [if freight_included = true] / 
  [or freight quote available upon request if freight_included = false]
- A general material-level chain-of-custody receipt confirming collection 
  and transfer of the bulk material
- Limited representative spot checks at pickup, followed by full receiving, 
  inspection, testing, grading, and reconciliation at TechReboot's warehouse
[- Certified data sanitization or physical destruction, as applicable, 
  aligned with TechReboot procedures and applicable standards] 
  [if data_bearing_equipment = true]
- Environmentally responsible reuse, recycling, and downstream disposition
- An itemized reconciliation report showing verified quantities, models, 
  condition, and valuation [if warehouse_reconciliation_required = true]
[- Applicable Certificates of Data Destruction and Recycling] 
  [if compliance_requirements exist]
```

#### 6. Process and Timeline

**Pull `turnaround_days` from opportunity and use in ALL timeline sections:**

```
1. Schedule: TechReboot and [Company Name] coordinate the pickup date and site access.

2. Pickup & Spot Check: TechReboot collects the bulk material, performs limited 
   representative spot checks, and provides a general chain-of-custody receipt.

3. Warehouse Evaluation: Each device is received, identified, tested, graded, and 
   classified as qualifying buyback material or recycling material.

4. Process & Report: TechReboot completes the applicable data-security process and 
   provides an itemized evaluation report.

5. Payment: Final payment, based on qualifying buyback rates and applicable recycling 
   values, and the reconciliation package are targeted within [TURNAROUND_DAYS] 
   calendar days after pickup.
```

**Merge Field:**
- `[TURNAROUND_DAYS]` — from `opportunity.turnaround_days` (MUST MATCH Executive Offer section)

#### 7. Commercial Terms and Assumptions

**Standard template with conditional inclusions:**

```
Offer validity: This proposal is valid for [OFFER_VALIDITY_DAYS] days from 
[DATE_OF_PROPOSAL] unless extended in writing by TechReboot.

Ownership and authority: [Company Name] represents that it owns the equipment or 
has full authority to transfer it.

Pickup verification: Pickup includes only limited representative spot checks. 
The chain-of-custody receipt documents the general material collected and is not 
a device-level inventory, inspection, or acceptance.

Warehouse verification: Final quantities, models, functionality, condition, and 
eligibility will be determined during processing at TechReboot's warehouse and 
documented in the reconciliation report.

Qualifying devices: The quoted rates apply to represented units that power on, 
are unlocked, and are free from cracks, material damage, missing components, and 
other functional or cosmetic defects.

Nonqualifying devices: Locked, cracked, nonfunctional, incomplete, damaged, or 
otherwise nonqualifying devices will receive the applicable recycling value 
determined after processing.

Additional equipment: Unlisted or mixed electronics may be accepted and valued 
after processing based on model, condition, completeness, and recoverability.

Risk of loss: Risk of loss transfers to TechReboot when the material chain-of-custody 
document is executed at pickup [or CUSTOMIZE: "when warehouse receipt is signed"].

Title: Title transfers upon [TITLE_TRANSFER_RULE] unless superseded by a mutually 
executed purchase agreement.

[Data Security: [FULL DATA DESTRUCTION LANGUAGE] aligned with [DATA_STANDARD], 
with [CERTIFICATE OPTIONS].] [if data_bearing_equipment = true]

[Indemnification: TechReboot indemnifies [Company Name] against liability for 
data breaches arising from devices processed under this proposal, subject to the 
terms of a master services agreement.] [if indemnification_required = true]

[Insurance: TechReboot maintains general liability and cyber liability insurance 
as follows: [POLICY DETAILS].] [if insurance_required = true]

Governing documents: A mutually executed purchase agreement, statement of work, 
or master services agreement may supplement this proposal. If there is a conflict, 
the signed agreement controls.
```

#### 8. Why TechReboot (Boilerplate)

```
TechReboot provides nationwide IT asset management, technology buyback, data-security, 
and electronics recycling services. Our program is designed to give public-sector 
organizations a transparent financial return while reducing the labor, logistics, 
compliance, and reporting burden associated with surplus technology.

- No-cost pickup, packing, labor, and freight as a standard service differentiator.
- Transparent guaranteed pricing for identified equipment and itemized reconciliation 
  for mixed assets.
- Secure chain-of-custody controls and documented data-destruction reporting.
- Responsible reuse and recycling through established operational and downstream processes.
- A single accountable point of contact from proposal through payment and final reporting.
```

#### 9. Acceptance / Signature Block

```
The signatures below acknowledge acceptance of the commercial offer and authorize 
the parties to coordinate pickup, subject to any additional mutually executed 
agreement required by either party.

[COMPANY NAME]                        |  TECHREBOOT, INC.
Signature: __________________________ |  Signature: __________________________
Printed Name / Title: ________________ |  [Sales Rep Name], VP Business Development
Date: ______________________________ |  Date: ______________________________

Thank you for the opportunity to serve [COMPANY NAME].

TechReboot, Inc.
300 Brogdon Road, Suite 100, Suwanee, GA 30024
(770) 670-5627 | mike@techrebootusa.com
```

**Merge Fields:**
- `[COMPANY_NAME]` from `opportunity.company_id → company.name`
- `[PRIMARY_CONTACT_NAME]` from `opportunity.primary_contact_id → contact.first_name + last_name`
- `[PRIMARY_CONTACT_TITLE]` from `contact.title`
- `[SALES_REP_NAME]` from `opportunity.sales_owner_id`
- `[TURNAROUND_DAYS]` from `opportunity.turnaround_days` (**CRITICAL — must match all timeline mentions**)

---

### Merge Field Complete Reference

| Field Name | Source | Formula | Example | Used In Sections |
|------------|--------|---------|---------|---|
| `[COMPANY_NAME]` | `opportunity → company.name` | Direct | "Pompton Lakes Schools" | All |
| `[PRIMARY_CONTACT_FIRST]` | `opportunity → contact.first_name` | Direct | "John" | Header, Signature |
| `[PRIMARY_CONTACT_LAST]` | `opportunity → contact.last_name` | Direct | "Briggs" | Header, Signature |
| `[PRIMARY_CONTACT_TITLE]` | `opportunity → contact.title` | Direct | "Technical Support Specialist" | Header |
| `[PRIMARY_CONTACT_EMAIL]` | `opportunity → contact.email` | Direct | "jbriggs@plps.org" | Header |
| `[PRIMARY_CONTACT_PHONE]` | `opportunity → contact.phone` | Direct | "(973) 835-7100" | Header |
| `[PRIMARY_CONTACT_PHONE_EXT]` | `opportunity → contact.extension` | Direct | "1552" | Header (if exists) |
| `[SALES_REP_NAME]` | `opportunity → sales_owner_id → user.name` | HubSpot lookup | "Michael Stott" | Header, Signature |
| `[SALES_REP_TITLE]` | Hardcoded | "VP Business Development" | Literal | Header, Signature |
| `[SALES_REP_EMAIL]` | `opportunity → sales_owner_id → user.email` | HubSpot lookup | "mike@techrebootusa.com" | Header |
| `[SALES_REP_PHONE]` | Hardcoded or lookup | TechReboot main | "(770) 670-5627" | Header |
| `[PICKUP_ADDRESS_FULL]` | `opportunity → primary_pickup_location → address_street/city/state/zip` | Concatenate | "237 Van Ave, Pompton Lakes, NJ 07442" | Pickup address line, Terms |
| `[PROJECTED_QUALIFYING_VALUE]` | `opportunity.projected_qualifying_value` | Sum of qualified items | "$10,875.00" | Executive offer, title |
| `[TURNAROUND_DAYS]` | `opportunity.turnaround_days` | Direct — **USE EVERYWHERE** | "7" | Executive offer, Timeline (Step 5), all references |
| `[GUARANTEED_RATE_TABLE]` | `opportunity.asset_line_items (qualified only)` | For each qualified line: `[Manufacturer] [Model] - [Quantity] @ $[Unit Price]` | "ASUS Chromebook C204 - 200 units at $15.00 each" | Guaranteed Rates section |
| `[GUARANTEED_SUBTOTAL_EACH]` | `opportunity.asset_line_items.projected_subtotal (qualified)` | Quantity × Unit Price | "$3,000.00" | Each line in Guaranteed Rates table |
| `[TOTAL_GUARANTEED_SUBTOTAL]` | `opportunity.guaranteed_subtotal` | Sum of all qualified subtotals | "$10,875.00" | Guaranteed Rates footer |
| `[DEVICE_COUNT_TOTAL]` | `opportunity.device_count_total` | Sum of all quantities | "425" | (informational, rarely used in text) |
| `[OFFER_VALIDITY_DAYS]` | `opportunity.offer_validity_days` | Direct | "30" | Commercial Terms |
| `[PROPOSAL_DATE]` | System timestamp or manual | Today's date | "July 14, 2026" | Footer, Commercial Terms |
| `[DATA_PROCESS_REQUIRED]` | `opportunity → compliance_requirement.data_process_required` | Direct (if exists) | "Data sanitization" | Commercial Terms (if data-bearing) |
| `[DATA_STANDARD]` | `opportunity → compliance_requirement.data_standard` | Direct (if exists) | "NIST 800-88" | Commercial Terms (if data-bearing) |
| `[SPECIAL_COMPLIANCE_TEXT]` | `opportunity → compliance_requirement.special_compliance_types` | Boilerplate map | "FERPA compliance: Student data restricted" | Commercial Terms (if applicable) |
| `[TITLE_TRANSFER_RULE]` | `opportunity.title_transfer_rule` | Direct | "Upon payment in full" | Commercial Terms |
| `[RISK_OF_LOSS_TRANSFER]` | `opportunity.risk_of_loss_transfer` | Direct | "At pickup" | Commercial Terms |

---

## E. QA RULES — Pre-Generation Checklist

**Before a proposal can be generated, validate ALL:**

| Requirement | Field | Check | Fail Action |
|-------------|-------|-------|------------|
| **Company Name** | `opportunity.company_id → company.name` | Non-empty | Block generation, show error "Organization name required" |
| **Primary Contact Name** | `opportunity.primary_contact_id → contact.first_name + last_name` | Both non-empty | Block generation, show error "Contact name required" |
| **Primary Contact Email** | `opportunity.primary_contact_id → contact.email` | Valid email, non-empty | Block generation, show error "Contact email required" |
| **Pickup Address** | `opportunity.primary_pickup_location → address_street/city/state/zip` | All non-empty | Block generation, show error "Pickup address required" |
| **At Least One Line Item** | `opportunity.asset_line_items.count()` | ≥ 1 | Block generation, show error "At least one device required" |
| **Quantity on All Priced Lines** | `opportunity.asset_line_items[qualified].quantity` | All > 0 | Block generation, show error "Quantity required for all devices" |
| **Unit Price on All Buyback Lines** | `opportunity.asset_line_items[qualified].unit_price` | All > 0 | Block generation, show error "Price not found for [Model]. Route to Bruce." |
| **Turnaround Term Selected** | `opportunity.turnaround_days` | In (7, 14, 21) or custom | Block generation, show error "Turnaround term must be selected" |
| **Turnaround Consistency** | All timeline/payment mentions | Use same `turnaround_days` value | Auto-check in merge field replacement, flag if inconsistency detected |
| **No Internal Contradictions** | All terms / timeline / payment | Logical consistency | Example: "Data destruction required" but "No data-bearing equipment" → warn "Verify compliance requirements" |
| **QA Summary** | All above | Pass all checks | Show summary: "10 checks passed ✅" |

---

## F. PROPOSAL GENERATION WORKFLOW

### Trigger
User clicks "Generate Proposal" in opportunity record (internal rep or system automation after form submission).

### Step 1: Run QA Checklist
- Validate all requirements from Section E
- If any fail → Show error message, do NOT proceed
- If all pass → Proceed to Step 2

### Step 2: Load Data from Opportunity Record
- Fetch opportunity record from database
- Fetch company record (by company_id)
- Fetch primary contact record (by primary_contact_id)
- Fetch all asset line items for this opportunity
- Fetch all pickup locations for this opportunity
- Fetch compliance requirements (if any)
- Fetch pricing table for reference

### Step 3: Build Merge Field Map
- Create key-value map of all `[FIELD]` values from Section D
- Validate all merge fields have values (no null/empty critical fields)
- Log any warnings (e.g., "Sales rep phone not found, using main line")

### Step 4: Render Proposal
- Load proposal template (DOCX or Google Doc template)
- Replace all merge fields with values from merge field map
- For repeating sections (device tables), iterate through `asset_line_items`:
  - Include only items where `qualifies_for_buyback = true`
  - Use line item data: model, quantity, unit price, subtotal
- For conditional sections (data destruction, compliance):
  - Include "Data Security" section only if `data_bearing_equipment = true`
  - Include "Indemnification" section only if `indemnification_required = true`
  - Include "Insurance" section only if `insurance_required = true`
- Generate final document

### Step 5: Save Proposal Document
- Save rendered document to cloud storage (Google Drive, AWS S3, or similar)
- Generate unique document URL (e.g., `https://storage.techreboot.com/proposals/opp_5f6e7d8c_v1.docx`)
- Create `proposal` record in database with:
  - `proposal_id` (UUID)
  - `opportunity_id` (link to opportunity)
  - `proposal_version` (1, 2, 3 if regenerated)
  - `proposal_url` (link to document)
  - `proposal_format` ("DOCX")
  - `proposal_generated_date` (timestamp)
  - `generated_by_user_id` (sales rep ID)
  - `content_sections` (JSON map of all merge field values, for audit trail)

### Step 6: Update Opportunity Record
- Update `opportunity.proposal_document_id` (link to proposal record)
- Update `opportunity.generated_proposal_url` (link to document)
- Update `opportunity.proposal_status` = "Generated"
- Log activity: "Proposal generated at [timestamp] by [rep]"

### Step 7: Generate Email Draft
- Create email template:
  ```
  To: [PRIMARY_CONTACT_EMAIL]
  CC: [SALES_REP_EMAIL]
  Subject: Conditional Guaranteed Buyback Proposal — [COMPANY_NAME] | [TURNAROUND_DAYS]-Day Turnaround
  
  Body:
  Hi [PRIMARY_CONTACT_FIRST],
  
  Attached is our conditional guaranteed buyback proposal for [COMPANY_NAME]'s 
  surplus technology equipment.
  
  Quick Summary:
  - Total Equipment: [DEVICE_COUNT_TOTAL] devices
  - Projected Qualifying Value: UP TO $[PROJECTED_QUALIFYING_VALUE]
  - Turnaround: [TURNAROUND_DAYS] calendar days from pickup
  - No-Cost Pickup: Full white-glove service included
  
  Next Steps:
  1. Review the attached proposal
  2. Confirm any questions with [SALES_REP_NAME] at [SALES_REP_PHONE] or [SALES_REP_EMAIL]
  3. Sign and return to schedule pickup
  
  Looking forward to working with [COMPANY_NAME]!
  
  Best regards,
  [SALES_REP_NAME]
  VP Business Development
  TechReboot, Inc.
  [PHONE] | [EMAIL]
  ```
- Show email draft in UI for rep review before sending
- Allow rep to customize message

### Step 8: Offer Rep Two Actions

**Option A: Send Now**
- Send email to primary contact with proposal attached
- Log email send in HubSpot activity
- Update deal stage to "Proposal Sent"
- Create follow-up task: "Follow up on [Company] proposal" (due 5 business days)
- Redirect to proposal tracking view

**Option B: Save Draft (Don't Send Yet)**
- Save email draft to opportunity record
- Queue for manual approval (if management approval required)
- Show: "Email saved. Awaiting management approval before send."
- Create task: "Approve proposal email for [Company]" (owner = manager)

### Step 9: Approval Workflow (If Needed)

**If automatic approvals were triggered (Stage 7):**
- **Pricing approval required:** Create task for Bruce with proposal details
- **Management approval required:** Create task for Michael Stott with proposal details
- Task includes: proposal link, value, device count, any flagged items

**Bruce/Manager action:**
- Review proposal
- Approve → Proposal moves to "Approved" status, email sent
- Reject with changes → Route back to opportunity for editing, regenerate proposal

### Step 10: Confirmation & Tracking

**On successful send:**
- Show confirmation: "Proposal sent to [contact email] ✅"
- Display proposal URL for rep to download/share
- Show email preview (what was sent)
- Display follow-up task details
- Offer "Quick Actions": Download PDF, Share link, Send follow-up reminder, Log call

---

# PART 5: FINAL BUILD PLAN

## Recommended Tech Stack

### Option 1: Minimum Viable Version (MV)
**Timeline:** 4–6 weeks  
**Cost:** Low  
**Scope:** Core automation, manual approval steps

| Component | Tool | Why |
|-----------|------|-----|
| Landing page/intake form | HubSpot Forms + custom CSS | Free, native to HubSpot, captures data directly to CRM |
| Data storage (companies, contacts, opportunities) | HubSpot CRM | Native, no migration, familiar to team |
| Automation/workflow | HubSpot Workflows + Make.com | HubSpot handles CRM sync; Make handles proposal generation + API calls |
| Pricing table | Google Sheets (shared) | Simple lookup, easy to update, version control |
| Proposal generation | Google Docs (template) + Make API | Inexpensive, template-based merge fields, Google Drive storage |
| PDF conversion | Make's PDF converter or smallpdf.com API | Converts DOCX to PDF for email |
| Email delivery | HubSpot workflows or Gmail (MCP) | Native to HubSpot or use Make + Gmail |
| File storage | Google Drive | Free tier sufficient, easy permissions |
| Approval/review tasks | HubSpot tasks | Native to CRM |
| Reporting | HubSpot reports + Google Sheets | Standard HubSpot dashboards |

### Option 2: Better Version (BV)
**Timeline:** 8–12 weeks  
**Cost:** Medium  
**Scope:** Native HubSpot custom objects, automated approvals, richer UI

| Component | Tool | Why |
|-----------|------|-----|
| Landing page/intake form | HubSpot Forms + custom portal (Webflow or WordPress) | Better UX, can handle multi-step forms, progress saving |
| Data storage | HubSpot CRM + Custom Objects | Better schema design, relationships, custom logic |
| Automation/workflow | HubSpot Workflows + n8n (self-hosted or cloud) | More powerful than Make, better error handling, native HubSpot SDK |
| Pricing table | Supabase (PostgreSQL) | Structured, queryable, versioning support, API-first |
| Proposal generation | PandaDoc or Formstack Documents API | More powerful merge fields, conditional sections, e-signature |
| PDF conversion | Native to PandaDoc or Formstack | Auto-converted, no extra step |
| Email delivery | HubSpot Workflows + custom templates | Native templates, rich formatting |
| File storage | Supabase Storage or AWS S3 | More reliable, versioning, programmatic access |
| Approval/review tasks | HubSpot workflows + custom notifications | Richer approval chains, conditional routing |
| Reporting | HubSpot reports + Metabase (self-hosted) | Custom dashboards, better visualizations |

### Option 3: Fully Automated Version (FA)
**Timeline:** 12–16 weeks  
**Cost:** High  
**Scope:** Custom application, AI-driven QA, real-time sync, full API integration

| Component | Tool | Why |
|-----------|------|-----|
| Landing page/intake form | React app (built in-house or via Retool) | Full control, mobile-optimized, real-time validation |
| Data storage | Supabase (PostgreSQL) | Primary database, normalized schema, audit trail |
| HubSpot sync | Supabase + HubSpot API (or native integration via Zapier) | Bidirectional sync, real-time updates |
| Automation/workflow | n8n (cloud or self-hosted) + custom Node.js microservices | Complex logic, parallel workflows, retry logic |
| Pricing table | Supabase + caching layer (Redis) | Fast lookups, versioning, audit trail |
| Proposal generation | Custom Node.js service (uses Templating engine + docxtemplater or similar) | Maximum flexibility, can generate DOCX/PDF natively |
| Email delivery | SendGrid or AWS SES (via n8n or custom service) | High volume, reliable, detailed tracking |
| File storage | AWS S3 + CloudFront CDN | Scalable, secure, versioning, auto-retention policies |
| Approval/review | Custom logic in n8n + HubSpot deal status mapping | Complex approval chains, conditional routing, escalation |
| Reporting | Business intelligence tool (Tableau, Looker, or Metabase) | Custom dashboards, predictive analytics, automated alerts |
| Monitoring/logging | Sentry + CloudWatch | Proactive error detection, performance monitoring |

---

## Recommended Build Path: Start with Option 1 (MV), Iterate to Option 2 (BV)

**Why:**
- **Option 1 is achievable in 4–6 weeks** using mostly no-code tools your team already knows (HubSpot + Google)
- **Can launch MVP and start gathering real usage data** (what reps actually do, what errors occur)
- **Option 2 upgrades are modular** — can swap out individual components (e.g., upgrade from Google Docs to PandaDoc) without rearchitecting the whole system
- **Reduces risk** of building for a theoretical workflow vs. real workflow

---

## PART 5A: MINIMUM VIABLE VERSION (4–6 Weeks)

### Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                     TECHREBOOT REP                          │
│                (Internal User or District)                  │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
            ┌────────────────────────┐
            │   HubSpot Landing      │
            │     Page / Form        │
            │  (Form on Portal)      │
            └────────┬───────────────┘
                     │ Form submission
                     ▼
            ┌────────────────────────┐
            │   HubSpot Contact,     │
            │  Company, Deal Objects │
            │  (Auto-created)        │
            └────────┬───────────────┘
                     │
                     ▼
            ┌────────────────────────┐
            │   HubSpot Workflows    │
            │  (Detect new deal,     │
            │  validate fields)      │
            └────────┬───────────────┘
                     │
        ┌────────────┴────────────┐
        │                         │
        ▼                         ▼
   ┌─────────────┐         ┌─────────────┐
   │ QA Passed?  │         │   Needs     │
   │   YES       │         │  Approval?  │
   └─────┬───────┘         └─────┬───────┘
         │                       │ YES
         │ NO                    ▼
         │               ┌──────────────────┐
         │               │  Create Review   │
         │               │   Task (Bruce)   │
         │               └──────┬───────────┘
         │                      │
         │                ┌─────┴─────┐
         │                │ Approved? │
         │                └──────┬────┘
         │                       │ YES
         └───────────┬───────────┘
                     │
                     ▼
            ┌────────────────────────┐
            │   Make Automation      │
            │  (Pull opportunity     │
            │   data from HubSpot)   │
            └────────┬───────────────┘
                     │
                     ▼
            ┌────────────────────────┐
            │ Google Sheets API      │
            │ (Fetch pricing table   │
            │  for line items)       │
            └────────┬───────────────┘
                     │
                     ▼
            ┌────────────────────────┐
            │  Calculate pricing &   │
            │  qualification status  │
            └────────┬───────────────┘
                     │
                     ▼
            ┌────────────────────────┐
            │  Google Docs Template  │
            │  (Insert merge fields, │
            │  render to DOCX)       │
            └────────┬───────────────┘
                     │
                     ▼
            ┌────────────────────────┐
            │  Save to Google Drive  │
            │  (Sharable link)       │
            └────────┬───────────────┘
                     │
                     ▼
            ┌────────────────────────┐
            │  Generate email draft  │
            │  (Merge fields)        │
            └────────┬───────────────┘
                     │
                     ▼
            ┌────────────────────────┐
            │  HubSpot Workflow      │
            │  (Create follow-up     │
            │   task, update deal)   │
            └─────────────────────────
```

### Step-by-Step Implementation

#### Phase 1: Setup & Data Foundation (Week 1)

**Tasks:**
1. **Design HubSpot Custom Properties** (see Part 3)
   - Add all opportunity, line item, pickup location, and compliance properties to HubSpot
   - Export as CSV for documentation
   - Note which properties are dropdowns (need value lists)

2. **Create Pricing Reference Table in Google Sheets**
   - Column: Asset Category, Manufacturer, Model, CPU Tier, Condition, Locked Status, Unit Price
   - Populate from `TechReboot_Buyback_Pricing.docx`
   - Share with Make.com automation (will fetch this sheet)
   - Set permissions to "view only" for team

3. **Create HubSpot Landing Page / Form**
   - Use HubSpot Form tool (built into portal)
   - Field mapping:
     - Org name → Company name (auto-create if new)
     - Contact → Contact record (auto-create if new)
     - Address → Company address
     - Turnaround → Deal custom property
     - Line items → Store as JSON in a single deal custom field (simpler for MVP)
   - Form sections (collapsible):
     - Organization (A)
     - Contact (B)
     - Equipment (C) — repeatable rows stored as JSON
     - Data Requirements (E)
     - Terms (F)
   - Submit action: Create company, contact, deal + trigger Make automation

4. **Set Up Google Drive Folder Structure**
   - `/TechReboot Proposals/`
     - `Templates/`
       - `Conditional_Guaranteed_Buyback_Proposal_Template.docx` (Google Docs)
       - `Email_Draft_Template.txt`
     - `Generated/`
       - `/2026-07/` (by month)
         - `Pompton_Lakes_Schools_Proposal_v1.docx`
         - `Pompton_Lakes_Schools_Proposal_v2.docx` (if regenerated)

---

#### Phase 2: Proposal Template & Merge Field Setup (Week 1–2)

**Tasks:**

1. **Convert Pompton Lakes Proposal to Google Docs Template**
   - Open the canonical proposal (from project files)
   - Recreate in Google Docs for easier template merge
   - Replace all variable content with merge field placeholders:
     - `{{company.name}}`
     - `{{contact.first_name}}`
     - `{{turnaround_days}}`
     - `{{projected_qualifying_value}}`
     - etc. (see Part 4, merge field reference)
   - For device tables:
     - Use text like `{{#devices_qualified}}{{manufacturer}} {{model}} - {{quantity}} @ ${{unit_price}}\n{{/devices_qualified}}`
     - Make will replace with actual line items
   - Save as `/Templates/Conditional_Guaranteed_Buyback_Proposal_Template.docx`
   - Create a second copy for email body template

2. **Document All Merge Fields**
   - Export merge field reference (Part 4, Section D) to a CSV:
     - Column A: Merge field name (e.g., `{{company.name}}`)
     - Column B: HubSpot property path
     - Column C: Example value
     - Column D: Section where used
   - Share with Make.com dev (they'll use this for Make workflow)

3. **Test Merge Fields Manually**
   - Use Google Docs' built-in "Mail Merge" feature (if available) or plan for Make
   - Manually test one complete proposal generation using Pompton Lakes data
   - Verify all fields populate correctly, formatting preserved

---

#### Phase 3: Make.com Automation Workflow (Week 2–3)

**Tasks:**

1. **Create Make.com Account & Authorize Integrations**
   - Sign up for Make.com (free tier allows 1,000 operations/month — sufficient for MVP)
   - Install Make browser extension (for easy integration setup)
   - Authorize connections to:
     - HubSpot (OAuth)
     - Google Drive (OAuth)
     - Google Sheets (for pricing table lookup)
     - Gmail (for email draft generation)

2. **Build Make Workflow: "Generate Proposal"**

   **Trigger:** HubSpot workflow sends event "Proposal generation requested" (or Make polls HubSpot deal status = "Proposal Draft")

   **Steps:**

   ```
   Step 1: Receive HubSpot trigger
   - Opportunity ID from HubSpot
   
   Step 2: Fetch opportunity data from HubSpot
   - Use "HubSpot Get Deal" module
   - Retrieve: company name, contact, address, device list (JSON), turnaround, all custom fields
   - Also fetch associated company and contact records
   
   Step 3: Parse device line items (JSON)
   - Line items stored in deal as JSON string (from form submission)
   - Parse JSON to extract: manufacturer, model, quantity, condition, power-on, locked status
   
   Step 4: Look up pricing for each line item
   - For each device:
     - Query Google Sheets (pricing table)
     - Match by: category + manufacturer + model + condition + locked status
     - Retrieve unit price
   - If no match: Mark as "Review required", note reason
   
   Step 5: Calculate totals
   - Qualified subtotal = sum of (quantity × unit price) for matched devices
   - Build JSON with all line item prices
   
   Step 6: Build merge field map
   - Create JSON object with all merge field values:
     ```
     {
       "company_name": "Pompton Lakes Schools",
       "contact_first_name": "John",
       "contact_last_name": "Briggs",
       "turnaround_days": 7,
       "projected_qualifying_value": "$10,875.00",
       "device_table": [
         { "manufacturer": "ASUS", "model": "Chromebook C204", "quantity": 200, "unit_price": "$15.00", "subtotal": "$3,000.00" },
         ...
       ],
       ...
     }
     ```
   
   Step 7: Generate proposal document
   - Use "Google Docs Create Document from Template" module (or use a custom HTTP request)
   - Copy proposal template to working directory
   - Use text replacement to inject merge field values
   - Alternative: Use "JSON to DOCX" service (e.g., docxtemplater API call)
   
   Step 8: Save to Google Drive
   - Use "Google Drive Upload File" module
   - Save as: `/Generated/2026-07/{{company_name}}_Proposal_v{{proposal_version}}.docx`
   - Get sharable link
   
   Step 9: Generate email draft
   - Build email body with merge fields (turnaround, value, device count)
   - Create email subject: "Conditional Guaranteed Buyback Proposal — {{company_name}} | {{turnaround_days}}-Day Turnaround"
   - Store in HubSpot as custom field (don't send yet)
   
   Step 10: Update HubSpot deal
   - Update deal custom properties:
     - `generated_proposal_url` = Google Drive link
     - `proposal_status` = "Generated"
     - `email_draft_body` = draft email text
   - Create HubSpot activity: "Proposal generated by Make workflow"
   
   Step 11: Create HubSpot task
   - Task: "Follow up on {{company_name}} proposal"
   - Due date: 5 business days from today
   - Owner: Sales rep
   - Description: "Review generated proposal. Send email or route for approval if needed."
   
   Step 12: Notify rep (optional)
   - Send Slack message or email to rep:
     "✅ Proposal generated for {{company_name}}. Review: {{generated_proposal_url}}"
   ```

3. **Handle Errors Gracefully**
   - If pricing lookup fails: "Review required — pricing not found"
   - If HubSpot fetch fails: "Error retrieving opportunity data. Contact support."
   - Log all errors to Make's built-in history
   - Create fallback: Queue for manual generation if automated steps fail

---

#### Phase 4: HubSpot Workflow Automation (Week 2–3)

**Tasks:**

1. **Create HubSpot Workflow: "Trigger Proposal Generation"**
   - Trigger: Deal created + all required fields populated (company, contact, address, line items)
   - Condition 1: If QA validation passes
     - Check: Company name not empty
     - Check: Contact email not empty
     - Check: Address not empty
     - Check: At least one device line item
     - Check: Turnaround term selected
     - Action: Enroll in "Auto-Generate Proposal" workflow
   - Condition 2: If QA validation fails
     - Action: Create task "QA Review — Missing fields for {{company.name}}"
     - Action: Update deal stage to "Needs Data"

2. **Create HubSpot Workflow: "Auto-Generate Proposal"**
   - Trigger: Enrollment from above workflow
   - Action: Send event to Make.com (via webhook or HubSpot API call)
     - Payload: `{"operation": "generate_proposal", "deal_id": "{{dealId}}"}`
   - Wait for Make.com response (or use async callback)
   - On success: Update deal status to "Proposal Generated"
   - On failure: Create task for rep "Proposal generation failed — manual review needed"

3. **Create HubSpot Workflow: "Send Follow-Up Task After Proposal"**
   - Trigger: Deal property "proposal_status" = "Generated"
   - Action: Create task
     - Subject: "Follow up on {{company.name}} proposal"
     - Due date: 5 business days
     - Description: "Review proposal, send to contact, or route for approval"
   - Action: Update deal stage to "Proposal Sent" (optional — rep can do this)

---

#### Phase 5: Testing & QA (Week 3–4)

**Tasks:**

1. **End-to-End Test with Pompton Lakes Data**
   - Fill out landing form with Pompton Lakes Schools data
   - Verify deal created in HubSpot
   - Trigger Make workflow (manually, if needed)
   - Verify proposal generated and saved to Google Drive
   - Download proposal, check:
     - All merge fields populated correctly
     - Device table complete and accurate
     - Turnaround term consistent across all sections
     - No blank/null values in critical fields
     - Formatting intact (no text overlaps, correct page breaks)
   - Verify email draft created with correct body and subject

2. **Test Variations**
   - Multi-site pickup: Add secondary location, verify address captures all
   - Data destruction required: Verify "Data Security" section included
   - Review required items: Add device with unknown condition, verify "Review required" flag shown
   - Custom turnaround: Select "21 days", verify merge fields update

3. **Error Handling Tests**
   - Submit form with missing company name → Verify "Required field" error
   - Submit with no line items → Verify error or handle gracefully
   - Pricing lookup fails for device → Verify "Review required" message
   - Google Drive permission error → Verify Make logs error, task created for manual intervention

4. **Rep UAT (User Acceptance Testing)**
   - Give rep test access to landing form
   - Ask rep to submit a sample deal
   - Rep reviews generated proposal
   - Rep provides feedback: "Looks great, only change [X]" or "This needs [Y]"
   - Iterate on template/workflow based on feedback

---

#### Phase 6: Approval Workflow (Week 4)

**Tasks:**

1. **Build HubSpot Workflow: "Route to Bruce if Review Required"**
   - Trigger: Deal created with review-required devices
   - Condition: Deal property "review_required_subtotal" > $0
   - Action: Create task for Bruce
     - Subject: "Pricing review required — {{company.name}}"
     - Description: "Review required for [list devices]. Current value range: $[X] - $[Y]. Approve standard pricing or propose override."
     - Attachment: Link to generated proposal
   - Action: Update deal stage to "Needs Review"
   - Wait for: Bruce marks task complete + updates deal with decision
   - Action: Trigger proposal regeneration (if pricing changed) or move to "Approved"

2. **Build HubSpot Workflow: "Route to Michael if Value > $15k"**
   - Trigger: Deal created with `projected_qualifying_value` > $15,000
   - Action: Create task for Michael Stott
     - Subject: "Management approval required — {{company.name}} (${{projected_qualifying_value}})"
     - Description: "Please review and approve proposal for [company]. Device count: [X]. Turnaround: [Y] days."
   - Action: Update deal stage to "Awaiting Approval"
   - Wait for: Michael marks task complete + approves
   - Action: Trigger email send workflow

3. **Email Send Workflow**
   - Trigger: Deal stage = "Approved" OR all approvals completed
   - Action: Send email to primary contact
     - Subject: "Conditional Guaranteed Buyback Proposal — {{company.name}} | {{turnaround_days}}-Day Turnaround"
     - Body: Merge fields (value, device count, turnaround)
     - Attachment: Generated proposal PDF (download from Google Drive, convert to PDF via Make)
   - Action: Update deal stage to "Proposal Sent"
   - Action: Log email send to HubSpot activity
   - Action: Create follow-up task "Follow up on proposal" (due 5 days)

---

#### Phase 7: Launch & Documentation (Week 4–5)

**Tasks:**

1. **Create Runbook for Reps**
   - Document: "How to Generate a Proposal"
   - Steps:
     1. Fill out landing form (with required vs. optional field guidance)
     2. Submit
     3. Check HubSpot for created deal
     4. Wait for automation (or manually trigger if needed)
     5. Download proposal from generated email or HubSpot deal
     6. Review for accuracy
     7. Send to customer or route for approval (if flagged)
   - Include screenshots and example data

2. **Create FAQ for Known Issues**
   - "Pricing not found for device X" → How to handle (call Bruce, use manual override)
   - "Proposal didn't generate" → Check Make.com logs, check HubSpot deal data completeness
   - "Turnaround term appears twice in proposal" → Expected behavior (one in header, one in timeline)

3. **Train Sales Team**
   - Demo the workflow end-to-end
   - Let each rep submit a test deal and generate a proposal
   - Answer questions
   - Collect feedback for Phase 2

4. **Go-Live**
   - Enable landing form publicly (or limited to rep logins)
   - Announce to sales team: "Proposal automation live — start using for new opportunities"
   - Monitor Make.com logs for errors
   - Be ready for quick fixes

---

### HubSpot Property Setup for MVP

**Custom Properties to Create:**

**Deal Properties:**
- `turnaround_days` (number) — Required
- `turnaround_custom` (text) — Optional
- `proposal_type` (dropdown: Conditional guaranteed, Recycling-only, Mixed, Service-only)
- `guaranteed_subtotal` (currency) — Auto-calculated by Make
- `review_required_subtotal` (currency) — Auto-calculated by Make
- `device_count_total` (number) — Auto-calculated by Make
- `projected_qualifying_value` (currency) — Auto-calculated by Make
- `payment_method` (dropdown: Check, ACH, Card, Donation, None)
- `offer_validity_days` (number)
- `title_transfer_rule` (dropdown)
- `risk_of_loss_transfer` (dropdown)
- `pickup_cost` (dropdown)
- `white_glove_service_included` (checkbox)
- `labor_included` (checkbox)
- `packing_materials_included` (checkbox)
- `freight_included` (checkbox)
- `on_site_inventory_required` (checkbox)
- `warehouse_reconciliation_required` (checkbox)
- `data_bearing_equipment` (checkbox)
- `data_process_required` (dropdown: Sanitization, Destruction, Recycling, Unknown)
- `data_standard` (dropdown: NIST 800-88, NAID, Certificate, District-specific, Unknown)
- `certificate_of_destruction` (checkbox)
- `special_compliance_required` (checkbox)
- `special_compliance_types` (multi-select: FERPA, HIPAA, CJIS, State law, Internal policy)
- `indemnification_required` (checkbox)
- `insurance_required` (checkbox)
- `generated_proposal_url` (text)
- `proposal_status` (dropdown: Draft, Generated, Sent, Accepted, Declined, Won, Lost)
- `email_draft_body` (long text)
- `proposal_document_id` (text)
- `bid_source_id` (text — reference)
- `internal_reviewer_id` (text — HubSpot user lookup)
- `risk_flags` (long text)
- `confidence_score` (number 0-100)
- `data_source_audit_trail` (long text)

**Contact Properties:**
- `is_decision_maker` (checkbox)
- `is_primary_contact` (checkbox)
- `role_in_process` (dropdown)
- `preferred_contact_method` (dropdown)
- `extension` (text)

**Company Properties:**
- `organization_type` (dropdown)
- `domain` (text)
- `region` (dropdown — auto-calculated from state)
- `data_source` (dropdown)

---

### Landing Form Field Mapping (HubSpot Form)

| Form Field | HubSpot Property | Type | Required |
|-----------|-----------------|------|----------|
| Organization Name | Company name | Single-line text | YES |
| Organization Type | Company organization_type | Dropdown | YES |
| Website | Company website | URL | NO |
| Main Address | Company address | Text | YES |
| City | Company city | Single-line text | YES |
| State | Company state | Dropdown | YES |
| ZIP | Company zip | Single-line text | YES |
| Pickup Address (if different) | Deal custom field "pickup_address" | Text | NO |
| First Name | Contact firstname | Single-line text | YES |
| Last Name | Contact lastname | Single-line text | YES |
| Email | Contact email | Email | YES |
| Phone | Contact phone | Phone | YES |
| Extension | Contact extension | Single-line text | NO |
| Title | Contact jobtitle | Single-line text | YES |
| Role in Process | Contact role_in_process | Dropdown | YES |
| Is Decision-Maker? | Contact is_decision_maker | Checkbox | YES |
| Device 1: Category | Deal custom field "line_items_json" (parsed) | Text (stored as JSON) | YES (at least 1) |
| Device 1: Manufacturer | "" | Text | YES |
| Device 1: Model | "" | Text | YES |
| Device 1: Quantity | "" | Number | YES |
| Device 1: Condition | "" | Dropdown | YES |
| Device 1: Power-On | "" | Dropdown | YES |
| Device 1: Locked/MDM | "" | Dropdown | YES |
| + Add Another Device | "" | Repeat rows | NO |
| Turnaround Term | Deal turnaround_days | Radio / Dropdown | YES |
| Data-Bearing Equipment? | Deal data_bearing_equipment | Checkbox | YES |
| Data Process | Deal data_process_required | Dropdown | YES |
| Data Standard | Deal data_standard | Dropdown | YES |
| Certificate of Destruction? | Deal certificate_of_destruction | Checkbox | YES |
| Payment Method | Deal payment_method | Dropdown | NO |
| Offer Validity | Deal offer_validity_days | Number | YES |
| Indemnification? | Deal indemnification_required | Checkbox | NO |
| Notes | Deal notes | Long text | NO |

---

### File Structure & Naming Conventions

```
Google Drive/
├── TechReboot Proposals/
│   ├── Templates/
│   │   ├── Conditional_Guaranteed_Buyback_Proposal_Template.docx
│   │   └── Email_Draft_Template.txt
│   └── Generated/
│       ├── 2026-07/
│       │   ├── Pompton_Lakes_Schools_Proposal_v1.docx
│       │   ├── Pompton_Lakes_Schools_Proposal_v2.docx
│       │   └── [Organization]_Proposal_v[#].docx
│       └── 2026-08/
│           ├── [Organization]_Proposal_v1.docx
│           └── ...

GitHub/
└── techreboot-proposal-automation/
    ├── docs/
    │   └── BUILD_PLAN.md (this document)
    └── data/
        ├── TechReboot_Buyback_Pricing.csv
        ├── pricing_table_schema.json
        ├── merge_fields_reference.csv
        └── device_categories.json
```

---

### Make.com Workflow Exports (Blueprints)

**For MVP, Make workflows should be documented as:**
1. JSON export of workflow (Make allows export/import)
2. Step-by-step setup guide for new Make users
3. Screenshots of each module configuration

**Key workflows:**
1. "Trigger: HubSpot Deal Created → Validate QA → Route or Generate"
2. "Generate Proposal from HubSpot Deal Data"
3. "Calculate Pricing & Qualification Status"
4. "Send Email & Create Follow-Up Task"

---

## PART 5B: BETTER VERSION (8–12 Weeks)

Upgrades to MVP:
- **Custom Objects in HubSpot** → Replace JSON line items with proper relational data
- **Webflow Landing Page** → Better UX, multi-step forms, progress saving
- **n8n Automation** → More powerful workflows, better error handling
- **Supabase** → Pricing table and proposal templates as API resources
- **PandaDoc** → Native proposal generation with conditional sections and e-signature
- **Metabase** → Custom dashboards and reporting

(Detailed specs for BV omitted for length, but follow same pattern as MV)

---

## PART 5C: FULLY AUTOMATED VERSION (12–16 Weeks)

Upgrades to BV:
- **Custom React App** → Full control over UI/UX
- **Supabase as Primary DB** → Replace HubSpot custom objects with Supabase tables
- **n8n with Custom Microservices** → Complex approval logic, parallel workflows
- **Custom DOCX Generation** → Node.js + docxtemplater, generate DOCX programmatically
- **Full API Sync Loop** → HubSpot ↔ Supabase ↔ Custom App bidirectional sync

(Detailed specs omitted for length)

---

## BUILD CHECKLIST & TIMELINE

### Pre-Launch Checklist (MV)

| Task | Owner | Due | Status |
|------|-------|-----|--------|
| Design HubSpot properties | Ops | Week 1 | ☐ |
| Create pricing reference sheet | Ops | Week 1 | ☐ |
| Build HubSpot landing form | Ops/Marketer | Week 1 | ☐ |
| Set up Google Drive folder structure | Ops | Week 1 | ☐ |
| Convert Pompton Lakes proposal to Google Docs | Ops | Week 2 | ☐ |
| Document merge fields | Ops | Week 2 | ☐ |
| Create Make.com account & authorize integrations | Tech | Week 2 | ☐ |
| Build Make workflow: Generate Proposal | Tech | Week 3 | ☐ |
| Build HubSpot workflows: QA validation, approval routing | Tech | Week 3 | ☐ |
| Build HubSpot workflow: Send email & follow-up task | Tech | Week 3 | ☐ |
| End-to-end test with Pompton Lakes data | QA | Week 3 | ☐ |
| Test variations (multi-site, compliance, etc.) | QA | Week 4 | ☐ |
| Test error scenarios | QA | Week 4 | ☐ |
| Rep UAT & feedback collection | Ops/Tech | Week 4 | ☐ |
| Iterate on template based on feedback | Tech | Week 4 | ☐ |
| Create runbook for reps | Ops | Week 5 | ☐ |
| Create FAQ for known issues | Ops | Week 5 | ☐ |
| Train sales team | Ops | Week 5 | ☐ |
| Go-live | Ops | Week 5 | ☐ |
| Monitor Make.com logs for errors (first 2 weeks) | Tech | Week 5–6 | ☐ |

### Success Metrics (What to Track)

| Metric | Target | How to Measure |
|--------|--------|---|
| Proposal generation success rate | >95% | Make.com logs: successful runs / total runs |
| Merge field accuracy | 100% | Manual review: no null/blank fields in 10 sample proposals |
| Turnaround term consistency | 100% | Manual review: same value in header, timeline, terms |
| Time to generate proposal | <5 min | Make.com logs: start → end timestamp |
| Rep satisfaction (NPS) | >7/10 | Survey: "Easy to use? Saves time?" |
| Proposal acceptance rate | >70% | HubSpot: Accepted deals / Total proposals sent |
| Time from form to email sent | <30 min | HubSpot activity log: form submit → email sent |

---

## PART 5D: RISKS & FAILURE POINTS

| Risk | Impact | Mitigation |
|------|--------|------------|
| **Pricing table incomplete** | Generated prices missing, route to Bruce too often | Keep pricing table updated; test with all device categories used by customers; route unknown models to Bruce (acceptable for MVP) |
| **Turnaround term inconsistency** (our original issue) | Proposal contradicts itself, customer confusion | Use single source-of-truth field; test all sections merge correctly; add QA check "all sections use same turnaround value" |
| **Form field too complex, reps skip it** | Incomplete data, poor proposals | Simplify form (test with rep), mark truly required fields clearly, provide examples, allow partial submission + follow-up |
| **Make.com API rate limits** | Automation stalls during high volume | Use Make's queue/delay modules; batch processing if needed; upgrade Plan if necessary |
| **Google Drive sharing issues** | Generated proposals not accessible to customer | Test permissions in advance; use "Anyone with link" sharing; provide direct download link in email, not just Drive link |
| **Merge field errors (null/blank)** | Unprofessional proposal with missing data | Add validation in Make: check all critical fields before merge; test with incomplete data; show warnings in email draft before send |
| **Contact records duplicate in HubSpot** | Wrong contact linked to proposal, email goes to wrong person | Use exact email match for contact dedup; add manual verification step if emails are similar (e.g., jbriggs@plps.org vs jbriggs+copy@plps.org) |
| **Company name auto-create creates duplicates** | Pompton Lakes / Pompton Lakes Schools / Pompton Schools all separate | Use strict company matching (domain first, then name); avoid auto-create unless match fails; log unresolved records for review |
| **Multi-site pickup forgotten in proposal** | Proposal mentions only one address, customer confused | Add secondary pickup location to proposal template section; test multi-site flows |
| **Conditional sections (data destruction) don't show** | Missing sections, incomplete proposal | Test all conditional logic (if data_bearing_equipment, if compliance_required, etc.); manual review proposals before send |
| **Email bounces to customer** | Customer never receives proposal | Validate email addresses on form submit; use email verification service; have rep confirm email before send |
| **Proposal PDF formatting broken** | Unreadable proposal (text overlaps, wrong fonts) | Test PDF generation with real data; use standard fonts; leave margins; test on multiple devices |

---

## PART 5E: WHAT STAYS MANUAL UNTIL PROVEN

| Task | Why | Criteria to Automate Later |
|------|-----|---|
| **Pricing overrides** | Complex business logic, needs approval | After 20+ proposals, track override % and reasons. If >10% overrides, re-evaluate pricing table |
| **Multi-site logistics** | Hard to estimate labor/pallets without seeing site | After 10 multi-site pickups, establish rough rules (e.g., each site +1 pallet, +2 hrs labor) |
| **Complex compliance** | HIPAA, state data laws need legal review | Build library of templates for each known compliance type, then automate routing |
| **Proposal PDF conversion** | Google Docs → PDF can have formatting issues | Use reputable service (Formstack, PandaDoc), test thoroughly, then automate |
| **Email send (first iteration)** | Want rep to review email before it goes out | After 50 emails sent, if 0 corrections needed, automate |
| **Deal stage updates** | Don't want to auto-advance deal if rep disagrees | After 3 months, review if auto-stage changes are correct >95% of the time |
| **Customer follow-up calls** | Timing matters (don't call before customer reviews) | Rep manually creates task; after 3 months, if follow-up timing is consistent, automate |

---

## CONCLUSION

This build plan takes you from **zero to MVP in 4–6 weeks**, using mostly no-code tools (HubSpot + Google + Make.com). You'll have a working proposal automation system that reduces rep time from hours of copy-paste and manual formatting to minutes of form-fill and email-send.

**Key success factors:**
1. Keep MVP scope tight (core workflow only)
2. Use HubSpot as single source of truth for CRM data
3. Test with real rep feedback early
4. Iterate to Better Version after validating MVP with 10+ proposals

**Next Action:** Start Phase 1 this week. You'll have working automation in 4 weeks, ready for live usage.

---

**END OF BUILD PLAN**

---

# APPENDIX: EXAMPLE DATA FLOW (Pompton Lakes)

## Form Submission Example

```json
{
  "organization_name": "Pompton Lakes Schools",
  "organization_type": "K-12 District",
  "website": "https://www.plps.org",
  "main_address": "237 Van Ave",
  "city": "Pompton Lakes",
  "state": "NJ",
  "zip": "07442",
  "contact_first_name": "John",
  "contact_last_name": "Briggs",
  "contact_email": "jbriggs@plps.org",
  "contact_phone": "(973) 835-7100",
  "contact_extension": "1552",
  "contact_title": "Technical Support Specialist",
  "contact_role": "IT/Technology",
  "contact_is_decision_maker": true,
  "line_items": [
    {
      "category": "Chromebook",
      "manufacturer": "ASUS",
      "model": "C204",
      "quantity": 200,
      "quantity_type": "Confirmed",
      "condition": "Good",
      "power_on": "Yes",
      "locked_status": "Unlocked",
      "cracked_screens": "No",
      "missing_components": "No"
    },
    {
      "category": "Laptop",
      "manufacturer": "Dell",
      "model": "Latitude 3120",
      "quantity": 25,
      "quantity_type": "Confirmed",
      "condition": "Good",
      "power_on": "Yes",
      "locked_status": "Unlocked",
      "cracked_screens": "No",
      "missing_components": "No"
    },
    {
      "category": "Laptop",
      "manufacturer": "HP",
      "model": "ProBook x360 11 G5 EE",
      "quantity": 200,
      "quantity_type": "Confirmed",
      "condition": "Good",
      "power_on": "Yes",
      "locked_status": "Unlocked",
      "cracked_screens": "No",
      "missing_components": "No"
    }
  ],
  "data_bearing_equipment": true,
  "data_process": "Data sanitization",
  "data_standard": "NIST 800-88",
  "certificate_of_destruction": true,
  "turnaround_days": 7,
  "payment_method": "Check",
  "offer_validity_days": 30,
  "title_transfer_rule": "Upon payment in full",
  "risk_of_loss_transfer": "At pickup",
  "white_glove_service": true,
  "labor_included": true,
  "freight_included": true
}
```

## HubSpot Deal Created

```json
{
  "dealId": "opp_5f6e7d8c",
  "dealname": "Pompton Lakes Schools — $10,875 Buyback",
  "associatedCompanyId": "co_7a8b9c0d",
  "associatedContactId": "ct_f3e4d5c6",
  "dealstage": "Proposal Draft",
  "amount": 10875.00,
  "turnaround_days": 7,
  "guaranteed_subtotal": 10875.00,
  "device_count_total": 425,
  "projected_qualifying_value": 10875.00,
  "proposal_status": "Draft",
  "data_bearing_equipment": true,
  "data_process_required": "Data sanitization",
  "certificate_of_destruction": true,
  "white_glove_service_included": true,
  "labor_included": true,
  "freight_included": true,
  "line_items_json": "[{...device 1...}, {...device 2...}, {...device 3...}]"
}
```

## Make.com Pricing Lookup Result

```json
{
  "line_items_priced": [
    {
      "manufacturer": "ASUS",
      "model": "C204",
      "quantity": 200,
      "condition": "Good",
      "locked_status": "Unlocked",
      "unit_price": 15.00,
      "projected_subtotal": 3000.00,
      "qualifies_for_buyback": true
    },
    {
      "manufacturer": "Dell",
      "model": "Latitude 3120",
      "quantity": 25,
      "condition": "Good",
      "locked_status": "Unlocked",
      "unit_price": 35.00,
      "projected_subtotal": 875.00,
      "qualifies_for_buyback": true
    },
    {
      "manufacturer": "HP",
      "model": "ProBook x360 11 G5 EE",
      "quantity": 200,
      "condition": "Good",
      "locked_status": "Unlocked",
      "unit_price": 35.00,
      "projected_subtotal": 7000.00,
      "qualifies_for_buyback": true
    }
  ],
  "guaranteed_subtotal": 10875.00,
  "review_required_subtotal": 0.00,
  "projected_qualifying_value": 10875.00,
  "approval_routing": "No approvals needed — value < $15k, all devices qualified"
}
```

## Generated Proposal Merge Fields

```json
{
  "company_name": "Pompton Lakes Schools",
  "primary_contact_first": "John",
  "primary_contact_last": "Briggs",
  "primary_contact_title": "Technical Support Specialist",
  "primary_contact_email": "jbriggs@plps.org",
  "primary_contact_phone": "(973) 835-7100",
  "primary_contact_phone_ext": "1552",
  "sales_rep_name": "Michael Stott",
  "sales_rep_title": "VP Business Development",
  "sales_rep_email": "mike@techrebootusa.com",
  "sales_rep_phone": "(770) 670-5627",
  "pickup_address_full": "237 Van Ave, Pompton Lakes, NJ 07442",
  "projected_qualifying_value": "$10,875.00",
  "turnaround_days": "7",
  "guaranteed_rate_table": "ASUS Chromebook C204 - 200 units at $15.00 each; projected qualifying subtotal: $3,000.00\nDell Latitude 3120 Laptop - 25 units at $35.00 each; projected qualifying subtotal: $875.00\nHP ProBook x360 11 G5 EE Laptop - 200 units at $35.00 each; projected qualifying subtotal: $7,000.00",
  "total_guaranteed_subtotal": "$10,875.00",
  "device_count_total": "425",
  "offer_validity_days": "30",
  "proposal_date": "July 14, 2026",
  "data_process_required": "Data sanitization",
  "data_standard": "NIST 800-88",
  "title_transfer_rule": "Upon payment in full",
  "risk_of_loss_transfer": "At pickup"
}
```

## Email Draft Generated

```
To: jbriggs@plps.org
CC: mike@techrebootusa.com
Subject: Conditional Guaranteed Buyback Proposal — Pompton Lakes Schools | 7-Day Turnaround

Body:

Hi John,

Attached is our conditional guaranteed buyback proposal for Pompton Lakes Schools' 
surplus technology equipment.

Quick Summary:
- Total Equipment: 425 devices
- Projected Qualifying Value: UP TO $10,875.00
- Turnaround: 7 calendar days from pickup
- No-Cost Pickup: Full white-glove service included

Next Steps:
1. Review the attached proposal
2. Confirm any questions with Michael Stott at (770) 670-5627 or mike@techrebootusa.com
3. Sign and return to schedule pickup

Looking forward to working with Pompton Lakes Schools!

Best regards,
Michael Stott
VP Business Development
TechReboot, Inc.
(770) 670-5627 | mike@techrebootusa.com
```

---

**END OF APPENDIX**
