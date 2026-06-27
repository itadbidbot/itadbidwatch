# ITAD Bid Watch - Operations Notes

## Source of truth

Current production repos:
- `itadbidwatch`
  - Live dashboard repo
  - Hosted on GitHub Pages
  - Main file: `index.html`
- `bidbot-scanner`
  - Live scanner repo
  - Deployed to Cloud Run job `bidbot-scanner`

Older repo:
- `scanner`
  - Older scanner repo
  - Keep for reference unless proven unused
  - Do not treat as current production by default

**⚠️ NEEDS VERIFICATION (2026-06-27):** The sections above describe a Cloud Run Job
architecture with a 6am Cloud Scheduler trigger. As of this update, the ACTUAL
day-to-day contact-extraction workflow runs manually via Cloud Shell
(`box_contact_extractor.py`), not via a scheduled Cloud Run job. It's unclear
whether the Cloud Run job described above is a separate/older/parallel process
to the bid-discovery scan (finding new bids) versus the contact-extraction step
(reading PDFs for names/emails/phones) — these may be two different things that
got conflated. **Confirm with Mike which process actually runs on the 6am
schedule, and whether box_contact_extractor.py is meant to eventually replace
or run alongside it**, before assuming this section is current.

## Cloud services

- GitHub: code hosting
- GitHub Pages: dashboard hosting
- Google Cloud Run Jobs: scanner runtime (bid discovery — see verification note above)
- Google Cloud Scheduler: 6am trigger (see verification note above)
- Google Cloud Shell: where `box_contact_extractor.py` is actually run today
  - **Hard weekly quota: 50 hours** (resets weekly, not daily). Heavy Playwright
    sessions (full backfills, large `--reextract-failed` runs) can burn through
    this in a single day. When exceeded, Cloud Shell is fully inaccessible
    until the weekly reset — there is no workaround, no override, no way to
    see the exact reset time once you're already locked out (you can only
    check remaining hours from inside Cloud Shell, via Session Info → Usage
    Quota — check this BEFORE running a long job, not after).
  - **Plan in progress**: a recycled/decommissioned MacBook (ITAD inventory)
    is being repurposed as a dedicated, always-on extraction machine via cron,
    specifically to avoid this quota entirely. Not yet built as of this
    update. Machine previously ran "OpenClaw" (a self-hosted AI agent
    framework) — intent is to wipe it clean and dedicate it solely to this
    extraction workflow, since OpenClaw's broad shell/file/tool access is a
    real credential-exposure risk if left running alongside scripts holding
    the Supabase service-role key and SMTP password.
- Supabase: application data
- Anthropic: scanner/dashboard AI features
- Jina Reader: **CONFIRMED UNRELIABLE (2026-06-24/25)** — see "Known maintenance
  issues" below, this is no longer just a theoretical risk, it has measurably
  failed in production.
- SAM.gov API: federal opportunities
- SMTP provider: email sending (Gmail SMTP, itadbidbot@gmail.com)

## Known maintenance issues

- GitHub tokens can expire and may need rotation
- Cloud Shell sessions are temporary; **Cloud Shell also has a hard 50-hour/week
  usage quota** — see Cloud Shell entry above. This is the single biggest
  operational constraint discovered this session.
- Supabase row fetches may require range-based pagination (default cap 1,000 rows)
- External APIs can fail or rate-limit
- **Box document availability checks via Jina are fundamentally broken and
  should not be trusted or re-introduced.** Jina cannot read Box.com at all
  (returns its own "Host not in allowlist" page instead of the real content).
  `box_contact_extractor.py` is now the sole, correct source of truth for
  `rfp_bids.doc_available` — it uses Playwright with a real browser session.
  The old Jina-based check that used to run inside `index.html`'s CSV upload
  flow has been REMOVED entirely (see "Fixed this session" below). Do not
  re-add a Jina-based Box check.
- **Jina Reader also fails on direct (non-Box) PDF links.** Confirmed real
  failures (HTTP 401) on legitimate government PDF URLs: University of Guam,
  a Finalsite-hosted Rockwall ISD PDF, two NH DAS PDFs — all on the same
  upload, same day. This was previously the only extraction path for direct
  PDF links (inside `index.html`'s upload flow) with no retry, no fallback,
  and no visible error surfaced to the user — meaning real contacts were
  likely being silently lost for an unknown period before this was caught.
  A Jina-free alternative now exists — see "Direct (non-Box) PDF extraction"
  below.

## Security notes

- Never paste live secrets into chat or docs
- Never commit secret values into GitHub
- Rotate exposed tokens immediately
- Prefer secret managers and environment configuration over hardcoding
- Be cautious about running general-purpose AI agent tools (e.g. OpenClaw) on
  any machine that also holds this project's credentials (Supabase service
  role key, SMTP password) — such tools often have broad shell/file access by
  default and have documented real-world prompt-injection/data-exfiltration
  risk from third-party skills/plugins.

## RFP School Watch notes — CSV upload flow (index.html)

The CSV upload flow currently:
- parses CSV in-browser
- inserts into `rfp_bids`
- skips rows without `Bid URL`
- deduplicates by `doc_id` (not title+institution — confirm which is actually
  current if these two notes conflict in a future audit)
- upserts using `doc_id`
- ~~checks Box document availability for `box.com` links~~ **REMOVED
  2026-06-24.** This used Jina Reader, which cannot read Box.com (see Known
  Maintenance Issues). New Box-linked rows now save with `doc_available =
  null` (shown as "?" in the dashboard) and get resolved correctly by
  `box_contact_extractor.py` on its next Cloud Shell run — NOT at upload time
  anymore.
- records filename in `upload_history`
- auto-refreshes the table after upload completes (added 2026-06-24, fixes a
  bug where the table previously needed a manual page refresh to show
  results)
- attempts direct-PDF contact extraction via Jina for non-Box `document_url`
  links ending in `.pdf` — **known unreliable, see Known Maintenance Issues.**
  A `pdfContactsSaved`/`pdfContactsDupes` variable-scoping bug that crashed
  this step's summary-popup (while the underlying save still succeeded) was
  also fixed 2026-06-24.

## Box Contact Extractor (`box_contact_extractor.py`) — run via Cloud Shell

This is the actual day-to-day contact-extraction engine. Run from Cloud Shell:

```bash
# Normal daily run — only processes bids not yet attempted
python3 box_contact_extractor.py --headless --since YYYY-MM-DD

# One-time/periodic backfill of doc_available across ALL Box links (fast,
# skips full contact extraction)
python3 box_contact_extractor.py --headless --check-availability-only

# Backfill bid_direction (buy/sell/unknown classification) onto bids already
# processed for contacts, without re-extracting contacts or touching assignee
python3 box_contact_extractor.py --headless --classify-only

# Targeted retry: re-process ONLY bids that currently have a red marker (no
# real contact found yet) — skips anything with a genuine green/yellow
# contact already saved. Use this to recover bids that were missed due to a
# bug that's since been fixed, without re-doing already-successful work.
python3 box_contact_extractor.py --headless --reextract-failed

# Test against a specific, known set of bids (e.g. to verify a fix before
# running against the whole database) — combine with --reprocess to force
# re-extraction even if already processed
python3 box_contact_extractor.py --headless --reprocess --doc-ids R-XXXX,R-YYYY

# Direct (non-Box) PDF links — see "Direct (non-Box) PDF extraction" below
python3 box_contact_extractor.py --headless --direct-pdfs --since YYYY-MM-DD
```

### Fixed this session (2026-06-24/25) — four real bugs, all verified against
### real documents, not just theoretical

These were found through methodical spot-checking against real bid PDFs after
the user (correctly) refused to accept "no contacts found" at face value,
based on 7 months of operational experience that every real bid PDF contains
a contact. That instinct was right — each "no contacts" case checked turned
out to be a real bug, not a genuinely contact-less document, until proven
otherwise case-by-case.

1. **Box file-listing race condition.** The old code used DOM selectors
   (`page.locator(...)`) to find files in a Box folder, with a fixed 3-second
   wait. Box's file list is rendered client-side by React and timing is
   inconsistent — the same exact URL, queried seconds apart, returned "0 items
   found" once and "3 items found" (correctly) another time. FIX: read the
   file list from `window.Box.postStreamData`, a JSON object embedded
   directly in the initial page HTML — present immediately on load, zero
   wait/race condition, 100% reliable across every folder tested. DOM
   selectors are kept only as a fallback if this JSON can't be found/parsed.

2. **Box "Currently Unavailable" false positive.** The old availability check
   searched the page's raw text for the phrase "Bid Document Currently
   Unavailable" and treated any match as proof the folder was empty. WRONG —
   confirmed via direct screenshot (Clarkstown Central School District,
   R-20260502-0402): some Box folders contain a literal placeholder file
   NAMED "Bid Document Currently Unavailable.txt" sitting ALONGSIDE real,
   valid documents. FIX: check the actual file listing (via the JSON above)
   for any real document extension (pdf/doc/docx/xls/xlsx/ppt/pptx) — only
   mark unavailable if there are none.

3. **Download button wrong-element bug.** Box's PDF preview page has TWO
   elements matching the selector `[aria-label='Download']`. The old code
   took `.first`, which silently resolved but the click would hang/time out
   every time — confirmed root cause of the Town of Greenwich case (RFB
   #7959, "Surplus Sale of IT Equipment") repeatedly showing "no contacts"
   across three separate runs even after unrelated timing fixes, despite the
   document genuinely containing a named contact
   (Daniel.Centofanti@GreenwichCT.Gov, confirmed via external web search of
   the institution's standard bid template). FIX: try ALL matching download
   buttons in order with a forced click, not just the first match.

4. **Long-filename click failure + 5-page PDF read limit too short.**
   - Filenames that Box's UI visually truncates (long system-generated names,
     e.g. multi-segment IDs from government export systems) could never be
     matched by `get_by_text(full_filename)`, since the full string never
     actually appears in the rendered DOM. FIX: match DOM rows by a
     truncation-safe ~25-character PREFIX of the filename instead of the full
     string. (An earlier attempt to fix this by clicking by raw DOM row INDEX
     instead caused a regression — DOM row count and JSON item count are NOT
     guaranteed to match 1:1 — confirmed on Town of Greenwich, 2 JSON items
     but 3 DOM rows. Reverted to prefix-matching, which is now the correct,
     stable approach.)
   - The PDF text extractor (`extract_text_from_pdf_bytes`) was hard-capped
     at 5 pages. Confirmed real case: Western Suffolk BOCES "Telephone System
     Service Contract" — a genuine 91-page, 5.8MB bid packet — had its real
     contact emails (multiple @wsboces.org addresses) starting on page 10,
     entirely missed by the 5-page cap. FIX: raised to a 30-page cap, but
     stops reading early the moment a real email pattern is found in the
     accumulated text — so typical short documents are still read fast, while
     large packets get a real chance instead of an arbitrary wall.
   - **Also added: occasional transient/intermittent flakiness was observed**
     even after all fixes above (a bid that failed once succeeded
     immediately on an identical retry — Desoto County Schools,
     R-20260615-0106). Root cause not fully isolated (likely a Box-side
     rendering/network hiccup, not a deterministic logic bug). Mitigation:
     `--reextract-failed` mode exists specifically to sweep up these
     transient misses on a periodic basis without re-doing already-successful
     work or slowing down every single daily run with a built-in retry.

### Network resilience (added 2026-06-24)

All Supabase read/write calls now go through a `supabase_request()` wrapper
with retry-and-backoff (up to 4 attempts) on connection errors — fixes a
known, recurring Cloud Shell DNS blip
(`NameResolutionError ... Failed to resolve 'powcnxmsrxixufcqbxbw.supabase.co'`)
that previously crashed an entire multi-hour run over a single transient
network hiccup. This was specifically important to fix before relying on long
unattended runs (Cloud Shell or otherwise).

### Resume support

- `--classify-only` and `--reextract-failed` both query Supabase fresh on
  every run to determine what's already done, so re-running the exact same
  command after a Cloud Shell disconnect (or hitting the weekly quota and
  coming back later) correctly picks up only what's still unresolved — no
  need to track progress manually.

### Buy/Sell/Unknown classification (added 2026-06-23)

Free, keyword-based (no API cost) classification of whether a bid is the
institution BUYING equipment (the normal case — refresh/replacement
purchases) versus SELLING/auctioning their OWN surplus (a fundamentally
different situation — pitching "we'll handle your surplus disposal" to
someone who is themselves the seller would be an obvious miss). Stored in
`rfp_bids.bid_direction` (text: `buy` / `sell` / `unknown`).

- **Default is BUY** whenever real document text was successfully read — most
  government solicitations are purchases. SELL only overrides this default
  when strong, specific surplus-disposal/auction language is present (e.g.
  "surplus auction", "as-is where-is", "highest bidder", "sale of surplus").
  UNKNOWN is reserved for cases with no real text to evaluate at all (empty
  folder, read failure).
  - (An earlier version of this logic required matching an explicit BUY
    keyword list before defaulting away from UNKNOWN, which caused ~75-80% of
    real bids to land as UNKNOWN simply because they didn't use one of a
    handful of specific phrases. Reworked to the default-to-BUY approach
    above, which matches reality far better.)
- **Auto-assignment, MOVE-FORWARD ONLY (per explicit user decision — do not
  retroactively backfill assignee on existing rows):** buy → Mike, sell →
  Bruce, unknown → Mike. Only applied to bids that don't already have an
  `assignee` set — never overwrites a value a human already chose.
- UI: a small BUY / SELL / ? badge appears next to the existing Bid Type
  (RFP/IFB/RFQ) badge in the RFP School Watch table (`index.html`).
- **Deliberately NOT built (explicit user decision, cost-conscious):** item/
  quantity extraction from bid documents (e.g. "Chromebooks — qty 1,200"),
  and a hover/click snippet showing the triggering text. Both would require
  an LLM call (Claude) per document — a real per-document cost the user
  explicitly declined for now. The buy/sell flag itself is free regex/keyword
  matching, no API cost, reusing text already read during normal extraction.

### Direct (non-Box) PDF extraction — NEW, MOSTLY UNTESTED (2026-06-27)

A `--direct-pdfs` mode was added to handle `document_url`/`bid_documents`
links that point straight to a PDF (not Box) — typically hosted on a school
district's own site, a government portal, or a CDN like Finalsite. This
replaces the unreliable Jina-based attempt inside `index.html` (see Known
Maintenance Issues) with a two-tier, Jina-free approach:

1. Plain `requests.get()` with a real browser User-Agent — fast, free, works
   for the large majority of sites that don't require cookies/JS.
2. Playwright fallback for sites that need a real browser session. This
   fallback specifically handles servers that respond by FORCING A FILE
   DOWNLOAD rather than rendering a normal page (confirmed real case: LSU
   Health Sciences Center's PDF link on `wwwcfprd.doa.louisiana.gov` does
   this — the initial version of this fallback didn't handle that case and
   threw `Page.goto: Download is starting`; fixed via
   `page.expect_download()`, the same pattern already proven for Box).

**Status as of this writing: the underlying fetch approach (method 1) is
verified working** — confirmed via a standalone test against a real
University of Guam PDF that Jina had 401'd on, and via a small `--limit 3`
production run where 2 of 3 bids found real (and correctly cross-validated —
already-known-via-another-path) contacts via plain `requests`. **The
Playwright-fallback download-handling fix is freshly written and has not yet
been re-tested against the real failing case (LSU) at the time of this
update — confirm that works before treating this mode as fully reliable, and
before running it at volume against the full ~193 remaining direct-PDF
links.**

```bash
# Small, safe first test against a real bid known to need the Playwright
# fallback specifically (forced-download case)
python3 box_contact_extractor.py --headless --direct-pdfs --reprocess --doc-ids R-20260417-0639

# Once verified, normal use:
python3 box_contact_extractor.py --headless --direct-pdfs --since YYYY-MM-DD
```

Saved contacts from this path use `data_source = 'pdf_direct'` (matching the
existing convention already used by `index.html`'s older inline attempt, for
consistency with historical data).

### Dashboard "Rebuild" button (added 2026-06-24, `index.html`)

A button in the RFP School Watch toolbar, next to the existing "☁ Box
Contacts" button. Hover text (user-specified):
> "Rebuild your contact list on bids that returned zero contacts on the first
> attempt. This is a quality assurance scan process. No data is lost, only
> gained, when implemented."

**Important architectural limit:** the dashboard is a browser-only
application — it cannot launch Playwright/Python itself. The button therefore
does NOT perform the rebuild directly. It queries Supabase live to count how
many Box-linked bids genuinely have no real (green/yellow) contact yet
(matching `--reextract-failed`'s logic exactly), shows that count, and gives a
"Copy Command" button that copies
`python3 box_contact_extractor.py --headless --reextract-failed` to the
clipboard for the user to paste into Cloud Shell themselves.

**Planned fast-follow, not yet built:** once a dedicated always-on machine
exists (see Cloud Shell entry above), this button could be upgraded to
actually trigger the rebuild server-side (e.g. via a small listener/API the
dedicated machine runs), removing the manual copy-paste step entirely.

## Supabase notes

- Project ID: `powcnxmsrxixufcqbxbw`
- Large tables may require parallel/ranged fetches (default row cap 1,000)
- Dashboard code already includes range-based loading for some views
- New/changed columns this session (confirm these actually got added in
  Supabase — they were specified but the user needs to add them manually via
  Table Editor, this assistant cannot run SQL directly against Supabase):
  - `rfp_bids.bid_direction` (text) — buy/sell/unknown classification

## Real impact, this session (2026-06-24/25)

Before any of this session's fixes, `pdf_contacts` quality breakdown:
- green: 100, yellow: 1,217, red: 6,443 (total 7,760)
- Actionable (green+yellow): **1,317**

After the four Box pipeline fixes + a full `--reextract-failed` sweep across
~1,960 historical Box links:
- green: 144, yellow: 1,505, red: 8,013 (total 9,662)
- Actionable (green+yellow): **1,649**

**Net gain: 332 real, previously-missed contacts recovered from documents
that were already in the system the whole time** — these were bugs causing
false negatives, not a data-source or coverage gap. The growth in red-marker
count is expected/correct, not a regression — it includes both new marker
rows from genuinely contact-less documents (several spot-checked and
confirmed truly empty: Killeen ISD, Hawaii Office of the Governor, County of
Onondaga) and the bulk of the ~1,623 historically-failed bids that were
re-attempted but still, correctly, found nothing.

## Scanner operational checks

Useful checks:
```bash
gcloud config set project itadbidbot-ai
gcloud run jobs describe bidbot-scanner --region us-central1
gcloud run jobs executions list --job bidbot-scanner --region us-central1 --limit 5
```
