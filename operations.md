
`OPERATIONS.md`
```md
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

## Cloud services
- GitHub: code hosting
- GitHub Pages: dashboard hosting
- Google Cloud Run Jobs: scanner runtime
- Google Cloud Scheduler: 6am trigger
- Supabase: application data
- Anthropic: scanner/dashboard AI features
- Jina Reader: document/URL access
- SAM.gov API: federal opportunities
- SMTP provider: email sending

## Known maintenance issues
- GitHub tokens can expire and may need rotation
- Cloud Shell sessions are temporary
- Supabase row fetches may require range-based pagination
- External APIs can fail or rate-limit
- Box document checks may return unknown/null if Jina fails

## Security notes
- Never paste live secrets into chat or docs
- Never commit secret values into GitHub
- Rotate exposed tokens immediately
- Prefer secret managers and environment configuration over hardcoding

## RFP School Watch notes
The CSV upload flow currently:
- parses CSV in-browser
- inserts into `rfp_bids`
- skips rows without `Bid URL`
- deduplicates by `title + institution`
- upserts using `doc_id`
- checks Box document availability for `box.com` links
- records filename in `upload_history`

## Supabase notes
- Project ID: `powcnxmsrxixufcqbxbw`
- Large tables may require parallel/ranged fetches
- Dashboard code already includes range-based loading for some views

## Scanner operational checks
Useful checks:
```bash
gcloud config set project itadbidbot-ai
gcloud run jobs describe bidbot-scanner --region us-central1
gcloud run jobs executions list --job bidbot-scanner --region us-central1 --limit 5