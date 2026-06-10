# ITAD Bid Watch - Project Overview

## What this product does
ITAD Bid Watch scans school districts, government entities, and procurement sites for IT-related bid opportunities, especially:
- Chromebooks
- iPads
- Apple devices
- ITAD / surplus / recycling / disposition opportunities

The system surfaces leads in a dashboard and sends hot lead emails every morning.

## Current live components

### Dashboard
- Repo: `itadbidwatch`
- Live URL: `https://app.stott.marketing/`
- Hosting: GitHub Pages
- Branch: `main`
- Main app file: `index.html`

### Scanner
- Repo: `bidbot-scanner`
- Runtime: Google Cloud Run Job
- GCP Project: `itadbidbot-ai`
- Job name: `bidbot-scanner`
- Region: `us-central1`
- Schedule: daily at `6:00 AM America/New_York`
- Deploy script: `./deploy.sh`

### Database
- Supabase project: `powcnxmsrxixufcqbxbw`
- URL: `https://powcnxmsrxixufcqbxbw.supabase.co`

## Repo map

### Current production repos
- `itadbidwatch`
  - Current live dashboard repo
  - Deploys to `app.stott.marketing` via GitHub Pages

- `bidbot-scanner`
  - Current live scanner repo
  - Deploys to Cloud Run job `bidbot-scanner`

### Older / historical repo
- `scanner`
  - Older scanner repo
  - Keep for reference only unless a live dependency is discovered
  - Do not assume this is the current production scanner

## Major dashboard features
- Google OAuth login
- Admin/user roles
- Daily Hot Leads
- All Bids view
- Bid Scan Sources
- Keywords & Pillars
- RFP School Watch CSV upload
- BidPrime email upload
- SAM.gov browser
- Platform badges on links
- Box.com document availability checks

## RFP School Watch upload behavior
The RFP School Watch upload is handled in `index.html`.

Current behavior:
- Uploads CSV rows into Supabase table `rfp_bids`
- Parses CSV in-browser
- Extracts date from filename when possible
- Ignores rows without `Bid URL`
- Deduplicates rows inside the CSV by `title + institution`
- Checks Supabase for existing `title + institution` matches
- Upserts rows using `doc_id`
- Runs Box document availability checks for `box.com` links
- Records uploaded filenames in `upload_history`

## Scanner deployment
The scanner is deployed from the `bidbot-scanner` repo.

Typical workflow:
1. Edit scanner files
2. Commit changes
3. Push to GitHub
4. Run `./deploy.sh`

`deploy.sh` does:
- Cloud Build container build
- Cloud Run job update
- Reattaches required secrets

## Known operational notes
- GitHub tokens may expire and need rotation
- Cloud Shell was previously used as the main editing environment
- Supabase range limits require paginated queries for large datasets
- Scanner depends on external services such as Anthropic, Jina, SMTP, and SAM.gov
- Box availability checks use Jina Reader
- Secrets should never be stored directly in repo files

## Current known people
- Mike (`itadbidbot@gmail.com`) - owner/admin
- Bruce - team member

## Recommended source of truth
For ITAD Bid Watch, treat these as source of truth:
- Dashboard code: `itadbidwatch`
- Scanner code: `bidbot-scanner`
- Live dashboard: GitHub Pages
- Live scanner runtime: GCP Cloud Run Job
- Data: Supabase

## Important caution
Before deleting, renaming, or archiving any repo:
- verify production is not using it
- especially double-check older repos like `scanner`