# ITAD Bid Watch

ITAD Bid Watch is a procurement monitoring platform focused on school districts, government entities, and technology-related bid opportunities.

## What it does
The platform helps identify and manage opportunities related to:
- Chromebooks
- iPads
- Apple devices
- IT asset disposition (ITAD)
- surplus technology
- electronics recycling and disposition services

## Live dashboard
- URL: `https://app.stott.marketing/`
- Hosting: GitHub Pages
- Deploy source: `main` branch of this repository

## Main files
- `index.html` - primary dashboard application
- `CNAME` - custom domain configuration for GitHub Pages
- `supabase/` - database migrations and related Supabase files

## Related repositories
- `itadbidwatch`
  - current live dashboard repo

- `bidbot-scanner`
  - current live scanner repo
  - deploys to Google Cloud Run

- `scanner`
  - older scanner repo kept for reference unless proven unused

## Documentation
For project context and operations, read:
- `PROJECT_OVERVIEW.md`
- `DEPLOY.md`
- `OPERATIONS.md`

## Dashboard workflow
Typical dashboard change flow:
1. Edit `index.html`
2. Commit changes
3. Push to `main`
4. GitHub Pages republishes the site

## Notes
- Dashboard and scanner are separate deploy paths
- Do not store secrets directly in the repo
- Verify older repos before deleting or renaming them
