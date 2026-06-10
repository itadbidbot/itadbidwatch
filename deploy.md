# ITAD Bid Watch - Deploy Guide

## Overview
ITAD Bid Watch has two separate deploy paths:

1. Dashboard deploy
- Repo: `itadbidwatch`
- Live URL: `https://app.stott.marketing/`
- Hosting: GitHub Pages
- Branch: `main`

2. Scanner deploy
- Repo: `bidbot-scanner`
- Runtime: Google Cloud Run Job
- GCP Project: `itadbidbot-ai`
- Job: `bidbot-scanner`
- Region: `us-central1`

## Dashboard deploy

### How dashboard deploy works
The dashboard is a static site deployed from the `main` branch of the `itadbidwatch` repo through GitHub Pages.

### Dashboard deploy steps
1. Edit `index.html`
2. Commit changes
3. Push to `main`
4. GitHub Pages republishes the site

### Example
```bash
git add index.html
git commit -m "Describe dashboard change"
git push