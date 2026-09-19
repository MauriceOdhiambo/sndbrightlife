# SND Brightlife CBO — Full-Stack Web Application & Cloud Migration

## Project Overview

**SND Brightlife CBO** is a community-focused digital platform designed to support member management, savings, table banking, lending, repayments, communication, administration, reporting, and community development activities.

This project involved the **migration and modernization of an existing Google Apps Script–based application into a production-oriented Vercel, Node.js, and Supabase/PostgreSQL architecture**.

The migration was designed to preserve the existing business workflows while introducing a more scalable deployment architecture, server-side authentication, persistent sessions, rate limiting, scheduled operations, secure environment configuration, and cloud-based integrations.

---

## Technology Stack

- **Frontend:** HTML, CSS, JavaScript
- **Backend:** Node.js / Vercel Serverless Functions
- **Database:** Supabase / PostgreSQL
- **Deployment:** Vercel
- **Source Control:** GitHub
- **Authentication:** Server-managed sessions
- **Email:** Resend integration
- **Notifications:** WhatsApp Cloud API integration
- **Automation:** Vercel Cron Jobs
- **Database Security:** PostgreSQL Row-Level Security (RLS)

---

## Key Contributions

### Cloud Architecture Migration

Migrated the application from a Google Apps Script architecture to a modern cloud-based architecture:

```text
Previous Architecture

Frontend
   ↓
Google Apps Script
   ↓
Supabase
