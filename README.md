# Australia United Party — Membership & AEC Preparation Workspace

A GitHub-ready, self-hosted web application for internal membership administration and preparation for a **proposed non-parliamentary federal political party**.

It is an independent administrative tool. It is **not** an Australian Electoral Commission (AEC) product, does not verify enrolment, does not determine legal eligibility, and does not lodge forms with the AEC.

## Included
- HTML5, CSS3 and browser JavaScript frontend.
- Node.js / Express backend and SQLite database.
- Login with bcrypt password hashing, server-side sessions, session cookie protections, CSRF token checks, rate-limited login and security headers.
- Roles: admin, secretary, membership officer and viewer.
- Member intake with declaration/consent checkboxes, unique member IDs and duplicate checks.
- Statuses: pending, active, incomplete, withdrawn, reserve and selected.
- Dashboard showing total, active, remaining to 1,500, reserve and selected counts.
- AEC-oriented CSV export restricted to records with the required declarations and no more than 1,650 rows.
- Audit log for key changes and exports.
- Templates for member intake, party profile worksheet, draft member declaration and AEC preparation checklist.

## Requirements
- Node.js 20 or newer.
- A computer/server where you can keep the SQLite database private.
- HTTPS for any production or internet-accessible deployment.

## Run locally
1. Extract the ZIP.
2. Install Node.js 20+ from https://nodejs.org/.
3. Open a terminal in this folder.
4. Copy `.env.example` to `.env`.
5. Set a long random `SESSION_SECRET` and a strong `ADMIN_PASSWORD` (at least 14 characters).
6. Run:

   ```bash
   npm install
   npm run check
   npm test
   npm start
   ```

7. Open http://localhost:3000 and sign in with the admin username/password from `.env`.

The first admin is created at first start only when `ADMIN_PASSWORD` is set. If no admin exists, set the environment variables and restart.

## Deploying with GitHub
1. Create a **private** GitHub repository.
2. Upload the extracted project files. Do not upload `.env`, `data/`, database files, backups or real member information.
3. Deploy to a private server or hosting environment that supports persistent disk storage and Node.js 20+.
4. Set environment variables in the hosting provider's secret manager.
5. Enable HTTPS and set `COOKIE_SECURE=true`; set `TRUST_PROXY=true` only if deployed behind a correctly configured trusted reverse proxy.
6. Restrict server access, patch dependencies, back up the database securely and test restore procedures.
7. Never commit member personal information to GitHub, even to a private repository.

## Important AEC requirements
For a non-parliamentary federal party, AEC guidance currently requires a membership list of 1,500–1,650 people for the registration test. The AEC expects member details to match the Electoral Roll and may contact a random sample. This app records member declarations but **cannot independently confirm electoral enrolment**.

The export in this app is a generic AEC-oriented CSV. Before lodging, download and use the **current official AEC sample membership spreadsheet** and current non-parliamentary party application forms from:
https://www.aec.gov.au/Parties_and_Representatives/party_registration/

The official AEC page includes the current application, party secretary appointment, statutory declaration, party agent appointment and sample membership spreadsheet. Do not assume the generic CSV is a replacement for the official spreadsheet.

## Data and privacy
- The app stores dates internally as ISO `YYYY-MM-DD`; the UI uses Australian conventions and labels.
- SQLite database and session files are stored under `data/`.
- Protect `data/` with OS-level permissions and encrypted storage/backups.
- Collect only information necessary for the stated membership and registration purpose.
- Publish a complete privacy notice before collecting real member data.
- Establish access, correction, withdrawal, retention, breach-response and deletion processes.
- Do not collect or store classified, security-sensitive or unrelated personal information.
- Do not use dummy, purchased or fabricated member records. Only genuine, informed and voluntary members should be recorded.

## Known limitations / production hardening
- This is a starter application, not a certified election-compliance product.
- No direct AEC enrolment lookup/API integration is included.
- CSV output is not guaranteed to match future revisions of the AEC XLS template.
- No public self-service membership endpoint is enabled; staff enter records after receiving the member's consent.
- Before public deployment, obtain an independent security review, legal/privacy review and usability testing.
- Add encrypted backups, monitoring, incident response, stronger administrator MFA and a formal retention schedule before production use.
