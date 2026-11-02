# Security notes

- Keep `.env`, `data/`, SQLite files, backups and all member records out of Git.
- Use HTTPS and `COOKIE_SECURE=true` in production.
- Set a unique 32+ character session secret and strong admin password.
- Restrict server and database filesystem access to authorised operators.
- Use a private repository; repository privacy is not a substitute for secure hosting.
- Review dependency advisories and update packages regularly.
- Back up encrypted database copies and periodically test restoration.
- Do not expose the database file through static hosting or public downloads.
- The current starter uses role checks, password hashing, rate limiting, security headers and CSRF checks; it has not undergone an independent penetration test.
- Do not put classified defence, security or unrelated sensitive data into member notes.
