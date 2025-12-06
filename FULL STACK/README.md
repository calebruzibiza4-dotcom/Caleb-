**Water Billing — Modernization Guide**

This workspace contains a modernized starting point for the legacy `waterbilling` system.

Files added:
- `waterbilling-modern.sql` — improved schema (InnoDB, proper types, FK constraints).
- `db.php` — PDO connection boilerplate.
- `api.php` — Small JSON API using prepared statements and password-hashed users.
- `index.html` — Responsive Bootstrap UI to list/add owners and bills.
- `temperature-app.html` — (previously created) temperature converter.

Quick setup (Windows + XAMPP):
1. Put this project folder in your Apache `htdocs` (e.g., `C:\xampp\htdocs\waterbilling`).
2. Start Apache and MySQL via XAMPP Control Panel.
3. Import `waterbilling-modern.sql` using phpMyAdmin or the MySQL CLI.

   Using MySQL client (PowerShell):

```powershell
# Run in PowerShell; update path and mysql credentials if needed
mysql -u root -p < "C:\Users\T R U T H\OneDrive\Documents\FULL STACK\waterbilling-modern.sql"
```

4. Configure DB credentials: open `db.php` and set `$DB_HOST`, `$DB_NAME`, `$DB_USER`, `$DB_PASS`.
5. Place `api.php`, `db.php`, and `index.html` under the same folder in htdocs.
6. Open the UI at: `http://localhost/waterbilling/index.html` (adjust path if you used a different folder).

Authentication & creating users:
- The API now supports JWT authentication. Protects owners/bills endpoints. Public endpoints: `login` and `register`.
- To create the first user you can either:
   - Use the `register` button in the login card of the web UI (creates a user via the API).
   - Or from the server run the CLI helper:

```powershell
php "C:\Users\T R U T H\OneDrive\Documents\FULL STACK\create_user.php" admin StrongPassword "Admin"
```

After creating a user, sign in from the UI. The token is stored in localStorage and used automatically for API requests.

Security notes:
- Change `$JWT_SECRET` in `db.php` to a strong random value before deploying.
- For production, restrict `Access-Control-Allow-Origin` to your domain and enable HTTPS.
- Consider adding refresh tokens or shorter token expiry for higher security.

Notes & next steps:
- Passwords: existing old SQL uses plaintext — create users through the API or update them with `password_hash()` before using.
- Authentication: current API returns minimal info for demo; for production add JWT/session handling and restrict CORS.
- Validation: server-side validation is minimal; add stricter checks for production.
- UI: this is a simple example. You can extend with edit/delete operations, pagination, and report downloads.

If you want, I can:
- Add login and JWT-based auth for the API.
- Add editing and deleting for owners/bills with confirmation.
- Migrate the legacy data file you attached into the new schema (automated mapping).
- Build a small installer script to import data and hash existing user passwords.

Which of the above should I do next?