# AuthMatrixV2

A Burp Suite extension for testing **authorization controls** across multiple users and roles — built on the modern **Montoya API**.

Send requests to AuthMatrix, configure your users with their tokens, define who *should* have access to each endpoint, and run all combinations in one click. Results are color-coded so auth bypasses stand out immediately.

---

## What it does

When testing access control, you typically need to replay the same requests with different user tokens and manually check every response. AuthMatrix automates this:

- You define your users (admin, regular user, guest, etc.) with their auth tokens
- You send requests from Burp to AuthMatrix
- You declare who *should* have access to each endpoint
- AuthMatrix replays every request for every user and flags anything unexpected

---

## Screenshots
<img width="1915" height="809" alt="image" src="https://github.com/user-attachments/assets/f355aabf-e3fd-4430-ae33-8e96c21c9a41" />

---

## Requirements

- Burp Suite Pro or Community **2022.8+** (Montoya API)
- Java JDK **11+**
- [`montoya-api.jar`](https://repo1.maven.org/maven2/net/portswigger/burp/extensions/montoya-api/) from Maven Central

---

## Build

```bash
# 1. Place montoya-api.jar in the project root
# 2. Create the source directory
mkdir -p build src/authmatrix
cp AuthMatrix.java src/authmatrix/

# 3. Compile
javac -cp montoya-api.jar -d build src/authmatrix/AuthMatrix.java

# 4. Package
jar cf AuthMatrix.jar -C build .
```

Or use the included `build.sh`:

```bash
chmod +x build.sh && ./build.sh
```

---

## Install in Burp Suite

1. Open Burp Suite
2. Go to **Extensions → Add**
3. Set **Extension Type** to `Java`
4. Select `AuthMatrix.jar`
5. The **AuthMatrix** tab will appear in the suite

---

## How to use

### Step 1 — Add your users

In the **Users / Roles** panel, click **+ Add User** and fill in:

| Field | Description | Example |
|---|---|---|
| Name | A label for this user | `Alice` |
| Header | The auth header name | `Authorization` |
| Token Value | The full header value | `Bearer eyJhbGci...` |
| Role | A logical role label | `admin` |

You can also use cookies: set Header to `Cookie` and Token Value to `sessionid=abc123`.

> Add as many users as you need — one column per user will appear in the Results table.

---

### Step 2 — Add requests

Right-click any request in Burp (Proxy history, Repeater, Target site map) and select **Send to AuthMatrix**.

The request appears in the **Requests** panel with these editable columns:

| Column | Description |
|---|---|
| `#` | Auto-assigned ID |
| `Path` | Method + path (read-only) |
| `Expected Users` | Comma-separated user *names* that should get a 2xx response |
| `Expected Roles` | Comma-separated *roles* that should get a 2xx response |
| `Description` | Freetext note about the endpoint |

> ⚠️ **Expected Users** and **Expected Roles** are mutually exclusive — only fill one per request. Rows with both filled turn red as a warning.

**Special values:**

- Leave both empty → everyone should have access (`all`)
- `Expected Roles: admin` → only users whose Role is `admin` should get 2xx
- `Expected Users: Alice, Bob` → only Alice and Bob should get 2xx

---

### Step 3 — Run

Click **▶ Run Auth Tests**.

AuthMatrix replays each request once per user, injecting or replacing that user's auth header, and records the HTTP status code.

---

### Step 4 — Read the results

The **Results** table shows one row per request and one column per user:

| Color | Meaning |
|---|---|
| 🟢 `✅ 200` | Access matches expectation — all good |
| 🔴 `🔴 200` | **Unexpected access** — possible auth bypass! |
| 🟡 `🟡 403` | Unexpected block — user should have had access |
| `–` | Not tested yet |

**Click any colored cell** to open the full request and response in a dark Repeater-style viewer at the bottom of the screen:

- Left panel: the exact HTTP request that was sent (with the injected token)
- Right panel: the full HTTP response received

The viewer uses syntax highlighting — status line in blue, header names in light blue, header values in orange, body in white — on a dark background.

---

## Save & Load sessions

Use the **💾 Save / Load** button in the toolbar to persist your work.

**Save session** exports a `.json` file containing:
- All users and their tokens
- All requests (raw HTTP bytes, expected access config, descriptions)
- All test results including the full request/response pairs

**Load session** restores everything exactly as it was — you can click cells to inspect previous results without re-running the tests.

This is useful for sharing findings with teammates or picking up a session later.

---

## Export CSV

Click **📄 Export CSV** to save the Results table as a `.csv` file.

The file includes all columns (`#`, `Path`, `Description`, one column per user) with the result for each combination. Emojis are converted to readable text (`OK_200`, `BYPASS_200`, `BLOCK_403`) for compatibility with Excel and LibreOffice.

The filename includes a timestamp: `authmatrix_results_20250317_143022.csv`.

---

## Typical workflow example

```
Users:
  Alice  | Authorization | Bearer eyJ...admintoken  | role: admin
  Bob    | Authorization | Bearer eyJ...usertoken   | role: user
  Guest  | Cookie        | sessionid=anonymous123   | role: guest

Requests:
  GET  /api/admin/users      Expected Roles: admin      "List all users"
  GET  /api/profile          Expected Roles: user       "Own profile"
  POST /api/admin/delete     Expected Roles: admin      "Delete user"
  GET  /api/public/health    (empty)                    "Health check"

Results after running:
                    Alice     Bob       Guest
  GET /api/admin    ✅ 200    ✅ 403    ✅ 403
  GET /api/profile  ✅ 200    ✅ 200    🔴 200   ← Guest accessed profile!
  POST /api/delete  ✅ 200    ✅ 403    🔴 200   ← Guest can delete users!
  GET /api/health   ✅ 200    ✅ 200    ✅ 200
```

---

## Frequently asked questions

**Can I use cookies instead of Bearer tokens?**  
Yes. Set Header to `Cookie` and Token Value to your full cookie string, e.g. `session=abc; other=xyz`.

**What counts as "access"?**  
Any 2xx or 3xx response is treated as access granted. Everything else (401, 403, 404, 5xx) is treated as access denied.

**Can I test the same endpoint multiple times with different parameters?**  
Yes — send it to AuthMatrix multiple times. Each entry is independent and you can add a Description to differentiate them.

**Do I need to re-run after loading a session?**  
No. Saved sessions include all previous results. You can click cells and inspect request/response detail immediately after loading.

**My tokens expired — can I update them without re-adding everything?**  
Yes. Edit the Token Value cells in the Users panel and click Run Auth Tests again. The requests stay in place.

---

## Project structure

```
AuthMatrix/
├── src/
│   └── authmatrix/
│       └── AuthMatrix.java   ← single-file extension
├── montoya-api.jar            ← Montoya API (not included, download separately)
├── build.sh                   ← compile + package script
└── README.md
```

---

## License

MIT
