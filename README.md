🚀 JS ANALYZER

⚡ A JavaScript analysis tool that extracts endpoints, API keys, tokens, emails, passwords, private IPs, and internal hostnames from JavaScript files served by a target website.

JS-ANALYZER fetches the target's main page, discovers every `<script src="...">` reference, downloads each JavaScript file, and runs a set of regex patterns against the source to surface hardcoded secrets and hidden API routes. Findings are printed to the terminal with color-coded severity and saved to `results.txt`.

✨ Features

🔗 Endpoint discovery — relative API routes inside JS strings
🌐 Absolute URL extraction
🔑 Secret detection — AWS keys, Google API keys, Stripe live keys, GitHub tokens, Slack tokens, JWTs
📧 Email address extraction
🔒 Password assignment patterns (`password = "..."`, `passwd:`, `pwd=`)
🖥️ Private IP detection — 10.x, 192.168.x, 172.16-31.x
🏢 Internal hostname detection — `.internal`, `.intranet`, `.corp`, `.local`
🎨 Rainbow banner and color-coded findings
💾 Saves all findings to results.txt

📋 Requirements

🐧 Linux, macOS, or Windows
🐍 Python 3.8 or later
📦 requests >= 2.31.0
📦 beautifulsoup4 >= 4.12.0
📦 colorama >= 0.4.6
🌐 Outbound HTTPS access to the target

🛠️ Installation

Step 1 — Check your Python version

    python3 --version

Python 3.8 or later is required.

Step 2 — Install the required packages

    pip install "requests>=2.31.0" "beautifulsoup4>=4.12.0" "colorama>=0.4.6"

Step 3 — Or install from requirements.txt

    pip install -r requirements.txt

Step 4 — Clone the repository

    git clone https://github.com/K52-ai/js-analyzer.git

Step 5 — Enter the project directory

    cd js-analyzer

Step 6 — Make the script executable (optional)

    chmod +x js_analyzer.py

▶️ Usage

Step 1 — Start JS Analyzer

    python3 js_analyzer.py

Step 2 — Enter the target when prompted

    Target: https://example.com

Step 3 — The tool fetches the main page, lists all JS files, and analyzes each one automatically.

Step 4 — View saved findings

    cat results.txt

📝 requirements.txt

Create a file named `requirements.txt` with the following contents:

    requests>=2.31.0
    beautifulsoup4>=4.12.0
    colorama>=0.4.6

Save the file and exit the editor. Then run:

    pip install -r requirements.txt

📊 Results

Endpoints — relative API routes discovered inside JavaScript strings
URLs — absolute URLs referenced in JavaScript
aws_key — AWS Access Key IDs (AKIA...)
google_api — Google API keys (AIza...)
stripe_live — Stripe live secret keys (sk_live_...)
github_token — GitHub personal access tokens (ghp_...)
slack_token — Slack tokens (xox...)
jwt — JSON Web Tokens
email — email addresses
internal_host — internal / intranet / corp / local hostnames
password — password assignment patterns
private_ip — RFC1918 private IP addresses

Secret categories are printed in red with a ⚠️ marker. Non-secret findings are printed in yellow.

All findings are saved to `results.txt`, grouped by JavaScript file.

View saved results:

    cat results.txt

Count saved findings:

    wc -l results.txt

🖼️ Screenshots

Add your actual screenshots to the assets/ folder, then reference them:

    ![Scan](assets/scan.png)
    ![Secrets](assets/secrets.png)

⚠️ Important Notes

🛡️ Pattern matching only — the tool flags anything that looks like a secret. Verify each finding manually before treating it as a real leak.
🔍 Endpoint extraction only captures relative paths inside quoted strings in JavaScript. Dynamically constructed routes (concatenation, template literals built at runtime) are not captured.
🌐 The tool scans only JavaScript files referenced by the main page. Additional bundles loaded on-demand or via dynamic import are not fetched.
🔐 TLS certificate verification is disabled in the HTTP client.
⚡ Requests are sequential. No concurrency in this version.
💾 `results.txt` is overwritten on every run — back it up if you need history.

⚖️ Responsible Use

Use JS-ANALYZER only on systems you own or have explicit permission to test. Respect server rate limits and applicable laws.

📜 License

MIT License. See LICENSE for details.

👨‍💻 Author

K52-ai
🔗 GitHub Repository
<img width="1088" height="456" alt="image" src="https://github.com/user-attachments/assets/2deae248-a3b0-43f9-b590-1e45c02ecb03" />
