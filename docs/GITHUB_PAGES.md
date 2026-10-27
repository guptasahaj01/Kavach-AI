# Public deployment

GitHub Pages hosts the React interface only. FastAPI, the classifier, database and Ollama must run on a separate server. Publishing the interface alone does not enable inspections or generation.

## Publish the interface

1. Open the repository Settings → Pages.
2. Under Build and deployment, choose **GitHub Actions**.
3. Open Actions → Deploy console to GitHub Pages → Run workflow on main. A push changing frontend files also runs it.
4. The default URL is https://guptasahaj01.github.io/Kavach-AI/.

The committed workflow builds with npm ci and uploads frontend/dist. It uses the public repository variables below (Settings → Secrets and variables → Actions → Variables):

| Variable | Value |
| --- | --- |
| VITE_API_BASE_URL | The public HTTPS backend origin, for example https://api.kavach-ai-is.com |
| VITE_BASE_PATH | Leave unset for /Kavach-AI/; set / when using the custom domain |

Without a backend URL the public console explicitly reports that the backend is not connected. Variables beginning VITE_ are public bundle contents, never secrets. After changing variables, rerun the workflow.

## Host the backend

Use a server with sufficient memory for the injection classifier and chosen Ollama model; measure requirements before selecting a paid plan. The current installation uses persistent local SQLite state and local Ollama. A server with persistent storage is the straightforward deployment topology.

Install project Python dependencies and Ollama, install the configured model, and run the FastAPI service behind an HTTPS reverse proxy. Keep Ollama and the Python listener private to the server; expose the HTTPS application endpoint. Configure:

- KAVACH_ALLOWED_ORIGINS=https://guptasahaj01.github.io,https://kavach-ai-is.com,https://www.kavach-ai-is.com
- KAVACH_OLLAMA_URL=http://127.0.0.1:11434
- KAVACH_LLM_MODEL=qwen2.5:3b
- KAVACH_DB_PATH to a persistent writable database path
- KAVACH_API_KEYS in server-side configuration only, with new random tokens

Before exposing unrestricted research endpoints, add authentication/rate limits for costly generation and benchmark operations. The local research server is not a managed public service; public anonymous workloads need an explicit operating policy. Do not reuse local demonstration tokens.

## Connect kavach-ai-is.com

The domain must first be purchased; availability and ownership are not established by adding it to this repository.

After purchase:

1. Verify the domain in GitHub account Settings → Pages, using the exact TXT record GitHub provides.
2. Repository Settings → Pages → Custom domain: enter kavach-ai-is.com.
3. Set these DNS records at the domain provider:

| Type | Name | Value |
| --- | --- | --- |
| A | @ | 185.199.108.153 |
| A | @ | 185.199.109.153 |
| A | @ | 185.199.110.153 |
| A | @ | 185.199.111.153 |
| CNAME | www | guptasahaj01.github.io |

Preserve unrelated mail/TXT records. Remove only conflicting website records after confirming what they serve. Do not create wildcard records for Pages.

4. Set repository variable VITE_BASE_PATH to / and rerun deployment.
5. Once GitHub completes its DNS check and certificate issuance, enable Enforce HTTPS.
6. Configure api.kavach-ai-is.com separately to the backend host, and set VITE_API_BASE_URL to its HTTPS address.

Sources: [GitHub Pages custom domains](https://docs.github.com/en/pages/configuring-a-custom-domain-for-your-github-pages-site/managing-a-custom-domain-for-your-github-pages-site), [Creating a Pages site](https://docs.github.com/en/pages/getting-started-with-github-pages/creating-a-github-pages-site).

## Status

The deployment configuration is provided. Domain purchase, DNS ownership verification, backend provisioning and a successful Pages deployment must be checked separately; this document does not imply they have been completed.

## Free laptop demo (macOS)

The launcher starts a single local backend on port 8766, a temporary Cloudflare HTTPS tunnel and a macOS sleep-prevention process. It restricts browser origins to this GitHub Pages account and serializes heavy requests. Full benchmark runs are unavailable on the public demo to reserve laptop memory. The URL is public; use only synthetic inputs, and stop the demo when finished. Closing the Mac lid or losing connectivity can interrupt service.

Prerequisites: the repository Python environment, Ollama running with the configured model installed, cached classifier weights and `cloudflared` (`brew install cloudflared`). Then:

```bash
./venv/bin/python3 scripts/demo.py start --publish
./venv/bin/python3 scripts/demo.py status
./venv/bin/python3 scripts/demo.py stop
```

`--publish` uses the existing Git credential helper to update the repository's public `VITE_API_BASE_URL` variable and request a Pages rebuild. Credentials are never written into the project. Without it, set the variable manually to the URL printed by `status`. Each restart gets a new tunnel URL and requires a Pages rebuild. The website address stays the same.

Local process IDs, logs, tunnel URL and synthetic audit database are in ignored `.demo/`. The launcher stops its backend, tunnel and sleep-prevention child processes together. It does not install login services or start automatically when the computer restarts.
