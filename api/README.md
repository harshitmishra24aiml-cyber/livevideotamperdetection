# Crypto Sentinel FastAPI backend

This API is an additional service. It does not replace or modify the Streamlit entry point.

## Local Windows setup

From the repository root in PowerShell:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r api/requirements.txt
Copy-Item api/.env.example api/.env
```

Edit `api/.env` and set two private values:
- `API_KEY`: a long random client access token.
- `FORENSIC_HMAC_SECRET`: at least 32 random characters. Keep this only on the backend.

Load the environment variables in the current PowerShell session (replace the sample values):

```powershell
$env:API_KEY = "replace-with-a-long-random-api-token"
$env:FORENSIC_HMAC_SECRET = "replace-with-at-least-32-random-bytes"
$env:EVIDENCE_ROOT = "$PWD\api\data\evidence"
uvicorn api.main:app --reload --host 0.0.0.0 --port 8000
```

Open:
- Health: http://127.0.0.1:8000/health
- API docs: http://127.0.0.1:8000/docs

## API

- `POST /api/v1/videos/analyze` — upload a video and create a frame-by-frame SHA-256 baseline.
- `POST /api/v1/jobs/{job_id}/verify` — upload a later copy and compare its decoded frames with the stored baseline.
- `GET /api/v1/jobs/{job_id}` — retrieve baseline metadata.
- `GET /api/v1/jobs/{job_id}/report` — retrieve the signed-chain verification report.

All API endpoints except `/health` require `X-API-Key`.

**Forensic limitation:** the first upload establishes the reference baseline; it cannot prove that the video was authentic before it was uploaded. For a real evidence workflow, establish the baseline at a trusted camera/recorder or trusted capture point. Lossy re-encoding can change decoded pixels and therefore produce hash mismatches.

## Deployment notes

Use a persistent private volume or object storage for `EVIDENCE_ROOT`. Do not rely on an ephemeral container filesystem for evidence retention. Configure TLS/HTTPS, secrets, authentication, upload limits, retention and access logging before exposing the API publicly.
