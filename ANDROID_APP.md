# Crypto Sentinel Android app implementation

This Android client is being added to the existing repository without replacing the Streamlit application.

## Repository additions

- `api/main.py`: FastAPI service that calls the existing `core/` SHA-256 and verification modules.
- `api/requirements.txt`: isolated API dependencies; the Streamlit requirements remain unchanged.
- `api/Dockerfile`: container build for a cloud-hosted API.
- `mobile/starter/`: Flutter app source template.
- `mobile/README.md`: Windows setup and APK build instructions.

## Windows 11 setup

1. Install Flutter SDK, Android Studio and Python 3.11.
2. Add Flutter's `bin` directory to PATH.
3. Run `flutter doctor` and `flutter doctor --android-licenses`.
4. From the repository root, create the Android shell and copy the starter:

```powershell
flutter create --platforms=android --org com.cryptosentinel --project-name crypto_sentinel mobile_app
Copy-Item mobile/starter/pubspec.yaml mobile_app/pubspec.yaml -Force
New-Item -ItemType Directory -Force mobile_app/lib | Out-Null
Copy-Item mobile/starter/lib/main.dart mobile_app/lib/main.dart -Force
Set-Location mobile_app
flutter pub get
```

5. Add INTERNET permission to `android/app/src/main/AndroidManifest.xml`:

```xml
<uses-permission android:name="android.permission.INTERNET" />
```

6. Run `flutter run` to test on a phone or emulator.
7. Run `flutter build apk --release` to generate the installable APK.

## Run the API locally

From the repository root in PowerShell:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r api/requirements.txt
$env:API_KEY = "set-a-private-random-api-key"
$env:FORENSIC_HMAC_SECRET = "set-a-private-secret-of-at-least-32-characters"
$env:EVIDENCE_ROOT = "$PWD\api\data\evidence"
uvicorn api.main:app --reload --host 0.0.0.0 --port 8000
```

API health: `http://127.0.0.1:8000/health`  
Interactive docs: `http://127.0.0.1:8000/docs`

For a phone on the same Wi-Fi, use the PC's LAN IPv4 address rather than localhost. For use outside the local network, deploy the API with HTTPS and persistent private storage.

## API routes

| Method | Route | Purpose |
|---|---|---|
| GET | `/health` | Health check |
| POST | `/api/v1/videos/analyze` | Create a frame-hash baseline |
| POST | `/api/v1/jobs/{job_id}/verify` | Compare a later upload to the baseline |
| GET | `/api/v1/jobs/{job_id}` | Baseline metadata |
| GET | `/api/v1/jobs/{job_id}/report` | Signed-chain verification report |

All API routes except health require the `X-API-Key` header.

## Forensic interpretation

The first upload establishes the reference baseline. It does not prove that a video was authentic before that upload. For stronger provenance, the baseline must be generated at a trusted camera/recorder or capture point. Frame-level SHA-256 comparison is exact: re-encoding or transcoding can change decoded pixels and result in mismatches even when the scene appears unchanged.

## Before public release

- Deploy the API with HTTPS.
- Set `API_KEY` and `FORENSIC_HMAC_SECRET` as server-side secrets, never in the APK or Git.
- Configure persistent, access-controlled evidence storage for `EVIDENCE_ROOT`.
- Add user accounts or per-device credentials, rate limits, upload quotas, retention and audit logging.
- Test on-device upload, interrupted uploads, large files, altered frames and report downloads.
