# Android application starter

The Android client is added alongside the existing Streamlit application. It calls the FastAPI service in api/ and does not replace app.py.

## Generate the native Android project (Windows PowerShell)

From the repository root, after installing Flutter:

```powershell
flutter create --platforms=android --org com.cryptosentinel --project-name crypto_sentinel mobile_app
Copy-Item mobile/starter/pubspec.yaml mobile_app/pubspec.yaml -Force
New-Item -ItemType Directory -Force mobile_app/lib | Out-Null
Copy-Item mobile/starter/lib/main.dart mobile_app/lib/main.dart -Force
Set-Location mobile_app
flutter pub get
```

Add this permission directly under the opening manifest element in android/app/src/main/AndroidManifest.xml:

```xml
<uses-permission android:name="android.permission.INTERNET" />
```

Then run on a connected Android phone (USB debugging enabled) or emulator:

```powershell
flutter devices
flutter run
```

## Connect to the backend

Set the API base URL in the app to your deployed HTTPS FastAPI URL. Enter the API key provisioned by the backend administrator. Do not put production secrets in source code.

For local testing from a physical phone, use your Windows PC LAN IPv4 address (not 127.0.0.1) and allow port 8000 through Windows Firewall on a private network. For public phone installation, deploy the API with HTTPS and persistent evidence storage first.

## Build an installable APK

```powershell
flutter build apk --release
```

APK path: build/app/outputs/flutter-apk/app-release.apk

Copy the APK to your phone and install it. Android may ask you to allow installation from the browser or file manager used to open the APK.

## Current starter scope

- Select MP4, MOV, AVI, MKV, MPG or MPEG.
- Create a frame-by-frame SHA-256 baseline through the FastAPI backend.
- Compare a later upload against that baseline.
- Display frame mismatch counts and integrity percentage.

This is an initial mobile client. Add persistent job history, secure key provisioning, report downloads, upload progress/cancellation and stronger account authentication before public distribution.