# Gemini Cloud Demo Setup

This document describes how to configure Gemini Cloud Demo inference for the first-party bundled synthetic Windows demo assessment in RAVEN-X. The provider supports two authentication modes: **Google Cloud Vertex AI (ADC)** and **Google AI Studio (Developer API Key)**.

## Security Boundary

- Gemini Cloud Demo is strictly restricted to the server-owned synthetic fixture (`windows-hardening-v1`).
- Real endpoint evidence, customer reports, telemetry, hostnames, registry keys, and credentials are **never** forwarded to cloud endpoints.
- Any request attempting to pair Gemini with a real endpoint or fleet assessment fails closed with `422 INVALID_REQUEST` before any credential discovery, report reading, or network calls.
- Cloud inference is disabled by default (`RAVENX_CLOUD_GEMINI_ENABLED=false`).
- All automated tests and CI use pluggable test transports; no live API calls are made and no secrets are stored.

---

## Authentication Modes

### Mode 1: Google Cloud Vertex AI (`adc`, Default)

Uses official Google Cloud Application Default Credentials (ADC) for Vertex AI:
- **Auth Mode**: `RAVENX_CLOUD_GEMINI_AUTH_MODE=adc` (or omitted, as `adc` is default).
- **Pinned Endpoint**:
  ```
  https://aiplatform.googleapis.com/v1/projects/{project}/locations/global/publishers/google/models/gemini-3.5-flash-lite:generateContent
  ```
- **Authentication**: `Authorization: Bearer <token>` acquired via `google.auth.default(...)` using a bounded per-invocation timeout wrapper (does not modify process-global socket defaults).
- **Required Configuration**:
  - `RAVENX_CLOUD_GEMINI_ENABLED=true`
  - `RAVENX_CLOUD_GEMINI_PROJECT="your-project-id"` (or standard `GOOGLE_CLOUD_PROJECT`)
- **Envelope**: `generationConfig.responseSchema` with uppercase types (`ARRAY`, `STRING`).
- **Dependencies**: Requires optional dependencies in `requirements-cloud.txt` (`google-auth`, `requests`).

### Mode 2: Google AI Studio Developer API (`api_key`)

Uses a direct API key from Google AI Studio:
- **Auth Mode**: `RAVENX_CLOUD_GEMINI_AUTH_MODE=api_key`
- **Pinned Endpoint**:
  ```
  https://generativelanguage.googleapis.com/v1beta/models/gemini-3.5-flash-lite:generateContent
  ```
- **Authentication**: `x-goog-api-key: <key>` header (never passed in query strings, URLs, or command lines).
- **Required Configuration**:
  - `RAVENX_CLOUD_GEMINI_ENABLED=true`
  - `RAVENX_CLOUD_GEMINI_AUTH_MODE=api_key`
  - Key provisioned into Windows Credential Manager (`RAVEN-X/GeminiApiKey`) via `scripts/manage-gemini-credentials.ps1 -Action Set` or `python -m backend.cli gemini-key set`.
  - Project ID is **not** required and ADC is **not** initialized.
- **Envelope**: Developer API `generationConfig.responseMimeType: "application/json"` and `generationConfig.responseJsonSchema: {"type": "array", "items": {"type": "string"}}`.
- **Dependencies**: None beyond standard Python library (`urllib.request`).

---

## Windows PowerShell Key Provisioning Procedure (`api_key` Mode)

To provision or rotate the Gemini Developer API key in Windows Credential Manager without exposing your secret key in command history, environment variables, or console logs, use the masked-input manager:

### 1. Provision Key Securely
```powershell
# Run the interactive credential manager:
.\scripts\manage-gemini-credentials.ps1 -Action Set
```
The script securely prompts with `Read-Host -AsSecureString` and pipes standard input directly to the backend CLI without exposing the secret to command-line arguments or process environment blocks.

### 2. Verify Status Safely
```powershell
.\scripts\manage-gemini-credentials.ps1 -Action Status
```
Output:
```json
{
  "configured": true,
  "target": "RAVEN-X/GeminiApiKey",
  "type": "generic",
  "persistence": "local_machine"
}
```

### 3. Start the Server Locally
Enable cloud Gemini mode in your session or configuration:
```powershell
$env:RAVENX_CLOUD_GEMINI_ENABLED = "true"
$env:RAVENX_CLOUD_GEMINI_AUTH_MODE = "api_key"

& .venv-ravenx\Scripts\python.exe -m uvicorn backend.api.main:app --host 127.0.0.1 --port 8000
```

### 4. Verify in the Portal
1. Log in to the portal at `http://127.0.0.1:8000` (or frontend dev server `http://localhost:5173`).
2. Navigate to **AI Analyst**.
3. In **Evidence scope**, choose **Bundled synthetic Windows demo**.
4. In **Model**, choose **Gemini 3.5 Flash-Lite (Cloud Demo)**.
5. Click **Analyze evidence**.
6. Verify the prioritized plan renders with badge `Gemini 3.5 Flash-Lite (Cloud Demo)`.

### 5. Rotation or Deletion
To rotate the key:
```powershell
.\scripts\manage-gemini-credentials.ps1 -Action Rotate
```
To remove the key:
```powershell
.\scripts\manage-gemini-credentials.ps1 -Action Delete
```
Deletion immediately causes subsequent cloud calls to fall back cleanly to `Offline rules` without restarting the server.
