# Relay

Relay is a local, AI-assisted incident response workspace. It stores incidents, resolutions, runbooks, activities, and manually ingested signals in SQLite. Its incident agent retrieves resolved historical incidents with TF-IDF/cosine similarity, then produces evidence-linked recommendations. It remains usable without an LLM key through a clearly labeled retrieval fallback.

## Architecture

- **Frontend:** React + Vite, with the original Relay visual language and a fetch API client.
- **Backend:** FastAPI + SQLAlchemy + SQLite at `backend/app/main.py`.
- **Memory:** resolved incident text is persisted and ranked with scikit-learn TF-IDF/cosine similarity.
- **LLM:** Gemini configuration is reserved via environment variables; the no-key fallback is safe and deterministic. Logs are sanitized before analysis.

## Features

- Persistent incident creation, filtering, analysis, resolution and reopening
- Resolution feedback becomes future searchable incident memory
- Real, computed similarity scores and source incident references
- Runbook creation/deletion and retrieval during analysis
- Manual signal ingestion, service inventory, activity timeline and honest empty/unavailable states
- Seeded demo records (clearly marked as sample data) including connection-pool exhaustion
- Advisory-only human resolution review; Relay never runs commands or infrastructure changes

## Run locally

Requires Python 3.11+ and Node.js 18+.

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
uvicorn app.main:app --reload
```

In another terminal:

```powershell
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173`. The backend API documentation is at `http://localhost:8000/docs`.

## Configuration

Copy `backend/.env.example` to `backend/.env` (and load it in your shell or process manager). Key settings:

- `DATABASE_URL=sqlite:///./data/relay.db`
- `SEED_SAMPLE_DATA=true`
- `CORS_ORIGINS=http://localhost:5173`
- `GEMINI_API_KEY=` and `GEMINI_MODEL=` for future Gemini-backed analysis
- `VITE_API_BASE_URL=http://localhost:8000/api/v1` (optional frontend setting)

The database initializes and seeds only when empty. User records survive restarts. To reset demo data in development, stop the backend and delete only `backend/data/relay.db` after backing up any wanted user data.

### GitHub OAuth and workflow signals

Relay supports a real GitHub OAuth authorization flow and imports actual GitHub Actions workflow results as attributed signals. Create a GitHub OAuth App and set its callback URL to `http://127.0.0.1:8000/api/v1/github/callback`, then set these backend environment variables:

```env
GITHUB_CLIENT_ID=your_oauth_client_id
GITHUB_CLIENT_SECRET=your_oauth_client_secret
RELAY_TOKEN_ENCRYPTION_KEY=your_fernet_key
```

Generate the Fernet key with `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`. Tokens are encrypted before persistent storage. In Relay, open **GitHub**, sign in, choose a repository, then select **Sync workflows**. GitHub workflow results are ingested as GitHub-sourced signals; Relay does not label commits as deployments unless deployment evidence exists.

## Workflow

1. Create an incident and include symptoms, errors, logs and deployment context.
2. Open it and choose **Analyze with memory**.
3. Review the computed similar incidents, evidence, diagnostic advice, runbooks and uncertainty notes.
4. Use **Resolve incident** to save the confirmed cause, actual procedure, lesson and feedback.
5. A later similar incident will retrieve that saved resolution after restart.

For a polished walkthrough, use the landing page’s **Record the demo** button. It creates the checkout/database-timeout scenario, retrieves the seeded pool-exhaustion history, opens the analysis, and gives you a human-review resolution form to close the loop on camera.

## API highlights

`/api/v1/health`, `/overview`, `/incidents`, `/incidents/{id}/analyze`, `/incidents/{id}/resolve`, `/memory/search`, `/runbooks`, `/signals/ingest`, and `/services`.

## Tests

```powershell
cd backend
pytest tests -q
```

The backend test covers create → resolve → retrieve → fallback analysis. The frontend can be production checked with `npm run build`.

## Current limitations

Gemini is configured as an environment-driven extension point, but this MVP always uses the retrieval fallback until a provider implementation/key is enabled. GitHub/deployment integration is intentionally not simulated; deployment claims are only stored when supplied. Service dependency topology, FTS5 and schema migration tooling are future extensions; the SQLite schema is initialized safely on startup.
