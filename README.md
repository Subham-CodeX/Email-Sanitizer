# PhishingTrack

AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence Platform.

## Phase 0

Current milestone:
- React + Vite + TypeScript frontend
- FastAPI backend
- MongoDB connection
- Health and database-status endpoints
- CORS configuration
- Environment configuration
- Clean project structure ready for Phase 1 email ingestion

## Requirements

- Node.js 20+
- Python 3.11+
- MongoDB Atlas account or local MongoDB

## Backend

```bash
cd backend
python -m venv .venv

# Windows
.venv\Scripts\activate

# macOS/Linux
source .venv/bin/activate

pip install -r requirements.txt

copy .env.example .env
# macOS/Linux: cp .env.example .env

uvicorn app.main:app --reload --port 8000
```

Backend:
http://localhost:8000

Swagger:
http://localhost:8000/docs

Health:
http://localhost:8000/api/v1/health

## Frontend

```bash
cd frontend
npm install
copy .env.example .env
# macOS/Linux: cp .env.example .env

npm run dev
```

Frontend:
http://localhost:5173

## MongoDB

For MongoDB Atlas, put the connection string in:

`backend/.env`

Example:

```env
MONGODB_URI=mongodb+srv://USERNAME:PASSWORD@cluster.mongodb.net/?retryWrites=true&w=majority
MONGODB_DB=phishingtrack
```

Never commit `.env`.

## Phase 0 success criteria

Open the frontend and verify:
- Backend status: Connected
- MongoDB status: Connected
- API URL: http://localhost:8000
