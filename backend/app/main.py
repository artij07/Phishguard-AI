import json
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.dashboard import router as dashboard_router
from app.api.routes_scans import router as scan_router
from app.database.database import Base, engine


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(
    title="PhishGuard AI",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:5174",
        "http://127.0.0.1:5174",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scan_router)
app.include_router(dashboard_router)


@app.websocket("/ws/scans/{scan_id}")
async def scan_progress(websocket: WebSocket, scan_id: str):
    await websocket.accept()
    for value in [15, 35, 60, 85, 100]:
        await websocket.send_json({"scan_id": scan_id, "progress": value, "status": "processing"})
        if value == 100:
            await websocket.send_json({"scan_id": scan_id, "progress": 100, "status": "completed"})
            break
    await websocket.close()


@app.exception_handler(Exception)
async def handle_unexpected_error(request, exc):
    return JSONResponse(status_code=500, content={"detail": "An unexpected server error occurred."})
