from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

import db
from config import ORIGIN, SESSION_SECRET
from webauthn_routes import router as webauthn_router

app = FastAPI()
app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    same_site="lax",
    https_only=ORIGIN.startswith("https://"),
)

db.init_db()

app.mount("/static", StaticFiles(directory="static"), name="static")
app.include_router(webauthn_router)

@app.get("/", response_class=HTMLResponse)
def index():
    with open("static/index.html", "r", encoding="utf-8") as f:
        return f.read()

@app.get("/api/me")
def me(request: Request):
    user = request.session.get("user")
    return {"authenticated": bool(user), "user": user}

@app.post("/api/logout")
def logout(request: Request):
    request.session.clear()
    return {"ok": True}