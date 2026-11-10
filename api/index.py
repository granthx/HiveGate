"""Vercel serverless entrypoint for HiveGate."""

from __future__ import annotations

import os
import sys
from pathlib import Path

# Add repo root and test project to Python module search path
REPO_ROOT = Path(__file__).resolve().parent.parent
TEST_PROJECT_DIR = REPO_ROOT / "test project"

for path in (REPO_ROOT, TEST_PROJECT_DIR):
    path_str = str(path)
    if path_str not in sys.path:
        sys.path.insert(0, path_str)

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from gateway.main import create_app as create_gateway_app
from server import create_projects_app

# 1. Instantiate the Core Gateway Application
app = create_gateway_app()

# 2. Configure CORS to allow Cloudflare Pages, custom domains, and local frontends
cors_env = os.getenv("CORS_ORIGINS", "")
allowed_origins = [o.strip() for o in cors_env.split(",") if o.strip()] if cors_env else ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_origin_regex=r"https://.*\.pages\.dev",
    allow_credentials=True if allowed_origins != ["*"] else False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 3. Mount Test Projects and Zifi Browser endpoints (/api and /targets)
try:
    projects_app = create_projects_app()
    existing_paths = {getattr(r, "path", None) for r in app.routes}
    for route in projects_app.routes:
        path = getattr(route, "path", None)
        if path and (path.startswith("/api") or path.startswith("/targets")) and path not in existing_paths:
            app.routes.append(route)
            existing_paths.add(path)
except Exception:
    # Graceful fallback if UI project catalog cannot load in limited serverless env
    pass

