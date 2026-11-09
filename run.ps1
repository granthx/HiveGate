param(
    [Parameter(Position = 0)]
    [ValidateSet("install", "backend", "gateway", "demo", "projects", "all", "bench", "test")]
    [string]$Command = "demo",
    [string]$HostAddress = "127.0.0.1",
    [int]$Port = 8000,
    [int]$ProjectsPort = 8010
)

$ErrorActionPreference = "Stop"

switch ($Command) {
    "install"  { python -m pip install -r requirements.txt }
    "backend"  { python -m uvicorn demo.fragile_backend:app --host $HostAddress --port 9001 }
    "gateway"  { python -m uvicorn gateway.main:app --host $HostAddress --port $Port }
    "demo"     { python -m uvicorn server:app --app-dir "test project" --host $HostAddress --port $ProjectsPort }
    "projects" { python -m uvicorn server:app --app-dir "test project" --host $HostAddress --port $ProjectsPort }
    "all"      { python -m uvicorn server:app --app-dir "test project" --host $HostAddress --port $ProjectsPort }
    "bench"    { python -m demo.benchmark }
    "test"     { python -m pytest -q }
}
