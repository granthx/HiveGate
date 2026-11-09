.PHONY: install backend gateway demo projects bench test

PYTHON ?= python
HOST ?= 127.0.0.1
PORT ?= 8000
PROJECTS_PORT ?= 8010

install:
	$(PYTHON) -m pip install -r requirements.txt

backend:
	$(PYTHON) -m uvicorn demo.fragile_backend:app --host $(HOST) --port 9001

gateway:
	$(PYTHON) -m uvicorn gateway.main:app --host $(HOST) --port $(PORT)

demo:
	$(PYTHON) -m uvicorn demo.demo_app:app --host $(HOST) --port $(PORT)

projects:
	$(PYTHON) -m uvicorn server:app --app-dir "test project" --host $(HOST) --port $(PROJECTS_PORT)

bench:
	$(PYTHON) -m demo.benchmark

test:
	$(PYTHON) -m pytest -q
