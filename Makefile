# Cross-Platform Remote Administration & Steganography Security Lab
# Makefile for Linux (Arch / WSL2), macOS, and Windows

.PHONY: help setup certs probe controller client test lint format stego-demo defense-demo clean

# Determine OS and appropriate virtual environment Python path
ifeq ($(OS),Windows_NT)
    VENV_BIN := ./.venv/Scripts
    PYTHON   := $(if $(wildcard $(VENV_BIN)/python.exe),$(VENV_BIN)/python.exe,python)
    RM_CMD   := powershell -Command "Remove-Item -Recurse -Force -ErrorAction SilentlyContinue"
else
    VENV_BIN := ./.venv/bin
    PYTHON   := $(if $(wildcard $(VENV_BIN)/python),$(VENV_BIN)/python,python3)
    RM_CMD   := rm -rf
endif

help: ## Show this help menu
	@echo "Cross-Platform Security Lab - Make Targets"
	@echo "==========================================="
	@echo "Usage: make [target]"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-16s %s\n", $$1, $$2}'

setup: ## Create virtual environment and install all dependencies
	$(PYTHON) -m venv ./.venv
	$(PYTHON) -m pip install -r requirements.txt ruff

certs: ## Generate TLS certificates (CA, server, client) and HMAC pre-shared key
	$(PYTHON) -m core.crypto_utils --generate-certs --generate-psk

probe: ## Run cross-platform environment and capability detection
	$(PYTHON) -m core.platform_detect

controller: ## Start the TLS Controller server (reads from .env if present)
	$(PYTHON) -m core.controller

client: ## Start the Status Telemetry Client (reads from .env if present)
	$(PYTHON) -m core.client

test: ## Run the automated unit test suite
	$(PYTHON) -m unittest discover -s tests -p "test_*.py" -v

lint: ## Check code style and errors using Ruff
	$(PYTHON) -m ruff check .

format: ## Automatically format all code using Ruff
	$(PYTHON) -m ruff format .

stego-demo: ## Run PNG and PDF steganography demonstrations
	@echo "--- Running PNG LSB Steganography Demo ---"
	$(PYTHON) -m stego.png_stego --demo
	@echo "--- Running PDF Text Attachment Demo ---"
	$(PYTHON) -m stego.pdf_stego --demo

defense-demo: ## Run defensive file forensics demonstration
	$(PYTHON) -m defense.file_forensics --demo

clean: ## Remove temporary build caches, test outputs, and bytecode
	$(RM_CMD) .ruff_cache __pycache__ */__pycache__ *.pyc output_*.png output_*.pdf
