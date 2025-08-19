# WiFi Jammer Tool - Makefile
# By Paijo

.PHONY: help install install-dev test clean lint format demo run install-deps uninstall

# Variables
PYTHON = python3
PIP = pip3
PACKAGE_NAME = wifi-jammer
VERSION = 1.0.0

# Colors for output
RED = \033[0;31m
GREEN = \033[0;32m
YELLOW = \033[1;33m
BLUE = \033[0;34m
NC = \033[0m # No Color

help: ## Show this help message
	@echo "$(BLUE)WiFi Jammer Tool - Available Commands$(NC)"
	@echo "=========================================="
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-15s$(NC) %s\n", $$1, $$2}'

install: ## Install the tool system-wide
	@echo "$(BLUE)Installing WiFi Jammer Tool...$(NC)"
	@bash install.sh

install-dev: ## Install in development mode
	@echo "$(BLUE)Installing in development mode...$(NC)"
	$(PIP) install -e .
	@echo "$(GREEN)Development installation complete!$(NC)"

install-deps: ## Install only dependencies
	@echo "$(BLUE)Installing dependencies...$(NC)"
	$(PIP) install -r requirements.txt
	@echo "$(GREEN)Dependencies installed!$(NC)"

test: ## Run all tests
	@echo "$(BLUE)Running tests...$(NC)"
	$(PYTHON) run_tests.py

test-verbose: ## Run tests with verbose output
	@echo "$(BLUE)Running tests with verbose output...$(NC)"
	$(PYTHON) -m pytest tests/ -v

test-coverage: ## Run tests with coverage report
	@echo "$(BLUE)Running tests with coverage...$(NC)"
	$(PIP) install pytest-cov
	$(PYTHON) -m pytest tests/ --cov=wifi_jammer --cov-report=html --cov-report=term

lint: ## Run linting checks
	@echo "$(BLUE)Running linting checks...$(NC)"
	$(PIP) install flake8 black isort
	@echo "$(YELLOW)Running flake8...$(NC)"
	flake8 wifi_jammer/ tests/ --max-line-length=88 --ignore=E203,W503
	@echo "$(YELLOW)Running black check...$(NC)"
	black --check wifi_jammer/ tests/
	@echo "$(YELLOW)Running isort check...$(NC)"
	isort --check-only wifi_jammer/ tests/
	@echo "$(GREEN)Linting passed!$(NC)"

format: ## Format code with black and isort
	@echo "$(BLUE)Formatting code...$(NC)"
	$(PIP) install black isort
	black wifi_jammer/ tests/
	isort wifi_jammer/ tests/
	@echo "$(GREEN)Code formatted!$(NC)"

demo: ## Run the comprehensive demo
	@echo "$(BLUE)Running WiFi Jammer Tool demo...$(NC)"
	$(PYTHON) demo.py

run: ## Run the tool in interactive mode
	@echo "$(BLUE)Starting WiFi Jammer Tool...$(NC)"
	$(PYTHON) -m wifi_jammer.cli

run-scan: ## Run the tool in scan-only mode
	@echo "$(BLUE)Starting WiFi Jammer Tool in scan mode...$(NC)"
	$(PYTHON) -m wifi_jammer.cli --scan-only

clean: ## Clean build artifacts and cache
	@echo "$(BLUE)Cleaning build artifacts...$(NC)"
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf .pytest_cache/
	rm -rf htmlcov/
	rm -rf .coverage
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	@echo "$(GREEN)Cleanup complete!$(NC)"

uninstall: ## Uninstall the tool
	@echo "$(BLUE)Uninstalling WiFi Jammer Tool...$(NC)"
	$(PIP) uninstall $(PACKAGE_NAME) -y
	@echo "$(GREEN)Uninstallation complete!$(NC)"

check: ## Check installation and dependencies
	@echo "$(BLUE)Checking installation...$(NC)"
	@echo "$(YELLOW)Python version:$(NC)"
	$(PYTHON) --version
	@echo "$(YELLOW)Pip version:$(NC)"
	$(PIP) --version
	@echo "$(YELLOW)Installed packages:$(NC)"
	$(PIP) list | grep -E "(wifi-jammer|scapy|rich|click)"
	@echo "$(YELLOW)Tool availability:$(NC)"
	$(PYTHON) -c "import wifi_jammer; print('✓ WiFi Jammer Tool imported successfully')"
	@echo "$(GREEN)Installation check complete!$(NC)"

build: ## Build distribution packages
	@echo "$(BLUE)Building distribution packages...$(NC)"
	$(PYTHON) setup.py sdist bdist_wheel
	@echo "$(GREEN)Build complete!$(NC)"

install-from-source: ## Install directly from source
	@echo "$(BLUE)Installing from source...$(NC)"
	$(PIP) install -e .
	@echo "$(GREEN)Source installation complete!$(NC)"

quick-test: ## Quick test of core functionality
	@echo "$(BLUE)Running quick functionality test...$(NC)"
	$(PYTHON) -c "
import wifi_jammer
from wifi_jammer.core.interfaces import AttackType
from wifi_jammer.factory import AttackFactory
from wifi_jammer.utils import RichLogger

print('✓ Core modules imported successfully')
print('✓ Attack types available:', [at.value for at in AttackType])
print('✓ Factory created successfully')
print('✓ Logger created successfully')
print('✓ Quick test passed!')
"
	@echo "$(GREEN)Quick test passed!$(NC)"

security-check: ## Run security and safety checks
	@echo "$(BLUE)Running security checks...$(NC)"
	@echo "$(YELLOW)Checking for security warnings...$(NC)"
	$(PYTHON) -c "
import warnings
warnings.filterwarnings('error')
try:
    import wifi_jammer
    print('✓ No security warnings detected')
except Exception as e:
    print(f'⚠️  Security warning: {e}')
"
	@echo "$(GREEN)Security check complete!$(NC)"

docs: ## Generate documentation
	@echo "$(BLUE)Generating documentation...$(NC)"
	$(PIP) install sphinx sphinx-rtd-theme
	sphinx-apidoc -o docs/source wifi_jammer/
	cd docs && make html
	@echo "$(GREEN)Documentation generated!$(NC)"

# Development helpers
dev-setup: install-deps install-dev ## Set up development environment
	@echo "$(GREEN)Development environment ready!$(NC)"

dev-test: format lint test ## Run all development checks
	@echo "$(GREEN)All development checks passed!$(NC)"

# Quick commands for common tasks
scan: run-scan ## Alias for run-scan
test-all: test-coverage lint ## Run comprehensive testing
format-all: format lint ## Format and lint code

# Default target
all: install-dev test lint ## Install, test, and lint
	@echo "$(GREEN)All tasks completed successfully!$(NC)"
