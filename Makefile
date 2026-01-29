.PHONY: install setup test clean help

help:
	@echo "Vibe Probe - OSINT Reconnaissance Tool"
	@echo ""
	@echo "Available commands:"
	@echo "  make install    - Install dependencies"
	@echo "  make setup      - Setup configuration files"
	@echo "  make test       - Run basic tests"
	@echo "  make clean      - Clean generated files and reports"
	@echo "  make run        - Run example scan"
	@echo ""
	@echo "Usage:"
	@echo "  python vibe-probe.py <domain> [options]"

install:
	pip install -r requirements.txt

setup:
	@if [ ! -f .env ]; then \
		cp .env.example .env; \
		echo "Created .env file - please edit with your API keys"; \
	else \
		echo ".env already exists"; \
	fi
	@if [ ! -f config.yaml ]; then \
		cp config.example.yaml config.yaml; \
		echo "Created config.yaml file"; \
	else \
		echo "config.yaml already exists"; \
	fi

test:
	@echo "Testing DNS probe..."
	@python -c "import sys; sys.path.insert(0, '.'); from probes.dns_probe import DNSProbe; print('✓ DNS probe imports successfully')"
	@echo "Testing configuration..."
	@python -c "import sys; sys.path.insert(0, '.'); from utils.config import Config; print('✓ Configuration loads successfully')"
	@echo "Testing reporter..."
	@python -c "import sys; sys.path.insert(0, '.'); from reporter import ReportGenerator; print('✓ Reporter imports successfully')"
	@echo ""
	@echo "✓ All basic tests passed"

clean:
	@echo "Cleaning up..."
	@rm -rf reports/
	@rm -rf __pycache__
	@rm -rf probes/__pycache__
	@rm -rf utils/__pycache__
	@find . -name "*.pyc" -delete
	@find . -name "*.pyo" -delete
	@find . -name ".DS_Store" -delete
	@echo "✓ Cleanup complete"

run:
	@echo "Example scan requires a target domain:"
	@echo "  make run-example DOMAIN=example.com"

run-example:
	@if [ -z "$(DOMAIN)" ]; then \
		echo "Usage: make run-example DOMAIN=example.com"; \
	else \
		python vibe-probe.py $(DOMAIN) --verbose; \
	fi
