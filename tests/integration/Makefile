# Makefile for ABAC integration tests

.PHONY: help install test test-ecs test-efs test-path test-all clean report

help:
	@echo "ABAC Integration Tests"
	@echo ""
	@echo "Usage:"
	@echo "  make install      Install test dependencies"
	@echo "  make test         Run all ABAC tests"
	@echo "  make test-ecs     Run ECS isolation tests only"
	@echo "  make test-efs     Run EFS isolation tests only"
	@echo "  make test-path    Run path isolation tests only"
	@echo "  make report       Generate HTML test report"
	@echo "  make clean        Clean up test artifacts"
	@echo ""
	@echo "Environment variables required:"
	@echo "  KEYCLOAK_URL, SRE_ROLE_ARN, ECS_CLUSTER, EFS_FILESYSTEM_ID"

install:
	pip install -r requirements.txt

test:
	pytest -v -m abac

test-ecs:
	pytest -v test_abac_ecs_isolation.py

test-efs:
	pytest -v test_abac_efs_isolation.py

test-path:
	pytest -v test_abac_path_isolation.py

test-all: test

report:
	pytest -v -m abac --html=report.html --self-contained-html
	@echo "Report generated: report.html"

clean:
	rm -f report.html
	rm -rf __pycache__ .pytest_cache
	rm -rf fixtures/__pycache__
	find . -name "*.pyc" -delete
