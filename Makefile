.PHONY: install run status report test lint format clean browser

install:
	pip install -e ".[dev]"

browser:
	playwright install chromium

run:
	swiggy-hunter run

status:
	swiggy-hunter status

report:
	swiggy-hunter report

test:
	pytest -q

lint:
	ruff check src tests

format:
	ruff format src tests

clean:
	rm -rf build dist *.egg-info .pytest_cache .ruff_cache
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
