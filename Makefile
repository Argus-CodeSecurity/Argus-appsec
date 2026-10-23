# Developer convenience targets. See CONTRIBUTING.md.
.PHONY: install test lint format-check typecheck accuracy check fmt scan-example docker docs clean

install:
	pip install -e ".[dev,ast]"

test:
	pytest -q

lint:
	ruff check .

format-check:
	ruff format --check .

typecheck:
	mypy src/nephilex

accuracy:
	python benchmarks/accuracy.py

# Everything CI runs on a pull request.
check: lint format-check typecheck test accuracy

fmt:
	ruff format .
	ruff check . --fix

# Run a full scan on the bundled vulnerable example with all features on.
scan-example:
	nephilex scan examples/vulnerable-app --attack-sim --patches

docker:
	docker build -t nephilex:local .

docs:
	mkdocs serve

clean:
	rm -rf .pytest_cache .ruff_cache .mypy_cache htmlcov .coverage \
		dist build src/*.egg-info examples/reports
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
