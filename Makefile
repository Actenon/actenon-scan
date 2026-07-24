.PHONY: install test lint verify-claims

install:
	pip install --upgrade pip
	pip install -e ".[dev]"

test:
	python -m pytest tests/ -v

lint:
	python -m ruff check .
	python -m ruff format --check .

# Machine-verify every claim the README makes about the package itself.
# Fable 5 Part 3A/G: for a trust product, one falsified claim costs more
# than ten missing features.
verify-claims:
	@echo "==> Verifying zero runtime dependencies"
	@python -c "import tomllib,sys; \
	        d=tomllib.load(open('pyproject.toml','rb')); \
	        deps=d['project'].get('dependencies',[]); \
	        sys.exit(1) if deps else print('OK: zero runtime deps')"
	@echo "==> Verifying __version__ matches pyproject.toml"
	@python -c "import tomllib; from actenon_scan import __version__; \
	        pv=tomllib.load(open('pyproject.toml','rb'))['project']['version']; \
	        assert __version__ == pv, f'__version__={__version__!r} but pyproject={pv!r}'; \
	        print(f'OK: __version__={__version__} matches pyproject')"
	@echo "==> Verifying Python badge in sync"
	@python scripts/sync_badges.py --check
	@echo "==> Verifying README install instructions"
	@python scripts/check_readme_installs.py
	@echo "==> Verifying ecosystem table"
	@python -m actenon_protocol.ecosystem --check README.md --repo actenon-scan
	@echo "==> All claims verified."
