.PHONY: develop test build

develop:
	python -m pip install -e .

test:
	python -m unittest discover -s tests -v

build:
	python -m build
