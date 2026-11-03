Quick Start Guide
=================

Plexiglass 0.1 provides a non-interactive CLI and a dependency-free Python SDK
for controlled prompt-injection and synthetic data-leakage evaluation.
Requires Python 3.10 or newer.

.. code-block:: shell

    pip install -e .
    python examples/fixture_server.py

In another terminal:

.. code-block:: shell

    plx scan --cases examples/security-cases.jsonl \
      --target http://127.0.0.1:8765 --output evaluation-runs/baseline

The output contains complete JSON/JSONL evidence and an escaped HTML report.
To fail CI on new assertion failures, supply ``--baseline`` pointing to a prior
``report.json`` for the same case pack. Exit codes are 0 for pass/no regressions,
1 for assertion failures/regressions, and 2 for incomplete or invalid evaluations.

The sample server is a protocol fixture, not an AI model or security benchmark.
Adapt cases and endpoint wrappers to your application's actual trust boundaries.
See the repository README for the case schema, HTTP contract, SDK, limitations,
and migration of older interactive commands to ``plx-legacy``.
