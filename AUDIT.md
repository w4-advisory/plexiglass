# Plexiglass functionality audit

Updated: 3 November 2026. Implementation: `codex/security-evaluation-mvp`, version 0.1.0. Original baseline: `54bf161`.

## Current assessment

The first milestone now provides a dependency-free CLI/SDK for repeatable, assertion-based prompt-injection and synthetic data-leakage evaluation against JSON HTTP application endpoints and Python callables. Runs preserve full evidence and produce baseline regression gates suitable for CI.

This is a controlled application-evaluation MVP. A passing run proves only that the supplied assertions held. The bundled three-case pack and deterministic fixture server demonstrate behavior; they are not a validated security benchmark or evidence of broad model safety.

## Completed from the original audit

| Area | Implemented behavior | Evidence |
|---|---|---|
| Case-aware verdicts | Validated case IDs, objectives, roles, suites, and deterministic exact-output/literal-canary assertions. Invalid checks fail before requests. | `plexiglass/evaluation.py`, `examples/security-cases.jsonl` |
| Application targets | JSON HTTP POST adapter with configurable body and nested response path; bearer token from an environment variable; callable SDK adapter. | HTTP tests cover full message forwarding, nested responses, settings, and authentication. |
| Complete evidence | Versioned manifest with complete cases and SHA-256 case hash; full responses, assertion evidence, and latency in JSONL/JSON; escaped HTML report. | Long-response preservation and HTML escaping tests. |
| Failure accounting | Target failures and evaluator failures remain distinct from passes/failures; raw exception text is excluded from reports. | Malformed response, timeout, callable exception, and invalid output tests. |
| Regression gates | Identical case/evaluator versions required; incomplete/inconclusive reports rejected; saved verdicts checked against response evidence; named regressions and improvements. | Defended baseline vs vulnerable HTTP fixture identifies the synthetic canary leak. |
| Automation | Non-interactive `plx scan` / `plx compare`, explicit output directories, and exit codes 0/1/2. | CLI integration tests exercise pass, regression, and infrastructure-error outcomes. |
| Basic bounds | Request count and socket-operation timeouts; 10 MB HTTP response bound; no implicit retries or credential forwarding through redirects. | Limit, timeout, and redirect rejection tests. |
| Packaging | Core no longer imports ML dependencies; Python >=3.10; packaged JSON/version resources; modern build commands; optional legacy dependencies. | Source/wheel build and installed CLI/resource smoke checks. |
| Legacy defects | All-success summary crash fixed; full prompt/response storage; resource loading independent of working directory; unknown metrics rejected and `pii_detection` alias recognized. | Source inspection; the optional ML runtime remains outside core integration coverage. |
| CI | Offline fixture/unit tests and wheel/install smoke workflow for Python 3.10, 3.12, and 3.14. | `.github/workflows/tests.yml`; remote workflow results must be checked on the PR. |

## Validation performed

- All 15 core tests pass locally. They exercise defended/vulnerable local HTTP applications, complete evidence, malformed output, authentication handling, redirects, timeout handling, nested response extraction, request settings, output escaping, incompatible/incomplete baselines, altered verdicts, duplicate cases, count limits, mutation isolation, and CLI exit codes.
- Tests run against localhost fixtures without paid model calls or downloaded ML models.
- Source distribution and wheel are built with isolated setuptools/wheel tooling; installation and CLI/resources are checked outside the checkout.
- Local execution uses Python 3.15. The declared compatibility matrix is checked by the new GitHub Actions workflow, not by claiming local testing of those interpreters.
- Live provider behavior, real application deployments, remote Hugging Face datasets, and the optional legacy ML stack have not been validated.

## Remaining gaps, in priority order

### P1: Validate representative cases and actual application boundaries

The adapter requires an endpoint that accepts a messages array and returns text at a configured JSON path. Applications with a fixed system prompt, retrieval pipeline, session state, or different input schema need an application-specific wrapper/callable. The endpoint must enforce session isolation; Plexiglass cannot infer it from text alone.

Next: versioned organization-specific policy packs, diverse direct/indirect injection cases, synthetic tenant/secret fixtures, and paired benign controls. Add case-pack provenance, licensing, meaningful category labels, and human-reviewed expected outcomes. Validate on known vulnerable and defended versions of a real application.

Acceptance: a reproduced finding identifies the application boundary violated, and the same case verifies a mitigation while benign tasks remain functional.

### P1: Broaden verdicts without overstating certainty

Exact output assertions are intentionally narrow. Literal canary absence misses encoded, transformed, partial, or paraphrased leakage. A formatting deviation can fail an exact-output check without demonstrating a consequential exploit. There is no calibrated LLM judge, semantic task-completion evaluator, general PII detector, or automatic severity rating.

Next: context-aware deterministic evaluators, evidence spans, task-specific outcomes, and an optional judge calibrated against human labels. Isolate judge instructions from untrusted target text. Track uncertainty and false-positive/negative rates. Add repeated trials, confidence intervals, category-level attack success, benign false-refusal rates, and utility retention.

Acceptance: each verdict mechanism has labeled validation cases and explicitly documented failure modes.

### P1: Replay and operational controls

Manifests preserve cases, evaluator version, endpoint URL, timeout/count limits, and a hash of extra request settings. They do not preserve the request body itself or callable configuration; users must retain non-secret deployment/request configuration separately. Provider-side model revisions and stochastic behavior may prevent exact replay.

The sequential runner flushes JSONL after each completed case but cannot resume interrupted runs. Socket timeouts are not a hard total-run deadline. Request count is not a monetary/token budget. There are no retries, rate controls, concurrency, usage/cost accounting, or global cancellation orchestration.

Next: explicit secret-safe replay configuration, provider-returned model IDs/usage, checkpoint/resume, bounded retry policies, rate controls, and token/cost/step/time budgets. Avoid blindly retrying actions with side effects.

Acceptance: interrupted runs resume by stable case ID; budgets stop new work reliably; replay records explain all non-secret configuration differences.

### P1: RAG, indirect injection, and agents

The current runner can send a complete preconstructed multi-message request but does not perform adaptive multi-turn attacks or instrument retrieval/tool actions. It cannot establish document authorization, cross-tenant isolation, tool argument integrity, approval enforcement, or whether an action actually executed.

Next: retrieval fixtures/provenance, indirect injection into documents/tool output, isolated agent tooling, permission checks, action traces, and downstream output sinks. Keep external side effects inside controlled fixtures.

Acceptance: unauthorized retrieval/actions are demonstrated through structured traces, rather than inferred from a model's statement that it performed them.

### P1/P2: Evidence security and team workflows

Reports deliberately retain complete application output. Reflected credentials or sensitive responses can appear in artifacts even though auth headers and exception messages are omitted. Local evidence directories are gitignored; there is no redaction policy, encryption layer, retention management, hosted access control, or signed evidence.

Next: configurable redaction/retention and restricted artifact storage, finding IDs, remediation guidance, justified expiring suppressions, and CI artifact examples. Add a hosted API/dashboard and team controls when shared use requires them. Hash validation is a consistency check, not tamper-proof attestation.

### P2: Legacy cleanup and documentation consolidation

The old chat/toxicity scanner remains optional under `plx-legacy`. Its dependency stack, provider/model options, Hugging Face dataset schemas, evaluator model reuse, and mixed error paths still need dedicated validation or replacement. The NER model used there recognizes entity categories rather than comprehensive PII/secrets.

The current README and source quickstart describe the new workflow. Previously committed generated HTML documentation is historical and should be regenerated/deployed through a separate documentation workflow. Dependency locking and automated dependency security checks remain future hardening work.

### Explicitly separate scope

Model supply-chain assessment, training-data poisoning, white-box robustness, multimodal evaluation, and non-LLM AI need distinct interfaces and suites. Do not mark these covered based on the presence of a chat endpoint.

## Recommended next milestone

Evaluate one real application with a versioned, human-reviewed injection/leakage pack and paired benign controls; add the wrapper and fixtures necessary to prove its actual trust boundaries. Then prioritize checkpoint/resume and richer verdict validation before expanding a dashboard or attack catalog.

## Reference basis

- [OWASP Top 10 for LLM Applications, 2025 edition](https://owasp.org/www-project-top-10-for-large-language-model-applications/assets/PDF/OWASP-Top-10-for-LLMs-v2025.pdf): threat coverage reference, not a certification checklist.
- [OWASP excessive agency guidance](https://owasp.github.io/www-project-top-10-for-large-language-model-applications/2_0_vulns/LLM06_ExcessiveAgency.html): application permissions and tool execution require application-level evidence.
- [NIST AI 600-1 Generative AI Profile](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence): broader risk management context; a scan does not establish organizational compliance.
- [Legacy NER model card](https://huggingface.co/dslim/bert-base-NER): entity classes and limitations.
