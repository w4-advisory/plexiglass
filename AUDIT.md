# Plexiglass functionality audit

Updated: 4 November 2026. Assessed implementation: version 0.1.0, commit `f9cea5c` (PR #17, reported merged). Original baseline: `54bf161`.

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
| CI | Offline fixture/unit tests and wheel/install smoke workflow for Python 3.10, 3.12, and 3.14. | `.github/workflows/tests.yml`; PR #17 jobs passed on Python 3.10, 3.12, and 3.14 during the implementation session. |

## Validation performed

- All 15 core tests pass locally. They exercise defended/vulnerable local HTTP applications, complete evidence, malformed output, authentication handling, redirects, timeout handling, nested response extraction, request settings, output escaping, incompatible/incomplete baselines, altered verdicts, duplicate cases, count limits, mutation isolation, and CLI exit codes.
- Tests run against localhost fixtures without paid model calls or downloaded ML models.
- Source distribution and wheel are built with isolated setuptools/wheel tooling; installation and CLI/resources are checked outside the checkout.
- Local execution uses Python 3.15. The Python 3.10/3.12/3.14 matrix passed remotely in PR #17; those interpreters were not tested locally.
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

## Comparison with other evaluation tools

### Scope and method

This is a documentation-based capability comparison researched on 4 November 2026, checked against the local Plexiglass source. garak, Promptfoo, PyRIT, Giskard, and Inspect are executable testing tools. OWASP risk catalogs, NIST risk-management guidance, and MITRE threat knowledge bases serve different purposes and are assessed separately below.

No competing tool was installed or run. No common-target benchmark, detection-rate comparison, cost measurement, or security review of those tools was performed. Documented functionality is not proof of detection accuracy. Sources track evolving documentation rather than pinned releases; record exact versions/commits before integration or benchmarking. Product and open-source editions may differ.

### Tool-by-tool comparison

| Tool | Documented capabilities relevant to Plexiglass | How Plexiglass fares | Recommended response |
|---|---|---|---|
| **garak** | Modular generators, probes, detectors, prompt transformations (buffs), and orchestration; generators handle connection/backoff concerns. [Architecture](https://reference.garak.ai/en/stable/basic.html). JSONL scan reporting is documented separately. [Reports](https://reference.garak.ai/en/latest/reporting.html). | Plexiglass has HTTP/callable targets and explicit case assertions, but only three bundled smoke cases and two assertion types. It lacks comparable extension contracts, attack catalog, transformations, and detector selection. Full JSONL evidence is useful but not a unique differentiator. | Prioritize an optional garak results importer and finding-to-regression conversion. Preserve probe/detector identity and original outcomes; do not relabel a detector hit as a proven application exploit. |
| **Promptfoo** | Separates application targets, adversarial generators, strategies, and application purpose. [Configuration](https://www.promptfoo.dev/docs/red-team/configuration/). Documents static/dynamic/multi-turn strategies and an MCP provider. [Strategies](https://www.promptfoo.dev/docs/red-team/strategies/), [MCP](https://www.promptfoo.dev/docs/providers/mcp/). | It is the closest overlap with Plexiglass's intended application testing workflow and has much broader attack delivery and MCP interfaces. Plexiglass's deterministic baseline gate is a small subset, not an established competitive advantage. | Compare both on the same application and reviewed cases. Add compatible export/import only where roles, assertions, and session semantics can be preserved; clearly flag information loss. |
| **Microsoft PyRIT** | Separates targets, converters, conversation/attack execution, scoring, and persistence responsibilities; supports adaptive attack workflows. [Framework design](https://github.com/microsoft/PyRIT/blob/main/doc/code/framework.md), [Project](https://github.com/microsoft/PyRIT). | Plexiglass sends preconstructed message lists in independent calls. It has no attacker feedback loop, branching conversations, converter stack, or campaign memory. A message list is not equivalent to an adaptive attack. | Use PyRIT as a possible discovery engine rather than initially rebuilding campaign orchestration. Turn reviewed discoveries into fixed Plexiglass replay cases when the target interface supports faithful replay. |
| **Giskard** | Open-source documentation includes scanning, checks, stateful/multi-turn scenarios, RAG evaluation, CI, and finding-to-regression workflows. [Library](https://docs.giskard.ai/oss/). Hub offers separate collaboration/access-control capabilities. [Offerings](https://docs.giskard.ai/). | Plexiglass lacks equivalent RAG/state inspection and workflow breadth. The evidence-to-regression idea already has competition, so product value needs validation. Hub features must not be assumed available in the open-source package. | Learn from the separation of business-quality checks and security findings. Add paired utility controls and investigate interoperability before building a hosted team product. |
| **Inspect AI** | Evaluation tasks combine datasets, solvers, and scorers; documentation covers agent tools, sandboxing, logs, and execution limits. [Documentation](https://inspect.aisi.org.uk/). | Plexiglass is a small application assertion runner, without a comparable agent/sandbox evaluation harness. Inspect is a broader evaluation platform, not simply a turnkey vulnerability scanner. | Consider it for instrumented agent research and comparison fixtures. Keep Plexiglass's application contracts and report format focused; defer a competing general-purpose harness. |

### Assessment and proposed positioning

Plexiglass is currently behind these tools in breadth of evaluation capabilities. Its demonstrated strengths are a small standard-library core, explicit deterministic assertions, complete local evidence, and a simple baseline gate. Those choices reduce setup complexity for narrow use cases; they do not establish better security detection, lower total cost, or unique functionality.

Proposed direction, subject to user validation: **an application security regression and evidence layer that turns reviewed discoveries into repeatable CI checks with traceable framework mappings**. Start with one real application's policies and trust boundaries. Keep external discovery engines optional and isolated so the core remains lightweight. Do not pursue feature parity with every scanner or claim framework compliance from mapped labels.

Build natively: case/result contracts, application adapters, evidence provenance, deterministic evaluators, replay, baseline semantics, and CI exports. Integrate selectively: broad attack discovery, adaptive campaigns, and specialized RAG/agent evaluation. Licensing, dependency isolation, data routing, and version compatibility must be reviewed before importing code or datasets. Result interchange is a proposal, not an existing integration.

## Security framework coverage and gaps

### Coverage terminology

No framework registry or framework-aware coverage report currently exists in code. The following tables are an analyst mapping, not implemented product metadata or certification. Framework editions below are explicit reference baselines; they are not a claim that these will always be the latest editions.

For the future report, distinguish capability from execution: `partial`/`unsupported`/`manual assessment required` describe capability; `not run`/`pass`/`fail`/`inconclusive` describe an actual case execution. A tool supporting a test does not mean the target passed it. A framework tag alone does not establish coverage, and no framework-wide percentage should be inferred from this audit.

### OWASP LLM Top 10: 2025 reference edition

Category names follow the [official OWASP list](https://genai.owasp.org/llm-top-10/). Findings below describe Plexiglass, not OWASP's endorsement of the mapping.

| Category | Current capability | Evidence needed to expand coverage |
|---|---|---|
| LLM01 Prompt Injection | **Partial:** controlled direct instruction override assertion. No indirect/adaptive suite. | Application-specific policy cases, retrieved/tool-content injection, benign controls, and boundary evidence. |
| LLM02 Sensitive Information Disclosure | **Partial:** case-insensitive literal synthetic canary detection. | Partial/transformed leakage evaluators, realistic protected fixtures, and authorization context. |
| LLM03 Supply Chain | **Unsupported; artifact/manual assessment required.** | Dependency/model provenance and artifact inspection. |
| LLM04 Data and Model Poisoning | **Unsupported.** | Controlled data/pipeline mutation and before/after behavior evidence. |
| LLM05 Improper Output Handling | **Unsupported.** HTML report escaping protects Plexiglass's output, not the application's sinks. | Instrumented downstream sinks and safe execution evidence. |
| LLM06 Excessive Agency | **Unsupported.** | Tool permissions, approval checks, and actual action traces. |
| LLM07 System Prompt Leakage | **Partial:** a canary seeded in a system-role message can reveal one protected value. | Dedicated extraction cases and distinction between harmless instruction disclosure and sensitive leakage. |
| LLM08 Vector and Embedding Weaknesses | **Unsupported.** | Retrieval fixtures, index/document authorization, and provenance. |
| LLM09 Misinformation | **Unsupported.** A benign arithmetic check is not a factuality suite. | Grounded task datasets and validated factuality evaluators. |
| LLM10 Unbounded Consumption | **Unsupported as a target vulnerability test.** Runner request limits/timeouts are operational controls. | Bounded amplification experiments and target usage/limit telemetry. |

### MCP security

Plexiglass has no native MCP client/server adapter, protocol negotiation, tool discovery, authorization test suite, or MCP execution trace. The generic HTTP adapter cannot establish MCP protocol/security coverage.

All categories in the [OWASP MCP Top 10: 2025 reference list](https://owasp.org/projects/mcp-top-10?tab=top10) are currently **unsupported as MCP-specific assessments**:

| Category | Proposed assessment capability |
|---|---|
| Token Mismanagement & Secret Exposure | Synthetic credential lifecycle and exposure checks. |
| Privilege Escalation via Scope Creep | Identity/scope matrix with denied-action fixtures. |
| Tool Poisoning | Malicious tool descriptions/output, changed definitions, and selection traces. |
| Software Supply Chain Attacks & Dependency Tampering | Artifact inventory/provenance; separate from runtime prompt tests. |
| Command Injection & Execution | Isolated tool sinks and observed execution outcomes. |
| Prompt Injection via Contextual Payloads | Injected resources/tool results and instruction-boundary checks. |
| Insufficient Authentication & Authorization | Missing/wrong identity, scope, audience, and tenant checks. |
| Lack of Audit and Telemetry | Correlated invocation/outcome records and redaction assertions. |
| Shadow MCP Servers | Authorized deployment inventory and policy comparison; not inferred from a chat endpoint. |
| Context Injection & Over-Sharing | Cross-session/user isolation and context contamination fixtures. |

Use the [official MCP security guidance](https://modelcontextprotocol.io/specification/latest/basic/security_best_practices) alongside the risk catalog; it addresses protocol-specific issues such as token passthrough and confused-deputy behavior. Pin the applicable protocol revision and supported transports before implementation. Distinguish direct server authorization checks from end-to-end agent tests that consume tool descriptions/results; they exercise different boundaries.

### NIST AI RMF / Generative AI Profile

NIST's AI RMF covers Govern, Map, Measure, and Manage; the GenAI Profile is a companion resource. [AI RMF Playbook](https://www.nist.gov/itl/ai-risk-management-framework/nist-ai-rmf-playbook), [NIST AI 600-1](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence).

Plexiglass can supply narrow technical evidence that may inform **Measure**, but there is no implemented NIST outcome/action mapping. Proposed evidence support: system context and boundaries for **Map**; reviewed tests and uncertainty for **Measure**; mitigation verification and tracked residual risk for **Manage**; accountable ownership, approvals, and assessment history for **Govern**. These are design proposals, not findings of conformance. Organizational policies, stakeholder decisions, monitoring, and risk acceptance require evidence outside a scanner. Do not add a blanket “NIST compliant” result.

### MITRE ATLAS and ATT&CK

[MITRE ATLAS](https://github.com/mitre-atlas/atlas-data) supplies AI adversary tactics, techniques, and case-study data. It is the primary MITRE reference for proposed AI attack mappings. Plexiglass has no implemented ATLAS registry, verified technique IDs, or technique-organized case packs. Existing override/leakage cases are candidates for reviewed mappings, not evidence of broad ATLAS coverage.

Import a pinned ATLAS release/commit; validate IDs and technique meaning; store the source, mapping rationale, case preconditions, observable outcome, and reviewer. Use ATT&CK only where a scenario also demonstrates a relevant conventional infrastructure behavior. Do not automatically equate a text response with exfiltration, execution, or a completed attack chain.

### Mapping implementation requirements

Extend the versioned case/result schema with framework name, edition/release, verified category/technique/outcome ID, source URL, mapping rationale, required target capabilities, evidence references, and review status. Plan backward compatibility with v1 packs/reports; the current strict `TestCase` constructor cannot accept arbitrary mapping fields. Separate organizational/manual controls from executable assertions.

A future coverage report must list supported checks, unmapped cases, unexecuted checks, inconclusive outcomes, manual requirements, and unsupported areas. Require trace evidence before claiming tool/RAG authorization coverage. Mappings should be reviewed and tested against a pinned registry; label proposed mappings until validated.

## Prioritized delivery plan

The order below reflects comparison findings and the existing audit, rather than an attempt to implement every framework simultaneously. Each step should refresh this audit with measured evidence.

| Order | Deliverable | Acceptance criteria |
|---|---|---|
| **1 — Real application validation (P1)** | A model-backed application example with a fixed server-owned policy, synthetic protected data, session isolation, and an application-specific wrapper. A reviewed pack of at least 30 cases spanning direct override, leakage variants, and benign controls. | Record model/settings and case-pack provenance; demonstrate a real failure, human adjudication, a mitigation, and retained benign utility. Keep deterministic fixtures in offline CI and live evaluations opt-in. Distinguish model behavior from application boundary failures. |
| **2 — Framework-aware schemas/reports (P1)** | Backward-compatible mapping schema, pinned OWASP LLM/MCP reference editions and ATLAS data, proposed NIST evidence relationships, and explicit capability/execution status. | Validate IDs/editions; preserve v1 imports; reject invalid mappings; show unsupported/manual/not-run/inconclusive areas. No invented compliance score or certification claim. |
| **3 — Comparative pilot and interoperability (P1)** | Run Plexiglass, garak, and Promptfoo against the same authorized application; examine PyRIT for adaptive discovery. Prototype garak result import and reviewed finding-to-regression conversion. | Pin tool versions, test corpus, target settings, comparable objectives, and request/token budgets. Report detection disagreements, human-confirmed failures, false positives, benign success, setup effort, latency, and cost separately. Preserve source verdicts/provenance; disclose semantic losses and incomparable suites. Do not compare raw pass rates across different case sets. |
| **4 — Verdict and execution quality (P1)** | Evaluator contracts, transformed/partial-leak fixtures, optional calibrated judge, complete non-secret replay configuration, checkpoint/resume, rate/retry controls, and usage budgets. | Publish labeled evaluator validation, disagreement/error rates, and repeated-trial uncertainty; recover interrupted runs without losing completed evidence; enforce limits and redact secrets. Give deterministic scorers preference when they can establish the outcome. |
| **5 — MCP/RAG/agent boundaries (P1)** | A version-pinned MCP adapter with scope/tenant, tool-poisoning, and context-isolation fixtures; RAG provenance and sandboxed tool-action traces. | Demonstrate denied vs unauthorized access/action using server/retrieval/tool evidence. Test both direct server behavior and end-to-end agent behavior. Keep authorization, sandboxing, and data retention explicit. |
| **6 — Product hardening (P2)** | Restricted artifacts, redaction/retention, finding ownership/remediation/suppressions, dependency checks, legacy retirement/validation, and docs publishing. | Reproduce and triage findings without exposing secrets; enforce expiring exceptions; verify clean installation/docs. Add a dashboard/API only after a team workflow needs it. |

Immediate next implementation: step 1, with the minimum schema design needed to avoid breaking step 2. Do not block actual application validation on mapping every framework. Treat the comparative pilot as a decision gate: if existing tools meet the user's workflow more effectively, integrate them and narrow Plexiglass's native scope rather than rebuilding their catalogs.

## Reference basis

- [OWASP Top 10 for LLM Applications, 2025 edition](https://owasp.org/www-project-top-10-for-large-language-model-applications/assets/PDF/OWASP-Top-10-for-LLMs-v2025.pdf): threat coverage reference, not a certification checklist.
- [OWASP excessive agency guidance](https://owasp.github.io/www-project-top-10-for-large-language-model-applications/2_0_vulns/LLM06_ExcessiveAgency.html): application permissions and tool execution require application-level evidence.
- [NIST AI 600-1 Generative AI Profile](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence): broader risk management context; a scan does not establish organizational compliance.
- [Legacy NER model card](https://huggingface.co/dslim/bert-base-NER): entity classes and limitations.
