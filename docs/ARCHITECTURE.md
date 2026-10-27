# Architecture

KAVACH separates probabilistic detection, deterministic action authorization, and evaluation. The protected application and research simulator are distinct execution paths.

## Protected request path

1. `auth.py` resolves an opaque bearer token against an operator-configured identity map. Missing credentials yield public access; invalid credentials are rejected.
2. `tool_security.py` creates an immutable task scope from the principal and one application-defined workflow. Model text cannot increase scope.
3. `engine.py` inspects the user request with normalization/rules, a local classifier, and context analysis. In the runtime, `context_review.py` may review a complete, ML-only flag with zero rule findings using the real backend without tools. Only the final effective `ALLOW` proceeds; rule findings and incomplete coverage cannot be overridden.
4. `runtime.py` retrieves public demonstration documents from a cached TF-IDF index. Original document/chunk IDs are preserved.
5. `rag_provenance.py` inspects retrieved content through the same runtime inspection callback, including eligible bounded advisory reviews. The protected runtime quarantines content still flagged or uncertain and builds the context from surviving chunks only.
6. `generation.py` invokes a real Ollama model, operationally defaulting to `qwen2.5:3b`. Public RAG answers directly from the inspected facts with no tools. Sensitive workflows narrow scope and the native tool catalog to only their required account-read or export operation, with the selected account/destination. Retrieved text remains untrusted evidence.
7. Every proposed action goes through `ToolDispatcher`. A complete tool definition, strict arguments, role permission, task scope, account ownership, expiry, call budget, and destination/data constraints govern execution.
8. Authorized tools operate on local synthetic data. The export handler receives a server-derived record payload rather than arbitrary model-supplied data.
9. Tool results are checked before re-entering model context. Sensitive workflows require their actual operation to complete; model prose alone cannot establish success. The final answer is checked before delivery.
10. The API records a correlated workflow trace and reports audit status. Missing generation or inspection evidence is exposed as an unavailable/review outcome.

## Contracts

- `Principal`: server-owned identity, role, account set, destination set.
- `TaskScope`: principal-bound workflow, permitted tools/resources/destinations, expiry, and call limit.
- `ProtectedQuery`: query, bounded retrieval settings, selected application workflow. No caller-controlled security bypass.
- `ProposedToolCall`: untrusted model proposal, never an authorization.
- `ToolExecutionResult`: policy decision, whether execution occurred, checked result/error.
- `RAGInspectionResult`: surviving chunks, quarantine IDs, assembled context, concrete actions taken.

The protected response exposes a disclosure-filtered diagnostic preview in `assembled_prompt`, `context_redacted` to indicate a changed preview, and `context_sha256` for the exact internal input. Tests inspect the actual model input directly; the preview must not be treated as an unredacted copy. Citations record included sources; they do not independently prove the generated answer's correctness.

## Bounded advisory context review

`KAVACH_CONTEXT_REVIEW=1` is the default. A complete inspection selected by the semantic threshold and containing zero rule matches may receive one structured review. No more than four reviews occur across a protected request's user input, retrieved chunks, and tool results. The reviewer receives a separate JSON envelope containing source, untrusted candidate content, and application-owned task scope. It has no tools and returns exactly `{"verdict":"ALLOW"}` or `{"verdict":"REVIEW"}`. Tool proposals, malformed/oversized output, and inconclusive answers cannot become an allow. An unavailable backend remains a failure/hold.

An advisory `ALLOW` changes only the effective inspection decision. The original classifier evidence remains in the trace, and authenticated tool/resource/destination permissions remain unchanged. `KAVACH_CONTEXT_REVIEW=0` disables the stage and retains strict classifier handling. Diagnostic inspection endpoints report the engine's decision without this runtime-only review; an analyzer hold and a protected-runtime advisory allow therefore describe different policy stages.

The reviewer adds inference cost and another model decision exposed to prompt injection. It can both reduce and introduce errors. Test it against hard-benign examples and active attacks, including attempts to manipulate the requested verdict; do not infer a security guarantee from its structured response format.

## Other paths

`/security/analyze` and `/security/analyze-document` expose inspection results without running an assistant task. `/security/authorize-tool` evaluates a proposal without execution; `/tools/execute` uses the actual dispatcher. Legacy inspection routes remain diagnostic interfaces.

`/v2/simulate_attack` uses a programmed susceptibility model with experimental hardening and output-filter controls. The 72-configuration runner also defaults to this simulator. Its results are not mixed into protected-workflow evidence.

The B0–B6 runner compares detector rejection on labeled text. B2 is Jaccard token overlap, not neural embeddings. B6 exercises prompt/document inspection, excluding actual generation and runtime actions.

## Important limits

Prompt labels and boundary warnings are probabilistic model cues. Provenance metadata alone does not implement full information-flow tracking. Task scope and tool policies enforce the specific actions represented by this application; they do not prove factual accuracy or universal injection immunity. See [the security model](SECURITY_MODEL.md) and [limitations](LIMITATIONS.md).
