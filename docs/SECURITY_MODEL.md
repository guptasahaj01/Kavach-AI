# Security model and boundaries

## Trusted state

The application owns credential resolution, principal resources, workflow definitions, tool registry, policy implementation, generation endpoint configuration, and containment policy. The operator must protect these configurations and the server process. A caller or model proposal cannot select a privileged identity through request JSON.

The application trusts a resolved user to request an operation only within that user's permissions. User intent and permission are separate checks. A relevant request for a different customer's record remains unauthorized.

## Untrusted inputs

User prompts, retrieved document bodies, and tool outputs may contain instructions or false information. Model tool proposals and generated answers remain untrusted. A document's claim to be an RBI circular, system message, or administrator does not grant permission. Source labels do not establish factual truth.

## Enforced properties

- The protected workflow accepts only effective `ALLOW` input inspection outcomes. By default, a bounded advisory stage may resolve a complete ML-only flag with zero rule findings. Concrete rule findings and incomplete coverage cannot be overridden; outcomes still requiring `FLAG`/`REVIEW` hold execution and `BLOCK` denies it.
- The generation context contains only inspected surviving chunks. Quarantined material cannot be reintroduced through the original retrieval list.
- Tool proposals pass through one dispatcher before any synthetic handler runs.
- The protected public-RAG model receives no tools and answers from retrieved facts. Sensitive protected workflows receive only their required tool, bound to the selected resource/destination, and cannot claim completion without that operation executing.
- Tool access requires a complete registered handler/schema and checks against authenticated role, task, and explicit resources.
- Account reads require an assigned account. Export destinations must be explicitly authorized and gateway-approved.
- Export data comes from the server-authorized synthetic record; an arbitrary model payload does not become trusted because its destination is approved.
- Incomplete tools such as money transfer and external email remain unavailable.
- Tool results and final answers pass checks before they are returned to the model or user.

These are scoped application properties, tested with controlled proposals and synthetic side effects. They are not a proof about every possible output of every model.

## Probabilistic defenses and uncertainty

Rules, ML scores, contextual interpretation, and prompt boundaries reduce risk but can miss attacks. Educational discussion is assessed using quoted versus active material; research language does not grant a broad exemption. Detector evidence is preserved separately from the enforcement decision.

Unavailable/erroring classifiers and incomplete inspection do not establish safety. The protected workflow reports review or backend failure, rather than silently allowing an uninspected operation. Resource and turn budgets bound work.

`KAVACH_CONTEXT_REVIEW=1` enables at most four runtime reviews per request through the configured real model backend, with no tools. Each eligible review returns a strict `ALLOW`/`REVIEW` object. Invalid output, attempted tool calls, uncertainty, and errors cannot grant an allow. Setting `0` retains the strict classifier gate. The reviewer cannot mint a principal or expand an account, destination, tool, or task scope.

The reviewer's verdict is fallible evidence. An attacker can try to manipulate the reviewer through candidate content; a mistaken allow may admit answer manipulation or disclosure that later checks also miss. Conversely, a mistaken review can withhold legitimate assistance. Structured messages and tool-free execution reduce authority but do not establish correct semantic classification. Compare both review modes on independent attacks and hard-benign scenarios, including legitimate task success and inference cost.

## Disclosure and logging

Canaries and known secret/PII patterns are defense signals, not a complete secret inventory. Keep real credentials out of model context. All banking data and tools shipped here are synthetic. Audit traces describe decisions and execution outcomes; failures to persist are reported separately from a successful zero count.

A general multi-tenant retrieval ACL system, full derived-data taint tracking, comprehensive secret detection, and guaranteed factual correctness are outside the current implementation. Restrict shared deployments to trusted operators and use HTTPS for credentials.
