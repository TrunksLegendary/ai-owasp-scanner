"""Declarative single-pattern static rules, one entry per detectable weakness.

Rules here are line-oriented: each is a regex evaluated against a source line.
Cross-line reasoning (model output reaching a dangerous sink) lives in
`engine.py`, which needs file-wide context that a single regex cannot express.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..models import Severity, Confidence


@dataclass(frozen=True)
class Rule:
    id: str
    category_id: str
    title: str
    pattern: re.Pattern[str]
    severity: Severity
    confidence: Confidence
    remediation: str
    detail: str = ""
    # Only apply to files whose suffix is in this set (empty = all code files).
    extensions: frozenset[str] = frozenset()
    # If this pattern also matches the line, suppress the finding.
    suppress_if: re.Pattern[str] | None = None


def _r(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE | re.VERBOSE)


RULES: tuple[Rule, ...] = (

    # ======================================================================
    # LLM01 — Prompt Injection
    # ======================================================================
    Rule(
        id="LLM01-UNTRUSTED-IN-SYSTEM-PROMPT",
        category_id="LLM01",
        title="Interpolated value inside a system-role prompt",
        pattern=_r(r"""["']role["']\s*:\s*["']system["'].{0,120}?\{[a-z_]\w*\}"""),
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        detail=(
            "A variable is interpolated directly into the system message. If that value "
            "is reachable by a user, they can rewrite the model's core instructions."
        ),
        remediation=(
            "Keep the system prompt static. Pass variable content as a separate user or "
            "tool message with explicit delimiters marking it as untrusted data."
        ),
    ),
    Rule(
        id="LLM01-FSTRING-PROMPT",
        category_id="LLM01",
        title="Prompt assembled by string interpolation",
        pattern=_r(r"""
            \b\w*prompt\w*\s*=\s*(?:f["']|["'][^"']*["']\s*(?:\+|%|\.format\s*\())
          | \b\w*prompt\w*\s*\+=\s*
          | \bPromptTemplate\s*\.\s*from_template\s*\(\s*f["']
        """),
        severity=Severity.MEDIUM,
        confidence=Confidence.LOW,
        detail=(
            "The prompt is built by concatenating or interpolating values. This is normal "
            "practice, but it is the point where untrusted text enters the model's "
            "instruction channel — confirm the interpolated values are delimited and "
            "treated as data."
        ),
        remediation=(
            "Wrap interpolated content in explicit delimiters and instruct the model to "
            "treat everything inside them as untrusted data, never as instructions."
        ),
    ),
    Rule(
        id="LLM01-NO-DELIMITER-EXTERNAL",
        category_id="LLM01",
        title="Retrieved external content concatenated into a prompt",
        pattern=_r(r"""
            \b\w*(?:context|docs?|documents|chunks?|retrieved|scraped|page_content|web|article)\w*
            \s*(?:\}|\))?\s*(?:\+|\})
            .{0,40}\b\w*prompt\w*
          | \b\w*prompt\w*\s*=\s*f?["'].{0,80}\{\s*\w*(?:context|docs?|retrieved|page_content)\w*\s*\}
        """),
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        detail=(
            "Content fetched from an external source (web page, document, RAG hit) is "
            "placed into the prompt. This is the indirect prompt injection path described "
            "in LLM01: hidden instructions inside that content become model instructions."
        ),
        remediation=(
            "Segregate and clearly denote untrusted external content, and instruct the "
            "model to never follow instructions found inside it."
        ),
    ),

    # ======================================================================
    # LLM02 — Sensitive Information Disclosure
    # ======================================================================
    Rule(
        id="LLM02-HARDCODED-PROVIDER-KEY",
        category_id="LLM02",
        title="Hard-coded AI provider API key",
        pattern=_r(r"""
            \bsk-(?:proj-|ant-|or-)?[A-Za-z0-9_\-]{20,}
          | \bAIza[0-9A-Za-z_\-]{35}
          | \bAKIA[0-9A-Z]{16}
          | \bghp_[A-Za-z0-9]{36}
          | \bhf_[A-Za-z0-9]{34,}
          | \bxox[baprs]-[A-Za-z0-9\-]{10,}
        """),
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        detail="A live-format credential appears literally in the source.",
        remediation=(
            "Revoke and rotate the key immediately, then load credentials from environment "
            "variables or a secret manager. Scrub it from git history."
        ),
        suppress_if=_r(r"""(?:example|placeholder|dummy|fake|test|xxxx|your[_-]?key|\.\.\.)"""),
    ),
    Rule(
        id="LLM02-ASSIGNED-SECRET",
        category_id="LLM02",
        title="Credential assigned as a string literal",
        pattern=_r(r"""
            \b[\w.]*(?:api[_-]?key|apikey|secret|token|password|passwd|access[_-]?key|
               private[_-]?key|auth[_-]?token|bearer)[\w.]*
            \s*[:=]\s*["'][^"'\s]{12,}["']
        """),
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        detail="A secret-looking name is assigned a literal string value.",
        remediation="Move the value into an environment variable or secret manager.",
        # Suppressors must be specific: a bare word like "secret" would match
        # inside the secret value itself and silently hide real findings.
        suppress_if=_r(r"""
            os\s*\.\s*(?:environ|getenv)
          | process\s*\.\s*env
          | \bgetenv\s*\(
          | \bSecret(?:Manager|Client|String|Ref)\b | \bget_secret\b | \bsecretsmanager\b
          | \bvault\s*\. | \bhvac\b
          | \$\{ | <[^>]{1,40}>
          | \b(?:example|placeholder|dummy|fake|sample|changeme|redacted|xxxxx)\b
          | \byour[_-](?:key|token|secret|password|api)
          | \.\.\.
        """),
    ),
    Rule(
        id="LLM02-LOGS-MODEL-IO",
        category_id="LLM02",
        title="Prompt or model response written to logs",
        pattern=_r(r"""
            \b(?:logger|log|logging|console)\s*\.\s*(?:debug|info|warn|warning|error|log)\s*\(
            [^)]{0,120}\b\w*(?:prompt|completion|response|message|answer|user_input|query)\w*\b
          | \bprint\s*\(\s*[^)]{0,80}\b\w*(?:prompt|completion)\w*\b
        """),
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        detail=(
            "Full prompts or completions are logged. Those payloads routinely contain user "
            "PII and, in RAG systems, retrieved private documents — which then land in log "
            "aggregators with a wider audience than the application itself."
        ),
        remediation=(
            "Redact or hash prompt and completion bodies before logging, or log only "
            "metadata (token counts, latency, model, request id)."
        ),
        # Logging metadata about a response is the recommended practice, not a finding.
        suppress_if=_r(r"""
            \.\s*usage\b | \.\s*model\b | \btoken(?:s|_count|_usage)?\b
          | \blatency\b | \belapsed\b | \bduration\b | \brequest_id\b
          | \bstatus(?:_code)?\b | \bfinish_reason\b | \blen\s*\(
          | \bredact | \bmask | \bhash
        """),
    ),

    # ======================================================================
    # LLM03 — Supply Chain
    # ======================================================================
    Rule(
        id="LLM03-TRUST-REMOTE-CODE",
        category_id="LLM03",
        title="trust_remote_code=True on a model load",
        pattern=_r(r"""\btrust_remote_code\s*=\s*True\b"""),
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        detail=(
            "This executes arbitrary Python shipped alongside the model repository at load "
            "time. A compromised or typosquatted model repo becomes remote code execution "
            "in your process."
        ),
        remediation=(
            "Set trust_remote_code=False. If the architecture genuinely requires custom "
            "code, vendor and review that code yourself and pin the exact revision."
        ),
    ),
    Rule(
        id="LLM03-UNPINNED-MODEL",
        category_id="LLM03",
        title="Model loaded without a pinned revision",
        pattern=_r(r"""\.\s*from_pretrained\s*\(\s*["'][^"']+["']"""),
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        detail=(
            "The model is fetched by name only, so whatever the hub serves today is what "
            "loads. An upstream repo can be re-uploaded with modified weights."
        ),
        remediation=(
            "Pin the artifact: from_pretrained(name, revision='<commit-sha>'), and record "
            "the model in your AI-BOM alongside its hash."
        ),
        suppress_if=_r(r"""\brevision\s*=|\bcommit_hash\s*=|\blocal_files_only\s*=\s*True"""),
    ),
    Rule(
        id="LLM03-TORCH-LOAD-UNSAFE",
        category_id="LLM03",
        title="torch.load without weights_only=True",
        pattern=_r(r"""\btorch\s*\.\s*load\s*\("""),
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        detail=(
            "torch.load unpickles by default, so loading a checkpoint from an untrusted "
            "source executes arbitrary code."
        ),
        remediation=(
            "Pass weights_only=True, or prefer the safetensors format, and verify the "
            "checkpoint hash against a known-good value before loading."
        ),
        suppress_if=_r(r"""\bweights_only\s*=\s*True"""),
    ),
    Rule(
        id="LLM03-UNPINNED-DEPENDENCY",
        category_id="LLM03",
        title="Unpinned dependency in requirements file",
        pattern=_r(r"""^\s*(?!\#)[A-Za-z][A-Za-z0-9._\-]{1,60}\s*(?:\[[^\]]+\])?\s*$"""),
        severity=Severity.LOW,
        confidence=Confidence.MEDIUM,
        detail="Dependency has no version constraint, so builds are not reproducible.",
        remediation="Pin with == and maintain a lock file with hashes.",
        extensions=frozenset({".txt"}),
    ),

    # ======================================================================
    # LLM04 — Data and Model Poisoning
    # ======================================================================
    Rule(
        id="LLM04-REMOTE-ARTIFACT-DOWNLOAD",
        category_id="LLM04",
        title="Model or dataset downloaded from a raw URL",
        pattern=_r(r"""
            \b(?:urlretrieve|wget|curl\s+-|hf_hub_download|snapshot_download|gdown)\b
          | \brequests\s*\.\s*get\s*\(\s*["']https?://[^"']+\.(?:bin|pt|pth|ckpt|safetensors|pkl|h5|onnx|gguf)["']
        """),
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        detail=(
            "A model or dataset artifact is pulled at runtime. Without an integrity check "
            "there is nothing distinguishing the intended artifact from a swapped one."
        ),
        remediation=(
            "Verify a known SHA-256 of the artifact after download and fail closed on "
            "mismatch. Record origin and hash in your AI-BOM."
        ),
    ),
    Rule(
        id="LLM04-UNSAFE-ARTIFACT-DESERIALIZE",
        category_id="LLM04",
        title="Model artifact loaded through pickle",
        pattern=_r(r"""
            \b(?:pickle|cPickle|dill|joblib)\s*\.\s*loads?\s*\(
          | \bnumpy\s*\.\s*load\s*\([^)]*allow_pickle\s*=\s*True
        """),
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        detail=(
            "Pickle deserialization executes arbitrary code. A poisoned model or "
            "preprocessing artifact compromises the host on load."
        ),
        remediation=(
            "Use safetensors or another non-executable serialization format, and only "
            "deserialize artifacts you produced and hash-verified."
        ),
    ),
    Rule(
        id="LLM04-TRAIN-ON-USER-DATA",
        category_id="LLM04",
        title="Fine-tuning or indexing directly on user-supplied data",
        pattern=_r(r"""
            \b(?:fine_?tune|finetune|train|fit|create_finetune|fine_tuning\s*\.\s*jobs\s*\.\s*create)\s*\(
            [^)]{0,120}\b(?:user|request|upload|submitted|feedback|customer)\w*
        """),
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        detail=(
            "User-controlled content feeds a training or indexing path with no visible "
            "validation step, which is the data poisoning vector described in LLM04."
        ),
        remediation=(
            "Validate, classify and review user-contributed data before it enters a "
            "training set or index. Track its provenance and keep it in a quarantined tier."
        ),
    ),

    # ======================================================================
    # LLM05 — Improper Output Handling
    #   (the primary taint checks live in engine.py; these catch config-level
    #    weaknesses that make output handling unsafe by construction)
    # ======================================================================
    Rule(
        id="LLM05-AUTOESCAPE-DISABLED",
        category_id="LLM05",
        title="Template auto-escaping disabled",
        pattern=_r(r"""\bautoescape\s*=\s*False\b|\bEnvironment\s*\((?![^)]*autoescape)"""),
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        detail=(
            "With auto-escaping off, any model output rendered through this template is "
            "injected into the page as raw markup."
        ),
        remediation="Enable autoescape (select_autoescape) and escape explicitly where needed.",
    ),
    Rule(
        id="LLM05-RAW-MARKDOWN-RENDER",
        category_id="LLM05",
        title="Model markdown rendered without sanitization",
        pattern=_r(r"""
            \bmarked\s*(?:\.\s*parse\s*)?\(
          | \bmarkdown\s*\.\s*markdown\s*\(
          | \breact-markdown\b.{0,60}\brehype-raw\b
          | \ballowDangerousHtml\s*:\s*true
        """),
        severity=Severity.MEDIUM,
        confidence=Confidence.LOW,
        detail=(
            "Model output is commonly rendered as markdown. Most markdown renderers pass "
            "embedded HTML through, so a model persuaded to emit a script tag or a "
            "javascript: link gets it executed in the user's session."
        ),
        remediation=(
            "Run rendered markdown through a sanitizer (DOMPurify, bleach) with a strict "
            "allow-list, and disable raw HTML pass-through in the renderer."
        ),
    ),

    # ======================================================================
    # LLM06 — Excessive Agency
    # ======================================================================
    Rule(
        id="LLM06-DANGEROUS-TOOL-ENABLED",
        category_id="LLM06",
        title="Agent granted an open-ended shell or code-execution tool",
        pattern=_r(r"""
            \bShellTool\s*\( | \bBashProcess\s*\( | \bTerminal\s*\(
          | \bPythonREPLTool\s*\( | \bPythonAstREPLTool\s*\( | \bPythonREPL\s*\(
          | \bcreate_(?:sql|pandas|csv|spark)_agent\s*\(
          | \bComputerTool\s*\( | \bcode_interpreter\b
        """),
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        detail=(
            "This is 'excessive functionality' in LLM06: an open-ended tool means any "
            "successful prompt injection escalates straight to arbitrary command or code "
            "execution."
        ),
        remediation=(
            "Replace the open-ended tool with narrowly-scoped functions that do exactly "
            "the operations the agent needs, and enforce authorization downstream."
        ),
    ),
    Rule(
        id="LLM06-DANGEROUS-FLAG",
        category_id="LLM06",
        title="Framework safety guard explicitly disabled",
        pattern=_r(r"""
            \ballow_dangerous_(?:requests|code|deserialization|tools)\s*=\s*True
          | \bdangerously_?allow\w*\s*[:=]\s*(?:True|true)
          | \bbypass_safety\w*\s*[:=]\s*(?:True|true)
          | \bpermission_mode\s*[:=]\s*["']bypassPermissions["']
        """),
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        detail="A guard the framework put there deliberately has been switched off.",
        remediation=(
            "Remove the override. If the capability is genuinely required, gate it behind "
            "an explicit allow-list and human approval."
        ),
    ),
    Rule(
        id="LLM06-NO-HUMAN-APPROVAL",
        category_id="LLM06",
        title="Autonomous agent loop with no approval hook",
        pattern=_r(r"""
            \bAgentExecutor\s*\( | \binitialize_agent\s*\( | \bcreate_react_agent\s*\(
          | \bmax_iterations\s*=\s*\d{2,}
          | \bautonomous\s*=\s*True | \bauto_?approve\w*\s*[:=]\s*(?:True|true)
        """),
        severity=Severity.HIGH,
        confidence=Confidence.LOW,
        detail=(
            "An agent executor runs tool calls in a loop. LLM06 calls for human approval "
            "on high-impact actions; confirm one exists on this path."
        ),
        remediation=(
            "Add a human-in-the-loop confirmation before any state-changing or "
            "irreversible tool call, and cap the iteration budget."
        ),
    ),

    # ======================================================================
    # LLM07 — System Prompt Leakage
    # ======================================================================
    Rule(
        id="LLM07-SECRET-IN-SYSTEM-PROMPT",
        category_id="LLM07",
        title="Credential or connection string inside a system prompt",
        pattern=_r(r"""
            (?:system[_-]?(?:prompt|message|instruction)|["']role["']\s*:\s*["']system["'])
            .{0,200}?
            \b(?:api[_-]?key|password|secret|token|bearer|connection[_-]?string|
               postgres://|mysql://|mongodb(?:\+srv)?://)\b
        """),
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        detail=(
            "The system prompt carries a secret. Since prompts leak — and LLM07 exists "
            "precisely because they do — treat this credential as already disclosed."
        ),
        remediation=(
            "Remove the secret from the prompt and rotate it. The application, not the "
            "model, should hold credentials and perform privileged calls in code."
        ),
    ),
    Rule(
        id="LLM07-AUTHZ-IN-SYSTEM-PROMPT",
        category_id="LLM07",
        title="Access-control rule expressed in the system prompt",
        pattern=_r(r"""
            (?:system[_-]?(?:prompt|message|instruction)|["']role["']\s*:\s*["']system["'])
            .{0,300}?
            (?:\bonly\s+(?:if|allow|admin|permitted)|\bif\s+the\s+user\s+is\s+(?:an?\s+)?(?:admin|manager|premium)
              |\bdo\s+not\s+(?:reveal|disclose|tell)|\bnever\s+(?:reveal|disclose|show)
              |\buser[_-]?role\b|\bis[_-]?admin\b|\bpermission\b)
        """),
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        detail=(
            "Authorization logic lives in the prompt. LLM07's core point is that this is "
            "not a security boundary: once the prompt leaks, the rules are known, and the "
            "model can be argued out of them regardless."
        ),
        remediation=(
            "Enforce the check in deterministic application code outside the LLM. Keep the "
            "prompt for tone and task framing only."
        ),
    ),
    Rule(
        id="LLM07-PROMPT-RETURNED-TO-CLIENT",
        category_id="LLM07",
        title="System prompt included in an API response",
        pattern=_r(r"""
            (?:jsonify|JSONResponse|res\s*\.\s*json|return\s*\{|\breturn\s+dict\s*\()
            [^)]{0,160}\bsystem[_-]?(?:prompt|message|instruction)\b
        """),
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        detail="The system prompt is serialized back to the client, disclosing it directly.",
        remediation="Strip prompt internals from any response leaving the trust boundary.",
    ),

    # ======================================================================
    # LLM08 — Vector and Embedding Weaknesses
    # ======================================================================
    Rule(
        id="LLM08-UNFILTERED-VECTOR-SEARCH",
        category_id="LLM08",
        title="Vector similarity search with no tenant or permission filter",
        pattern=_r(r"""
            \b(?:similarity_search|similarity_search_with_score|max_marginal_relevance_search
               |as_retriever|\.\s*query|\.\s*search)\s*\(
        """),
        severity=Severity.HIGH,
        confidence=Confidence.LOW,
        detail=(
            "A vector store is queried. LLM08 flags cross-tenant leakage when a shared "
            "index is searched without a permission-aware filter — confirm this query is "
            "scoped to the requesting user."
        ),
        remediation=(
            "Apply a metadata filter for tenant/user on every retrieval, or partition the "
            "index per tenant. Log retrievals immutably."
        ),
        suppress_if=_r(r"""\bfilter\s*=|\bwhere\s*=|\bnamespace\s*=|\btenant|\buser_id|\bmetadata_filter"""),
    ),
    Rule(
        id="LLM08-VECTORDB-NO-AUTH",
        category_id="LLM08",
        title="Vector database client configured without authentication",
        pattern=_r(r"""
            \b(?:QdrantClient|Weaviate\w*|Milvus\w*|ChromaClient|HttpClient|Pinecone)\s*\(
            [^)]{0,160}(?:host|url|uri)\s*=\s*["']https?://[^"']+["']
        """),
        severity=Severity.HIGH,
        confidence=Confidence.LOW,
        detail="A remote vector store endpoint is configured with no visible credential.",
        remediation="Require authentication on the vector store and restrict network access.",
        suppress_if=_r(r"""\bapi_?key\s*=|\bauth|\btoken\s*=|\bcredentials\s*="""),
    ),

    # ======================================================================
    # LLM09 — Misinformation
    # ======================================================================
    Rule(
        id="LLM09-UNVERIFIED-PACKAGE-INSTALL",
        category_id="LLM09",
        title="Package installed from model-generated name",
        pattern=_r(r"""
            \b(?:pip\s+install|npm\s+install|subprocess[^)]*install)\b[^)\n]{0,80}
            \{\w+\}|\bsubprocess[^)]{0,80}\b(?:install)\b[^)]{0,60}\b\w*(?:response|output|completion|suggested)\w*
        """),
        severity=Severity.CRITICAL,
        confidence=Confidence.MEDIUM,
        detail=(
            "This is the package hallucination path in LLM09: models invent plausible "
            "package names, and an attacker who registers that name owns your install."
        ),
        remediation=(
            "Never install a package name produced by a model. Resolve suggestions against "
            "an allow-list or a vetted internal registry first."
        ),
    ),
    Rule(
        id="LLM09-HIGH-STAKES-NO-REVIEW",
        category_id="LLM09",
        title="Model output used in a high-stakes domain",
        pattern=_r(r"""
            \b\w*(?:diagnos|medical|patient|prescription|dosage|legal_advice|
               contract_term|invest|trade_order|credit_decision|loan_approval)\w*\b
        """),
        severity=Severity.MEDIUM,
        confidence=Confidence.LOW,
        detail=(
            "Identifiers suggest the model touches a medical, legal or financial decision. "
            "LLM09 calls for human oversight and explicit limitation notices on these paths."
        ),
        remediation=(
            "Add human review before the output is acted on, ground responses in verified "
            "sources, and surface model limitations in the interface."
        ),
    ),

    # ======================================================================
    # LLM10 — Unbounded Consumption
    # ======================================================================
    Rule(
        id="LLM10-NO-INPUT-LENGTH-LIMIT",
        category_id="LLM10",
        title="User input reaches the model with no length validation",
        pattern=_r(r"""
            \b\w*prompt\w*\s*=\s*(?:request|req)\s*\.\s*(?:json|form|args|body|data|query)\b
          | \bmessages\s*=\s*\[[^\]]{0,60}(?:request|req)\s*\.\s*(?:json|form|body)
        """),
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        detail=(
            "Request data flows into the prompt without a size check. LLM10 covers both the "
            "denial-of-service and denial-of-wallet consequences of unbounded input."
        ),
        remediation="Validate and cap input length before the call, and reject oversized requests.",
    ),
    Rule(
        id="LLM10-UNBOUNDED-AGENT-LOOP",
        category_id="LLM10",
        title="Agent loop without an iteration or cost ceiling",
        pattern=_r(r"""
            \bwhile\s+True\s*:
          | \bmax_iterations\s*=\s*None
          | \bfor\s+_\s+in\s+itertools\s*\.\s*count\s*\(
        """),
        severity=Severity.MEDIUM,
        confidence=Confidence.LOW,
        detail=(
            "An unbounded loop around model calls can run up unlimited spend if the exit "
            "condition depends on model output."
        ),
        remediation="Cap iterations and total token spend per request; enforce a wall-clock timeout.",
    ),
)


RULES_BY_CATEGORY: dict[str, list[Rule]] = {}
for _rule in RULES:
    RULES_BY_CATEGORY.setdefault(_rule.category_id, []).append(_rule)
