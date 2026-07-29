"""The OWASP Top 10 for LLM Applications v2.0 (2025) catalog.

Titles, descriptions and mitigations are adapted from the OWASP document
(`LLMAll_en-US_FINAL.pdf`). Each entry records the PDF page it came from so any
claim the scanner makes can be checked against the source.

The PDF is not redistributed in this repository. Download it from
https://genai.owasp.org, then regenerate the searchable text with:

    python tools/extract_reference.py path/to/LLMAll_en-US_FINAL.pdf

Nothing here needs that file at runtime — it is purely for verification.

OWASP Top 10 for LLM Applications v2.0 is published by the OWASP Foundation
under CC BY-SA 4.0. The content in this module is adapted from it and is
therefore also licensed CC BY-SA 4.0; see NOTICE. https://genai.owasp.org
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Category:
    id: str
    number: int
    title: str
    summary: str
    pdf_page: int
    key_mitigations: tuple[str, ...]

    @property
    def label(self) -> str:
        return f"{self.id}: {self.title}"


CATEGORIES: tuple[Category, ...] = (
    Category(
        id="LLM01",
        number=1,
        title="Prompt Injection",
        summary=(
            "User or external content alters the model's behaviour in unintended ways. "
            "Direct injection comes from the user's own prompt; indirect injection arrives "
            "through content the model ingests (web pages, files, RAG documents). Can lead "
            "to sensitive data disclosure, unauthorized use of connected functions, or "
            "arbitrary commands in downstream systems."
        ),
        pdf_page=7,
        key_mitigations=(
            "Constrain model behaviour with an explicit role, capability and limitation "
            "statement in the system prompt.",
            "Define and validate expected output formats with deterministic code.",
            "Implement input and output filtering against defined sensitive categories.",
            "Enforce least privilege: give the application its own API tokens and handle "
            "privileged functions in code, not via the model.",
            "Require human approval for high-risk actions.",
            "Segregate and clearly mark untrusted external content.",
            "Run adversarial testing, treating the model as an untrusted user.",
        ),
    ),
    Category(
        id="LLM02",
        number=2,
        title="Sensitive Information Disclosure",
        summary=(
            "The model or its surrounding application exposes PII, credentials, proprietary "
            "algorithms or business data — through outputs, logs, training data, or the "
            "system prompt itself."
        ),
        pdf_page=12,
        key_mitigations=(
            "Sanitize and scrub sensitive data from training data and from model inputs.",
            "Apply strict access controls and least privilege to external data sources.",
            "Use federated learning and differential privacy techniques where applicable.",
            "Educate users on safe LLM usage and offer opt-out of training data inclusion.",
            "Avoid placing secrets in system prompts; use secure configuration instead.",
        ),
    ),
    Category(
        id="LLM03",
        number=3,
        title="Supply Chain",
        summary=(
            "Third-party models, datasets, adapters (LoRA) and packages introduce risk. "
            "Includes vulnerable or outdated components, tampered pre-trained models pulled "
            "from public hubs, unclear licensing, and compromised fine-tuning artifacts."
        ),
        pdf_page=15,
        key_mitigations=(
            "Vet data sources and suppliers; review their terms and privacy policies.",
            "Maintain an up-to-date SBOM/AI-BOM of models, datasets and dependencies.",
            "Pin and verify model and package versions; check signatures and hashes.",
            "Apply the same patching cadence to model artifacts as to code dependencies.",
            "Use model integrity and provenance attestation where available.",
        ),
    ),
    Category(
        id="LLM04",
        number=4,
        title="Data and Model Poisoning",
        summary=(
            "Pre-training, fine-tuning or embedding data is manipulated to introduce "
            "backdoors, biases or degraded behaviour. A poisoned model can be triggered by "
            "a specific input to behave maliciously."
        ),
        pdf_page=20,
        key_mitigations=(
            "Track data origin and transformations with tooling such as OWASP CycloneDX.",
            "Vet data vendors and validate model outputs against trusted sources.",
            "Enforce sandboxing to prevent the model from ingesting unvetted data sources.",
            "Use anomaly detection and adversarial robustness techniques.",
            "Test with red-team campaigns and monitor for backdoor-trigger behaviour.",
        ),
    ),
    Category(
        id="LLM05",
        number=5,
        title="Improper Output Handling",
        summary=(
            "Model output is passed to downstream components without validation, sanitization "
            "or encoding. Because LLM output is user-controllable in effect, this yields "
            "classic injection outcomes: XSS, SQL injection, SSRF, path traversal, and remote "
            "code execution when output reaches eval/exec or a shell."
        ),
        pdf_page=23,
        key_mitigations=(
            "Treat the model as any other untrusted user; apply zero-trust to its output.",
            "Follow OWASP ASVS input-validation and sanitization guidance on model output.",
            "Context-aware encode model output for its destination (HTML, SQL, shell, JS).",
            "Use parameterized queries for any database operation involving model output.",
            "Never pass model output to eval/exec or a shell; use strict allow-lists.",
            "Apply rate limiting and anomaly detection to output-driven actions.",
        ),
    ),
    Category(
        id="LLM06",
        number=6,
        title="Excessive Agency",
        summary=(
            "An LLM-based system is granted more functionality, permissions or autonomy than "
            "it needs. Damaging actions follow from unexpected or manipulated model output — "
            "excessive functionality, excessive permissions, or excessive autonomy (no human "
            "in the loop for high-impact actions)."
        ),
        pdf_page=26,
        key_mitigations=(
            "Minimize extensions/tools: expose only the functions the agent genuinely needs.",
            "Minimize extension functionality to the narrowest implementation.",
            "Avoid open-ended extensions (shell exec, arbitrary HTTP) in favour of specific ones.",
            "Minimize extension permissions using least-privilege downstream credentials.",
            "Execute in the user's context, not with a shared privileged identity.",
            "Require human approval for high-impact actions.",
            "Enforce authorization in downstream systems rather than trusting the model.",
        ),
    ),
    Category(
        id="LLM07",
        number=7,
        title="System Prompt Leakage",
        summary=(
            "The system prompt is disclosed, revealing sensitive functionality, credentials, "
            "internal rules, permission structures or filtering criteria that an attacker can "
            "then use to bypass controls. The core issue is that the system prompt was relied "
            "on as a security boundary in the first place."
        ),
        pdf_page=30,
        key_mitigations=(
            "Separate sensitive data from system prompts entirely; never embed secrets there.",
            "Avoid relying on system prompts for strict behaviour control.",
            "Implement guardrails outside the LLM that independently enforce behaviour.",
            "Enforce security controls (privilege separation, authorization) independently "
            "of the LLM, in deterministic code.",
        ),
    ),
    Category(
        id="LLM08",
        number=8,
        title="Vector and Embedding Weaknesses",
        summary=(
            "Weaknesses in how vectors and embeddings are generated, stored and retrieved in "
            "RAG systems. Includes unauthorized access and cross-tenant data leakage from a "
            "shared vector store, embedding inversion recovering source data, and poisoned "
            "documents becoming an indirect prompt injection vector."
        ),
        pdf_page=33,
        key_mitigations=(
            "Apply fine-grained, permission-aware access control to the vector database and "
            "partition it logically per tenant.",
            "Validate and attribute the data pipeline: only accept documents from vetted sources.",
            "Review and classify combined data for concealed malicious instructions.",
            "Maintain detailed immutable logs of retrieval activity.",
        ),
    ),
    Category(
        id="LLM09",
        number=9,
        title="Misinformation",
        summary=(
            "The model produces false or misleading content that appears credible, including "
            "package hallucination (inventing non-existent dependencies) and unsafe advice. "
            "Compounded by overreliance, where users accept output without verification."
        ),
        pdf_page=36,
        key_mitigations=(
            "Use retrieval-augmented generation against trusted, verified sources.",
            "Cross-verify model output with external sources and automatic validation.",
            "Keep a human in the loop, especially for medical, legal and financial content.",
            "Communicate model limitations to users in the interface itself.",
            "Verify that any package name the model suggests actually exists before install.",
        ),
    ),
    Category(
        id="LLM10",
        number=10,
        title="Unbounded Consumption",
        summary=(
            "Uncontrolled inference: denial of service, denial of wallet, and model theft via "
            "extraction. Arises when the application places no limits on request volume, "
            "input size, output length or cost."
        ),
        pdf_page=39,
        key_mitigations=(
            "Validate and cap input size to defined limits.",
            "Limit exposure of logits and logprobs to only what the application needs.",
            "Apply rate limiting and user quotas per identity, and cap max_tokens.",
            "Enforce timeouts and throttle resource-intensive operations.",
            "Monitor and alert on resource consumption and spend.",
            "Apply watermarking and access controls to defend against model extraction.",
        ),
    ),
)

BY_ID: dict[str, Category] = {c.id: c for c in CATEGORIES}

SOURCE_DOCUMENT = "OWASP Top 10 for LLM Applications v2.0 (2025), OWASP Foundation, CC BY-SA 4.0"


def get(category_id: str) -> Category:
    return BY_ID[category_id]
