"""Shared regex vocabulary for the static engine.

Kept separate from `rules.py` so the LLM-call and sink vocabularies can be
reused by the taint heuristic as well as by individual rules.
"""

from __future__ import annotations

import re

# --------------------------------------------------------------------------
# Files we scan
# --------------------------------------------------------------------------

CODE_EXTENSIONS = {
    ".py", ".pyi",
    ".js", ".jsx", ".mjs", ".cjs",
    ".ts", ".tsx",
    ".rb", ".go", ".java", ".cs", ".php",
    ".ipynb",
}

CONFIG_EXTENSIONS = {
    ".yaml", ".yml", ".json", ".toml", ".ini", ".cfg", ".env", ".txt", ".md",
}

SKIP_DIRS = {
    ".git", ".hg", ".svn",
    "node_modules", "venv", ".venv", "env", "__pycache__",
    "dist", "build", ".next", ".nuxt", "out", "target",
    ".mypy_cache", ".pytest_cache", ".ruff_cache", ".tox",
    "site-packages", "vendor", ".idea", ".vscode",
}

MAX_FILE_BYTES = 2_000_000

# --------------------------------------------------------------------------
# Recognising an LLM call
# --------------------------------------------------------------------------

# Providers / SDK surfaces that mean "a model is being invoked here".
LLM_CALL = re.compile(
    r"""(?ix)
    (?:
        # OpenAI-style
        \b(?:openai|client|oai)\s*\.\s*(?:chat\s*\.\s*)?completions\s*\.\s*create
      | \bopenai\s*\.\s*(?:ChatCompletion|Completion)\s*\.\s*create
      | \bresponses\s*\.\s*create\b
        # Anthropic
      | \b(?:anthropic|client)\s*\.\s*messages\s*\.\s*(?:create|stream)
      | \banthropic\s*\.\s*completions\s*\.\s*create
        # Google
      | \bgenerate_content\s*\(
      | \bGenerativeModel\s*\(
        # LangChain / LlamaIndex / generic chains
      | \b(?:llm|chain|agent|model|chat|qa|rag)\s*\.\s*(?:invoke|run|predict|apredict|
          ainvoke|arun|call|acall|generate|agenerate|complete|stream|batch)\s*\(
      | \bChatOpenAI\s*\( | \bChatAnthropic\s*\( | \bOpenAI\s*\(
      | \bLLMChain\s*\( | \bConversationChain\s*\(
      | \bquery_engine\s*\.\s*query\s*\(
        # Others
      | \blitellm\s*\.\s*(?:completion|acompletion)\s*\(
      | \bollama\s*\.\s*(?:chat|generate)\s*\(
      | \bcohere\s*\.\s*(?:chat|generate)\s*\(
      | \bhf_?pipeline\s*\( | \bpipeline\s*\(\s*["']text-generation["']
      | \bmodel\s*\.\s*generate\s*\(
    )
    """
)

# Extracting the text out of a model response object.
LLM_RESPONSE_ACCESS = re.compile(
    r"""(?ix)
    (?:
        \.\s*choices\s*\[\s*0\s*\]\s*\.\s*message\s*\.\s*content
      | \.\s*choices\s*\[\s*0\s*\]\s*\.\s*text
      | \.\s*content\s*\[\s*0\s*\]\s*\.\s*text
      | \.\s*message\s*\.\s*content
      | \.\s*output_text\b
      | \.\s*text\s*\(\s*\)
    )
    """
)

# Variable names that, by convention, hold model output.
LLM_OUTPUT_NAMES = re.compile(
    r"(?ix)\b\w*(?:llm_?(?:out|output|response|result|reply|answer|text)"
    r"|model_?(?:out|output|response|reply)"
    r"|completion|generated_?text|ai_?(?:response|reply|answer|output)"
    r"|gpt_?(?:response|output)|assistant_?(?:reply|message|response))\w*\b"
)

# --------------------------------------------------------------------------
# Dangerous sinks — what model output must never reach unvalidated
# --------------------------------------------------------------------------

SINKS: dict[str, re.Pattern[str]] = {
    "code_execution": re.compile(
        r"(?ix)\b(?:eval|exec|execfile|compile)\s*\(|"
        r"\bnew\s+Function\s*\(|"
        r"\bsetTimeout\s*\(\s*[\"'`]|"
        r"\bpython_?repl\b|\bPythonREPL\w*\s*\("
    ),
    "shell_execution": re.compile(
        r"(?ix)\bos\s*\.\s*(?:system|popen)\s*\(|"
        r"\bsubprocess\s*\.\s*(?:run|call|check_output|check_call|Popen)\s*\(|"
        r"\bshell\s*=\s*True\b|"
        r"\bchild_process\s*\.\s*exec(?:Sync)?\s*\(|"
        r"\bcommands\s*\.\s*getoutput\s*\("
    ),
    "sql": re.compile(
        r"(?ix)\b(?:cursor|conn|connection|db|session|client)\s*\.\s*"
        r"(?:execute|executemany|executescript|raw|query)\s*\(|"
        r"\btext\s*\(\s*f[\"']|"
        r"\.\s*raw\s*\(\s*[f\"'`]"
    ),
    "html_render": re.compile(
        r"(?ix)\binnerHTML\s*=|\bouterHTML\s*=|"
        r"\bdangerouslySetInnerHTML\b|"
        r"\bdocument\s*\.\s*write\s*\(|"
        r"\brender_template_string\s*\(|"
        r"\|\s*safe\b|\bMarkup\s*\(|"
        r"\bv-html\b|\bmark_safe\s*\("
    ),
    "ssrf_http": re.compile(
        r"(?ix)\brequests\s*\.\s*(?:get|post|put|delete|head|request)\s*\(|"
        r"\bhttpx\s*\.\s*(?:get|post|Client)\s*\(|"
        r"\burllib\s*\.\s*request\s*\.\s*urlopen\s*\(|"
        r"\bfetch\s*\(|\baxios\s*\.\s*(?:get|post)\s*\("
    ),
    "file_write": re.compile(
        r"(?ix)\bopen\s*\([^)]*[\"'](?:w|a|w\+|a\+|wb|ab)[\"']|"
        r"\bPath\s*\([^)]*\)\s*\.\s*write_(?:text|bytes)\s*\(|"
        r"\bfs\s*\.\s*write_?[Ff]ile(?:Sync)?\s*\(|"
        r"\bos\s*\.\s*(?:remove|unlink|rmdir)\s*\(|"
        r"\bshutil\s*\.\s*rmtree\s*\("
    ),
    "deserialization": re.compile(
        r"(?ix)\bpickle\s*\.\s*loads?\s*\(|\bcPickle\s*\.\s*loads?\s*\(|"
        r"\bdill\s*\.\s*loads?\s*\(|\byaml\s*\.\s*load\s*\((?![^)]*SafeLoader)|"
        r"\bmarshal\s*\.\s*loads?\s*\("
    ),
}

SINK_LABELS = {
    "code_execution": "code execution (eval/exec)",
    "shell_execution": "shell command execution",
    "sql": "SQL query execution",
    "html_render": "raw HTML rendering",
    "ssrf_http": "outbound HTTP request",
    "file_write": "filesystem write/delete",
    "deserialization": "unsafe deserialization",
}

SINK_SEVERITY = {
    "code_execution": "CRITICAL",
    "shell_execution": "CRITICAL",
    "deserialization": "CRITICAL",
    "sql": "HIGH",
    "html_render": "HIGH",
    "file_write": "HIGH",
    "ssrf_http": "MEDIUM",
}

# --------------------------------------------------------------------------
# Untrusted-input sources (for indirect prompt injection)
# --------------------------------------------------------------------------

EXTERNAL_CONTENT_SOURCE = re.compile(
    r"(?ix)\brequests\s*\.\s*get\s*\(|\bhttpx\s*\.\s*get\s*\(|"
    r"\bBeautifulSoup\s*\(|\bWebBaseLoader\s*\(|\bUnstructured\w*Loader\s*\(|"
    r"\bPyPDF\w*Loader\s*\(|\bSeleniumURLLoader\s*\(|\bAsyncHtmlLoader\s*\(|"
    r"\bfeedparser\s*\.\s*parse\s*\(|\bplaywright\b|"
    r"\.\s*read\s*\(\s*\)\s*$|\bimap\b|\bemail\s*\.\s*message_from|"
    r"\bsimilarity_search\w*\s*\(|\bretriever\s*\.\s*(?:get_relevant_documents|invoke)\s*\("
)

USER_INPUT_SOURCE = re.compile(
    r"(?ix)\brequest\s*\.\s*(?:json|form|args|data|body|values|GET|POST)\b|"
    r"\breq\s*\.\s*(?:body|query|params)\b|"
    r"\binput\s*\(|\bsys\s*\.\s*argv\b|"
    r"\bawait\s+request\s*\.\s*json\s*\(\s*\)"
)
