# Marimo Code Analysis and Review

**Course:** CYBR 8420 – Designing for Software Security Engineering  
**Project:** Marimo – Reactive Python Notebook Platform  
**Team:** Team 4  
**Repository:** https://github.com/marimo-team/marimo 

---

## Part 1: Code Review

### 1.1 Scope and Focus

Our code review followed a scenario based and weakness based approach directly tied to our earlier work on:

- Misuse cases: data exfiltration, malicious code execution, public exposure of apps, denial of service, and debug mode misuse  
- Assurance cases: confidentiality of data in transit, execution isolation, and data exfiltration prevention  
- Threat models and data flow diagrams for Marimo

Rather than attempting to inspect every file, we scoped our review to areas with the highest security impact:

- `marimo/_server/…`  
  - HTTP server, WebSocket handling, authentication, middleware, error handling, and API endpoints
- `marimo/_secrets/secrets.py`
  - `secrets.py` is the high-level glue that exposes secret-management operations to the rest of the application including `_get_providers`, `get_secret_keys`, `write_secret()`.  
- `marimo/_runtime/…`  
  - Notebook execution engine, dependency management, execution context, and sandbox behavior. The `_runtime` package is effectively the **code execution control plane** for Marimo: it compiles and executes notebook cells, manages reactive re-execution, and coordinates state. Because executing user-provided Python is a core feature, `_runtime` cannot itself be treated as a security boundary; any compromise of a notebook is, by design, a compromise of the process running the runtime.  
- CLI and deployment entrypoints  
  - `marimo_cli/run_docker.py`, `marimo_cli/sandbox.py`, and related scripts that control flags such as `--no-token`, host binding, and Docker based deployment  
- Data access and SQL related modules  
  - `marimo/_data/…` modules that expose SQL, previews, and summaries to notebooks  
- Documentation, security policy, and examples  
  - `SECURITY.md`, example framework integrations, and HTML templates that are likely to be copied into downstream deployments

This scope kept our effort aligned with the risks that matter in a financial analysis environment instead of treating all files as equally critical, and it let us focus on the boundary between **untrusted notebook code** and the **Marimo runtime and server infrastructure**.

---

### 1.2 CWE Checklist for the Review

We used the following CWE list as a structured checklist across both manual and automated analysis. These CWEs were selected because they map directly to notebook execution, web exposure, and containerized deployment patterns in Marimo.

| CWE ID | Name | Why it matters for Marimo |
|--------|------|---------------------------|
| CWE-89  | SQL Injection | Marimo can issue SQL queries and display database results in notebooks. Unsafe query construction could expose or corrupt financial data. |
| CWE-95  | Improper Neutralization of Directives in Dynamically Evaluated Code (Eval Injection) | Dynamic execution via `exec` or `eval` in examples or runtime logic can become a code injection vector if user input is not tightly controlled. |
| CWE-78  | OS Command Injection | Notebook content or helper utilities may call `subprocess` or OS shell commands. If arguments become attacker controlled, this can lead to command injection. |
| CWE-79  | Cross Site Scripting (XSS) | The Marimo frontend renders notebook output and tracebacks into the browser. Unsafe HTML sinks can allow XSS when apps are publicly exposed. |
| CWE-200 | Exposure of Sensitive Information to an Unauthorized Actor | Misconfigured public apps, logs, or responses could reveal sensitive data or analysis artifacts. |
| CWE-209 | Information Exposure Through an Error Message | Verbose tracebacks and debug mode can leak file paths, configuration details, and internal state. |
| CWE-250 | Execution with Unnecessary Privileges | Containers or processes running as root increase the impact of a compromise inside a notebook or server process. |
| CWE-352 | Cross Site Request Forgery (CSRF) | Example login forms without CSRF protections could influence downstream adopters who copy patterns into production. |
| CWE-353 | Missing Support for Integrity Check | Lack of subresource integrity on CDN resources can allow script injection via third party compromise. |
| CWE-400 | Uncontrolled Resource Consumption | Unbounded execution, memory use, or repeated queries in notebooks can lead to denial of service in multi tenant deployments. |
| CWE-312 | Cleartext Storage of a Password | Marimo supports dotenv providers and writes secrets to .env files in plain key=value format (tests demonstrate literal values written). Plaintext secrets at rest can be exposed if files are accessible or accidentally committed. |
| CWE-285 | Improper Authorization | Secret creation and mutation endpoints (e.g., create_secret) rely on application authorization (requires("edit")). If authorization is misconfigured, attackers could create/overwrite secrets. |
| CWE-703 | Improper Check or Handling of Exceptional Conditions | Some provider implementations (e.g., delete_key in env provider) are incomplete/buggy and provider.write_key calls are not consistently wrapped with robust error handling, which can lead to inconsistent state or unintended information leakage. |
| CWE-20  | Improper Input Validation | Client-side sanitization exists for secret keys, but server-side validation of secret keys, provider names, and values is not clearly enforced in the write path; this could allow malformed keys or filesystem path manipulation in provider implementations. |
| CWE-798 | Use of Hard-coded Credentials | Example files and templates can encourage or accidentally include hard-coded secrets; copying examples into deployments could introduce hard-coded credentials in repos or images. |

This checklist served as a lens for reading code and interpreting automated findings, and it mapped cleanly onto our misuse cases for **untrusted code execution inside Marimo’s runtime** and **web exposure of notebook-backed apps**.


---

### 1.3 Manual and Automated Tools

#### 1.3.1 Manual Review Methods

We used several manual review techniques:

- Targeted file walkthroughs in `marimo/_server`, `marimo/_runtime`, and `marimo_cli` looking for authentication, configuration flags, input handling, logging, and error reporting paths  
- Search based review using queries such as `subprocess`, `exec(`, `eval(`, `--no-token`, `"0.0.0.0"`, `debug`, `sql`, `SELECT`, and `EXPLAIN` across the repository to locate high risk patterns  
- Architecture level reasoning using our threat models, DFDs, and assurance cases to understand how Marimo is expected to run in a secure environment (developer laptop versus shared server versus public apps)
- Generative assistance for comprehension: we used short, focused prompts to explain what functions do or to get a second look at complex code paths; we then validated results manually. 

For `_runtime` specifically, we treated it as the **execution core** rather than a sandbox, and focused on:

- How cells are executed (e.g., use of Python’s `exec` model)  
- How global namespaces and execution contexts are constructed and reused  
- Whether any runtime internals or privileged objects are injected into notebook-visible namespaces  
- How runtime behavior might interact with caching or serialization mechanisms

To speed up manual review, we also used generative AI chat in the style recommended in the course materials, for example:

- “Explain what this code does: [code snippet]”  
- “Evaluate the security of this Python code and explain results using CWEs: [code snippet]”  
- “Examine this function for CWE 78 (OS Command Injection) and CWE 95 (Eval Injection): [code snippet]”

AI assistance was used only to summarize or clarify code behavior. All final findings, CWE mappings, and risk assessments were verified directly against the Marimo codebase.

#### 1.3.2 Automated Analysis Tools

We complemented manual review with two primary static analysis tools:

- **Semgrep** (multi language SAST)  
  - Command:  
    ```bash
    semgrep --config auto . --json --output semgrep-report.json
    ```  
  - Purpose: enforce language and framework agnostic security rules covering Python, TypeScript, HTML, and Dockerfiles and map findings to CWEs where possible.

- **Bandit** (Python security scanner)  
  - Commands:  
    ```bash
    bandit -r . -f html -o bandit_report.html
    [main]  INFO    profile include tests: None
    [main]  INFO    profile exclude tests: None
    [main]  INFO    cli include tests: None
    [main]  INFO    cli exclude tests: None
    [main]  INFO    running on Python 3.10.0
    Working... ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:25
    [html]  INFO    HTML output written to file: bandit_report.html
    ```  
  - Purpose: focus on Python specific issues such as unsafe `subprocess` usage, dynamic evaluation, insecure deserialization, and misuse of asserts.

---

### 1.4 Anticipated Challenges

Before running tools or opening files, we identified several challenges:

- **Scale and churn**  
  Marimo is an actively developed open source project with a large codebase and frequent changes. We had to accept that we would only be able to reason deeply about selected modules within the timeframe of the assignment.  

- **Dynamic behavior**  
  The reactive notebook execution model, dynamic imports, and runtime generated code make it difficult to fully understand behavior from static inspection alone. `_runtime` exists specifically to orchestrate arbitrary Python execution in response to user actions, which means many security properties depend on how Marimo is *deployed and isolated*, not just how the code is written.  

- **Tool noise and false positives**  
  Both Semgrep and Bandit can produce a significant number of low risk or context dependent findings, requiring careful triage rather than blind acceptance.  

- **Configuration dependent risks**  
  Some of the most serious risks, such as running without authentication or binding to `0.0.0.0`, are driven by how Marimo is launched, not just by code structure.

---

### 1.5 Strategy to Address Challenges

To deal with these challenges, we adopted the following strategy:

- **Tie everything to misuse cases**  
  Every manual finding and every automated finding we decided to keep is explicitly tied to one or more misuse cases and CWEs. This kept us from chasing issues that do not matter in our target environment.  

- **Limit scope, deepen depth**  
  Instead of shallowly scanning everything, we prioritized depth in a few critical areas: notebook execution, server configuration, example deployments, Docker related files, and execution control paths in `_runtime`.  

- **Use automated tools as triage, not verdict**  
  We treated Semgrep and Bandit as spotlights to find potential hotspots. We then manually reviewed representative examples to determine whether a finding was relevant, exploitable, or simply a benign pattern in test or example code.  

- **Leverage repository structure and documentation**  
  We used existing documentation, `SECURITY.md`, and the directory layout to infer intended security properties and validate whether the implementation and examples support those goals.

---

## Part 1: Findings from Manual Code Review

This section summarizes findings discovered through direct human review of Marimo’s code, configuration, and documentation rather than solely via automated tools.

### M 1: Risky Public Binding and Tokenless Access

- **Location:** `marimo_cli/run_docker.py` and related CLI documentation  
- **Related misuse cases:** Public exposure of Marimo apps, data exfiltration  
- **Related CWE(s):** CWE 200 (Exposure of Sensitive Information), CWE 250 (Execution with Unnecessary Privileges)  

**Description and risk**

The Docker based CLI helper defaults to binding the Marimo server to `host = "0.0.0.0"` inside a container so that it is reachable from the host system. Combined with flags that disable token based authentication, this lowers the barrier to running a notebook server that is reachable by unintended users on the network. While the code is not inherently vulnerable by itself, the defaults and examples lean toward convenience over security. In a financial analysis environment, this increases the likelihood of exposing internal notebooks or datasets to unauthorized actors if the container is deployed into a misconfigured network segment.

**Suggested mitigation**

- Strengthen documentation and CLI help text to mark `0.0.0.0` binding and `--no-token` style options as high risk, including explicit warnings about external exposure.  
- Prefer more restrictive defaults, such as binding to `127.0.0.1` unless explicitly overridden.  
- Encourage use of reverse proxies and network level controls in deployment guides to avoid direct exposure of the notebook server port.

---

### M 2: Verbose Tracebacks and Error Messages

- **Location:** Error handling paths in `marimo/_server` and `marimo/_runtime` that display tracebacks and debug information  
- **Related misuse cases:** Debug mode misuse, information disclosure  
- **Related CWE(s):** CWE 209 (Information Exposure Through an Error Message), CWE 200  

**Description and risk**

Marimo provides rich tracebacks and detailed error displays to support interactive debugging, which is highly valuable during development. However, in production deployments or in shared multi tenant environments, these verbose error messages can reveal file paths, environment details, and in some cases the content of failing queries or code fragments. If an unauthenticated or low privileged user can trigger errors in a publicly reachable app, this increases the information available for reconnaissance and targeted attacks.

**Suggested mitigation**

- Ensure that production configuration routes errors through a sanitized error handler that hides internal paths and sensitive values.  
- Make the distinction between development mode and production mode explicit in documentation and examples.  
- Where possible, log detailed diagnostics on the server side while displaying only generic error messages to end users.

---

### M 3: Resource Exhaustion and Lack of Hard Limits

- **Location:** Execution and scheduling logic in `marimo/_runtime` and associated modules  
- **Related misuse cases:** Denial of service, malicious code execution  
- **Related CWE(s):** CWE 400 (Uncontrolled Resource Consumption)  

**Description and risk**

Our review did not identify clear, built in hard limits on execution time, memory usage, or request rate for notebook code. While this is common for notebook style systems, it means that a single notebook can submit expensive queries, allocate large dataframes, or enter long running loops without an obvious mechanism for global resource control. In a multi user environment, this creates opportunities for unintentional or intentional resource exhaustion attacks that degrade service for other analysts.

Because `_runtime` is responsible for orchestrating all cell execution and re-execution, the absence of built-in limits there means that any long-running or malicious notebook directly impacts the process hosting the runtime.

**Suggested mitigation**

- Introduce configuration options for per notebook and per user resource caps, including execution timeouts and memory ceilings.  
- Document deployment patterns that place Marimo behind infrastructure level controls such as reverse proxies with rate limiting and Kubernetes resource quotas.  
- Provide example guardrails or defaults for organizational deployments where resource isolation is a requirement.

---

### M 4: Runtime Execution Engine and Isolation Boundary

- **Location:** `marimo/_runtime/…` (execution engine, dependency graph, and context management)  
- **Related misuse cases:** Malicious code execution, data exfiltration, denial of service  
- **Related CWE(s):** CWE 95 (Eval Injection), CWE 250 (Execution with Unnecessary Privileges), CWE 400 (Uncontrolled Resource Consumption)  

**Description and risk**

The `_runtime` package is intentionally designed to execute arbitrary user-provided Python code in response to notebook edits and UI events. Static review confirmed that the runtime behaves like a standard Python execution environment: once a notebook is loaded, its code runs with the same OS-level privileges as the Marimo process. There is no indication of an internal sandbox, separate interpreter, or per-notebook process isolation within `_runtime` itself.

This means:

- Any user who can run or modify a notebook effectively controls a general-purpose Python execution environment.  
- The blast radius of a compromised notebook is determined by **how Marimo is deployed** (container, user account, network position), not by `_runtime` logic.  
- Any caching or state reuse at the runtime level must be treated as potentially sensitive, especially if multiple users share a single runtime process.

This behavior is not a bug—arbitrary code execution is the product’s core feature—but it is an important architectural constraint for secure deployment.

**Suggested mitigation**

- Treat `_runtime` as **untrusted-code infrastructure** and never as a security boundary.  
- Run Marimo in containers or VMs using a non-root user with strictly limited filesystem and network access.  
- Avoid sharing a single runtime process across mutually untrusted users; prefer per-user or per-notebook isolation where feasible.  
- Clearly document that execution isolation and host protection must be provided by the deployment environment (e.g., Docker, Kubernetes, or OS-level sandboxing).

---

### M 5: Example Patterns and Secure Defaults

- **Location:** Example framework integrations (`examples/frameworks/*`), HTML templates, and documentation snippets  
- **Related misuse cases:** Public exposure, data exfiltration, CSRF and XSS risks  
- **Related CWE(s):** CWE 79 (XSS), CWE 352 (CSRF), CWE 353 (Missing Support for Integrity Check)  

**Description and risk**

Several example applications and HTML templates are designed to be minimal and educational. However, examples that omit CSRF tokens, subresource integrity attributes, or input validation can be copied verbatim into downstream production settings. When these patterns lack explicit warnings, they effectively encode insecure defaults. In particular, login forms without CSRF tokens and pages that import scripts from CDNs without integrity attributes are risky starting points for real applications.

**Suggested mitigation**

- Upgrade example code to demonstrate secure patterns by default, including CSRF protection, SRI on CDN resources, and safe rendering of untrusted output.  
- Clearly label any intentionally simplified examples as not production safe and link to secure variants.  
- Align examples with the project’s own `SECURITY.md` guidance so that documentation, examples, and implementation reinforce the same security posture.

---

### M 6: Cleartext dotenv storage and plaintext secret writes

- **Location:**  
  - marimo/_secrets/secrets.py (write_secret) — invokes provider.write_key  
  - marimo/_secrets/env_provider.py (DotEnv provider implementation)  
  - tests/_secrets/test_secrets.py (verifies literal 'NEW_SECRET="new_value"' written to .env)  
  - frontend code that may trigger secret writes via server endpoints (write-secret-modal.tsx)  

- **Description and risk:**  
  - write_secret delegates secret persistence to DotEnvSecretsProvider which writes key=value entries to files on disk. The test suite demonstrates the secret value is present literally in the .env file after write. This means secrets are stored at rest in cleartext (CWE-312). If these files are accessible to other users, processes, backups, or are accidentally committed to git, the secret values can be exfiltrated (CWE-200).  

- **Suggested mitigation:**  
  - Avoid long-lived plaintext storage for high-value secrets; recommend using OS-native or cloud secret stores (e.g., AWS Secrets Manager, HashiCorp Vault, Keychain).  
  - If filesystem-backed providers are required: (1) write files atomically (write temp file + fsync + rename), (2) set restrictive file permissions (600) and ownership, (3) avoid storing secrets in repo or build artifacts and add dotenv patterns to .gitignore, (4) scan git history for accidental commits (git-secrets, truffleHog) and rotate any exposed secrets.  
  - Update tests and provider implementations to assert permissions and atomic writes.

---

### M 7: Generated code may inline default secret values (client-side artifact leakage)

- **Location:** frontend/src/components/editor/database/as-code.ts (formatting code that emits os.environ.get with defaults) and frontend as-code generation flows.

- **Description and risk:**  
  - The frontend generation logic can produce Python snippets like os.environ.get("KEY", "default_value") and stores those default strings in generated artifacts. If the UI or users provide default values that are actual secrets (or if client-side state includes secret strings), the generated code or saved scripts may contain secret values in plaintext. This is an information exposure risk (CWE-312, CWE-200).  

- **Suggested mitigation:**  
  - Never embed secret values as literal defaults in generated code. Only emit env lookup expressions without defaults, or use placeholders.  
  - On the frontend, avoid storing actual secret values in code-generation maps; only keep the env key names.  
  - Add server-side checks to strip any secret-like literals from generated artifacts before saving or exporting, and document this behavior.

---

### M 8: Exposure of secret key names and provider metadata to the UI

- **Location:**  
  - marimo/_secrets/secrets.py (get_secret_keys) — collects provider type, provider name, and keys  
  - marimo/_runtime/runtime.py (SecretsCallbacks.list_secrets) — broadcasts SecretKeysResult to UI

- **Description and risk:**  
  - The system returns secret key names and provider names to the frontend so users can select keys. While this does not return secret values, enumerating key names reveals presence and types of credentials (e.g., AWS keys) which is a sensitive disclosure (CWE-200). In multi-tenant or shared deployments, exposing key names or provider paths to unauthorized users increases attack surface.

- **Suggested mitigation:**  
  - Only return key names and provider metadata to authenticated and authorized users — enforce least privilege.  
  - Consider redacting provider internal names or file paths from the UI and only present friendly labels.  
  - Log accesses to secret listings for audit, and implement UI controls that avoid overexposing environment layout.

---

### M 9: Authorization reliance and secret write surface

- **Location:** marimo/_server/api/endpoints/secrets.py (create_secret endpoint) which is decorated with @requires("edit"), and marimo/_secrets/secrets.py (write_secret) invoked by the endpoint.

- **Description and risk:**  
  - The create_secret API performs privileged write operations (writes secret values to providers). This endpoint is protected by a requires("edit") decorator, but the effectiveness depends on the requires implementation and the session auth pipeline. If authorization checks are missing, bypassable, or misconfigured, attackers could create or overwrite secrets (CWE-285).

- **Suggested mitigation:**  
  - Audit and harden the requires(...) decorator and authentication/session management. Ensure server-side checks validate both identity and permissions, not rely solely on client-sent data.  
  - Add CSRF protection and anti-replay measures to mutate endpoints.  
  - Add server-side validation of provider name, provider type, and key names against an allow-list before performing writes.  
  - Maintain an audit log of create/update/delete operations for secrets that records actor (user/session), time, target provider and key (without logging secret values).

---

### M 10: Provider implementation bugs and insufficient error handling

- **Location:**  
  - marimo/_secrets/env_provider.py — delete_key currently implemented as "del key" then raise NotImplementedError (bug)  
  - marimo/_secrets/models.py — provider abstract API expects get_keys/write_key/delete_key  
  - marimo/_secrets/secrets.py — write_secret calls provider.write_key without try/except

- **Description and risk:**  
  - The env provider's delete_key implementation is a no-op/bug and does not remove keys from storage. write_secret does not catch provider exceptions; a failed write can leave partial state or bubble up internal errors to callers causing information exposure (CWE-703). Additionally, malformed inputs might be passed to provider implementations, creating opportunities for path traversal or corruption (CWE-20).

- **Suggested mitigation:**  
  - Fix provider implementations (implement delete_key to update the underlying .env file correctly). Ensure write_key/delete_key perform safe, atomic updates and set secure file permissions.  
  - Add robust server-side input validation (allowed key name pattern, max length, provider whitelist).  
  - Wrap provider calls in controlled try/except that returns sanitized error messages to callers while logging full details to secure server logs.  
  - Add unit tests that assert correct delete behavior, atomicity, and error handling.

---

### M 11: Client-side sanitization without server-side validation

- **Location:** frontend/src/components/editor/chrome/panels/write-secret-modal.tsx (client-side replaceInvalid) and marimo/_secrets/secrets.py (no visible server-side validation in write path)

- **Description and risk:**  
  - The UI removes non-word characters from secret key input, but client-side sanitization can be bypassed. The server-side write path shown does not perform explicit validation of key or value content before delegating to the provider, risking malformed keys or abuse of provider semantics (CWE-20).

- **Suggested mitigation:**  
  - Implement and enforce server-side validation of secret key names (regex whitelist), maximum lengths, and allowed provider targets. Reject requests that fail validation with clear, non-sensitive error responses.  
  - Keep client sanitization as UX convenience only; rely on server validation for security.

---

### M 12: SQL helper APIs and injection-prone data access patterns

- **Location:**  
  - `marimo/_data/…` modules that expose SQL query, preview, and summary helpers to notebooks

- **Related misuse cases:**  
  - Data exfiltration, unauthorized modification of financial data, abuse of shared database resources

- **Related CWE(s):**  
  - CWE-89 (SQL Injection)  
  - CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)  
  - CWE-20 (Improper Input Validation)

**Description and risk**

Marimo’s data helpers are designed to let notebooks run SQL queries and display results inside the notebook UI. During manual review of the `marimo/_data` modules and their surrounding usage patterns, we observed that the primary abstraction expects notebooks to pass raw SQL strings directly into helper functions. This is expected for an analysis-focused tool, but it also means:

- There is no framework-level requirement to use parameterized queries when interpolating user-influenced values.  
- Nothing in the helper API distinguishes “static analyst-written SQL” from SQL strings that might contain request parameters or other untrusted input in a published app.  
- Query helpers focus on execution and display, not on enforcing column/row filters or hiding sensitive fields by default.

In a single-user environment where only a trusted analyst writes notebooks, this is mostly a correctness/usability concern. But in our hypothetical **financial analysis** context, where notebooks can be turned into shareable apps or exposed over the network, it becomes a security issue:

- If notebook authors build queries with string concatenation or f-strings around user inputs, the helper APIs will happily execute them, providing a path for **SQL injection (CWE-89)**.  
- Over-broad queries (e.g., `SELECT *` on large tables) combined with previews in the UI increase the chance of **unintentional data exposure (CWE-200)** beyond what a given user or role should see.  

The risk is amplified when the same Marimo deployment is used by multiple teams or when the database contains both production and analytical data. A single vulnerable query in a popular notebook/app could become a pivot point into more sensitive tables.

**Suggested mitigation**

- At the API level, provide **first-class parameterized query helpers**, for example functions that take `(sql_template, params)` and internally use the database driver’s safe parameter binding instead of encouraging string concatenation.  
- In documentation and examples, clearly distinguish between:
  - “Trusted analyst SQL in private notebooks” and  
  - “SQL built from user input in published apps”, with explicit guidance that the latter **must use parameterization and strict input validation**.  
- Offer safer defaults in any “query builder” or convenience functions:
  - Discourage `SELECT *` in examples; demonstrate explicit column lists and limited result sets.  
  - Show patterns for adding row-level filters appropriate for multi-tenant or role-based scenarios.  
- Add tests or linting rules (even simple ones) that flag obviously dangerous patterns in example notebooks, such as string concatenation around `WHERE` clauses with user-provided values. This nudges downstream users towards safer composition when they copy patterns from Marimo’s examples.


## Part 1: Findings from Automated Code Scanning

### 1.6 Automated Tools Run

We used two primary automated tools and archived their outputs in our team repository:

- **Semgrep**  
  - Command:  
    ```bash
    semgrep --config auto . --json --output docs/5.CodeAnalysis/Diagrams/semgrep-report.json
    ```  
  - Scope: repo root, including Python, TypeScript, JavaScript, HTML, and Dockerfiles  
  - Artifact: `docs/5.CodeAnalysis/Diagrams/semgrep-report.json`

- **Bandit**  
  - Commands:  
    ```bash
    bandit -r . -f json   -o docs/5.CodeAnalysis/Diagrams/bandit_report.html
    bandit -r . -f screen > docs/5.CodeAnalysis/bandit-report.txt
    ```  
  - Scope: all Python files in the repository  
  - Artifacts: `[docs/5.CodeAnalysis/Diagrams/bandit_report.html](https://github.com/os2594/Team4/blob/main/docs/5.CodeAnalysis/Diagrams/bandit_report.html)` and `[docs/5.CodeAnalysis/Diagrams/semgrep-report.json](https://github.com/os2594/Team4/blob/main/docs/5.CodeAnalysis/Diagrams/semgrep-report.json)`

---

### 1.7 Semgrep Summary

We used Semgrep OSS with the `--config auto` setting to scan our Marimo fork:

- Rules run: 511  
- Targets scanned: approximately 3,140 files  
- Findings: 116 total (mix of security, correctness, and maintainability)  

From these findings, we focused on issues that intersect with our misuse cases: data exfiltration, malicious code execution, public exposure of Marimo apps, and denial of service. Representative examples include:

1. **Docker containers running as root (CWE 250 – Execution with Unnecessary Privileges)**  
   - Files: `docker/Dockerfile` (lines 29, 34, 39)  
   - Rule: `dockerfile.security.missing-user.missing-user`  
   - Summary: The Dockerfile does not specify a non root `USER` at the end of the build, which means the container may run Marimo processes as root by default. If an attacker exploits a vulnerability in the notebook server, they gain root within the container, increasing the blast radius of a compromise. This directly relates to our malicious code execution and secure deployment concerns.

2. **Dynamic code execution via `exec()` and `eval()` in AI tools examples (CWE 95 – Eval Injection)**  
   - Files: `examples/ai/tools/chat_with_tools.py`, `examples/ai/tools/code_interpreter.py`  
   - Rules:  
     - `python.lang.security.audit.exec-detected.exec-detected`  
     - `python.lang.security.audit.eval-detected.eval-detected`  
   - Summary: These example tools use `exec()` and `eval()` to run dynamically constructed Python code. Semgrep flags this as an injection risk because, if any portion of the evaluated string becomes user controlled, it could allow arbitrary code execution. This aligns with our malicious code execution misuse case and reinforces the need for sandboxing and strict control of which examples are deployed in production.

3. **Missing integrity checks on CDN resources (CWE 353 – Missing Support for Integrity Check)**  
   - Files: HTML templates under `examples/frameworks/*/templates/` and `frontend/islands/__demo__/*.html`  
   - Rule: `html.security.audit.missing-integrity.missing-integrity`  
   - Summary: Several example pages include externally hosted JavaScript and CSS without a subresource integrity attribute. If a CDN or intermediary is compromised, an attacker could inject malicious scripts that run in users’ browsers. For publicly exposed Marimo apps, this amplifies our information disclosure and public exposure misuse cases.

4. **Example login forms without CSRF protection (CWE 352 – Cross Site Request Forgery)**  
   - Files:  
     - `examples/frameworks/fastapi/templates/login.html`  
     - `examples/frameworks/flask/templates/login.html`  
   - Rule: `python.django.security.django-no-csrf-token.django-no-csrf-token`  
   - Summary: Semgrep identifies that these manually built forms do not include CSRF tokens. If adopters copy these examples directly into a real deployment, they could be vulnerable to CSRF attacks. This connects to our broader theme that documentation and examples must not encourage insecure defaults.

5. **Command execution in frontend test configuration (CWE 78 – OS Command Injection)**  
   - File: `frontend/playwright.config.ts`  
   - Rule: `javascript.lang.security.detect-child-process.detect-child-process`  
   - Summary: The Playwright configuration makes calls to Node’s `child_process`. Semgrep warns that, if any part of the command or its arguments becomes user controlled, this could lead to OS command injection. While this lives in test code, it still highlights the importance of sandboxing and principle of least privilege when Marimo is run in CI or shared environments.

6. **XSS prone DOM APIs and React patterns (CWE 79 – Cross Site Scripting)**  
   - Files:  
     - `frontend/src/components/editor/output/ConsoleOutput.tsx` (uses `dangerouslySetInnerHTML`)  
     - `frontend/src/components/editor/output/MarimoTracebackOutput.tsx` (uses DOM methods like `innerHTML`)  
   - Rules:  
     - `typescript.react.security.audit.react-dangerouslysetinnerhtml.react-dangerouslysetinnerhtml`  
     - `javascript.browser.security.insecure-document-method.insecure-document-method`  
   - Summary: Both findings point to rendering HTML fragments into the DOM. These are safe only if the HTML is fully trusted. If notebook output, error messages, or tracebacks can be influenced by an attacker, such as via untrusted code or public apps, these become potential XSS sinks. This reinforces our threat models around publicly exposed Marimo apps, debug mode leakage, and the need for robust output sanitization.

Overall, the Semgrep results confirmed that our CWE checklist is well aligned with Marimo’s architecture and typical deployment patterns and helped us prioritize manual review around notebook execution, web UI rendering, and deployment examples.

---

### 1.8 Bandit Summary

#### 1.8.1 Bandit Execution and Metrics

- **Files scanned:** 600+ Python files  
- **Issues reported:** dozens of findings with a mix of low, medium, and high severity  
- **Report artifacts:** `bandit-report.json` and `bandit-report.txt` under `docs/5.CodeAnalysis/`  

Bandit produced a broad set of warnings. We focused on those that intersect with our CWE checklist and misuse cases.

#### 1.8.2 Representative Bandit Findings

**Use of `subprocess` with potentially variable input (CWE 78 – OS Command Injection)**  
- **Pattern:** calls to `subprocess.run` or similar functions with non literal arguments  
- **Risk:** if untrusted input ever flows into these arguments in the future, there is a path toward OS command injection  
- **Mitigation direction:** ensure that any subprocess use is limited to controlled commands or uses argument lists with strict validation rather than shell strings  

**Use of dynamic evaluation features such as `eval` or `exec` (CWE 95 – Eval Injection)**  
- **Pattern:** dynamic execution of constructed strings in example tools  
- **Risk:** if user controlled content can reach these strings, arbitrary code execution becomes possible  
- **Mitigation direction:** isolate this behavior to clearly documented example code, avoid it in core runtime paths, and provide sandboxing guidance  

**Broad or empty exception handlers (CWE 209 – Information Exposure Through an Error Message)**  
- **Pattern:** `except Exception:` handlers that log or surface errors in a generic way  
- **Risk:** if these handlers print exception objects or tracebacks directly to users, they can expose sensitive implementation details or data fragments  
- **Mitigation direction:** narrow exception types where practical and route full details to server side logs while showing generic messages to users  

**Warnings about use of `assert` for security relevant checks (CWE 703 – Improper Check or Handling of Exceptional Conditions)**  
- **Pattern:** `assert` statements used for invariants that could be disabled with optimized Python flags  
- **Risk:** security relevant checks implemented only as asserts may not run in production if optimization is enabled  
- **Mitigation direction:** replace asserts with explicit conditionals and error handling for any security relevant logic  

**Network and HTTP calls using high level libraries without explicit timeouts**  
- **Pattern:** calls to `urllib` or similar modules without explicit timeouts  
- **Risk:** unbounded network calls may contribute to resource exhaustion or unexpected blocking  
- **Mitigation direction:** prefer explicit timeouts and robust error handling for external requests  

Bandit’s results complemented Semgrep by highlighting Python specific patterns and helped us confirm that our CWE checklist remained appropriate for the Marimo codebase.

---

## Part 2: Key Findings and Contributions

### 2.1 Summary of Key Findings and Risk

The table below summarizes the most important findings across manual and automated review. These drive our perception of risk in a financial analysis environment.

| ID  | Source (Manual or Tool) | CWE(s)                       | Short description                                                             | Risk in financial environment                                                                                  |
|-----|-------------------------|------------------------------|-------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------|
| KF 1 | Manual (M 1)           | CWE 200, CWE 250             | Public binding combined with tokenless access can expose internal notebooks  | Unauthorized analysts or external actors could reach sensitive notebooks if network segments are misconfigured. |
| KF 2 | Manual (M 2)           | CWE 209, CWE 200             | Verbose tracebacks and debug mode can leak internal details                  | Detailed error messages may reveal paths, queries, and system information useful for targeted attacks.          |
| KF 3 | Manual (M 3)           | CWE 400                      | Lack of built in resource limits on notebook execution                       | Heavy notebooks or malicious code can exhaust CPU or memory, leading to denial of service for other analysts.   |
| KF 4 | Manual (M 4)           | CWE 95, CWE 250, CWE 400     | Runtime execution engine is not a sandbox; arbitrary user code runs with process privileges | Compromised notebooks have the full power of the Marimo process; isolation must be provided by containers and OS, not by `_runtime` itself. |
| KF 5 | Automated (Semgrep)    | CWE 250, CWE 95              | Containers run as root and example code uses `exec` and `eval`               | Exploited notebooks or misused examples could lead to high impact compromise inside containers or hosts.        |
| KF 6 | Automated (Semgrep)    | CWE 79, CWE 352, CWE 353     | XSS prone rendering and insecure example templates                           | Downstream teams that copy examples without hardening may deploy applications with XSS, CSRF, or CDN based script injection risks. |
| KF 7 | Automated (Bandit)     | CWE 78, CWE 209              | Subprocess and exception handling patterns in Python modules                  | Poorly guarded subprocess calls or logging may turn into command injection or information leakage issues in certain configurations. |
| KF 8 | Manual (M 6)           | CWE 312, CWE 200             | Cleartext dotenv storage and plaintext secret writes to .env files           | Secrets written to disk in plaintext can be exfiltrated via backups, repo commits, or access by other processes — high impact for credentials. |
| KF 9 | Manual (M 7)           | CWE 312, CWE 200             | Generated code may inline default secret values in artifacts                 | Secrets embedded in generated scripts or exported code may leak to version control or artifacts. |
| KF 10 | Manual (M 8)          | CWE 200                      | Exposure of secret key names and provider metadata to UI                     | Enumeration of keys/providers increases attacker reconnaissance and targeted attacks. |
| KF 11 | Manual (M 9)          | CWE 285                      | Authorization reliance for secret-create endpoint (requires("edit"))         | Misconfiguration or bypass could allow unauthorized secret creation/overwrite. |
| KF 12 | Manual (M 10)         | CWE 703, CWE 20              | Provider implementation bugs and insufficient error handling (delete_key bug, no wrapping of writes) | Inconsistent secret state, errors leaking internal details, potential path traversal/abuse of provider semantics. |
| KF 13 | Manual (M 11)         | CWE 20                       | Client-side sanitization without server-side validation for secret keys      | Attackers can bypass client checks to create malformed keys or abuse provider semantics; server-side validation required. |
| KF 14 | Manual (M 12)         | CWE 89, CWE 200, CWE 20 | SQL helper APIs execute raw SQL strings passed from notebooks; without strong guidance and parameterization patterns, notebooks that incorporate user input can introduce SQL injection and overbroad data exposure in shared financial databases. |

Overall, we found that Marimo does not exhibit obvious catastrophic vulnerabilities in the core runtime based on our sample, but it does rely heavily on deployment choices, container configuration, and example patterns. In a financial environment, this means secure defaults, **strong runtime isolation**, and hardened documentation are critical.

---

### 2.2 Planned and Ongoing Contributions to Marimo

Based on our analysis, our planned or ongoing contributions to the upstream Marimo project include:

#### Documentation and design changes

- Proposing clearer secure deployment guidance, including a secure deployment checklist for binding, tokens, TLS, and reverse proxy use  
- Strengthening examples to favor parameterized SQL, safe query patterns, and secure defaults  
- Improving documentation around authentication and token based access for public facing apps  
- Explicitly documenting that `_runtime` is not a sandbox and that execution isolation must be provided by containers, VMs, or other infrastructure

#### Code and configuration improvements

- Recommending stricter behavior or higher visibility warnings for flags such as `--no-token` and host binds to `0.0.0.0`  
- Suggesting improvements to error handling so that production deployments default to sanitized error messages  
- Recommending or contributing initial hooks for execution time limits, memory caps, and sandbox enhancements  
- Proposing Dockerfile changes so Marimo containers run as a non root user by default

#### Security communications

- Aligning `SECURITY.md` with our findings by clarifying expectations for responsible disclosure  
- Adding a short section on secure notebook deployment in regulated environments  
- Highlighting common pitfalls when exposing notebook-backed apps directly to the internet

---

### 2.2.1 OSS Project Interactions

As part of this assignment, we identified the following candidate issues and pull requests to file against the main Marimo repository:

- **Issue:** “Clarify secure deployment guidance for public apps” (secure binding, authentication, and reverse proxy recommendations)  
- **Issue or pull request:** “Run Docker containers as non root by default” to reduce the impact of a compromised notebook environment  
- **Issue:** “Harden example applications with CSRF, SRI, and secure rendering patterns” to align examples with secure defaults  
- **Issue:** “Document runtime isolation expectations for `_runtime` and notebook execution” to make it clear that the project assumes container or OS-level sandboxing

These interactions build directly on the misuse cases and CWEs that emerged from our code review.

---

### 2.3 Team Repository and Collaboration

Team 4 used the GitHub repository at https://github.com/os2594/Team4 to coordinate work on this assignment. Our collaboration approach included:

- Dividing code review responsibilities primarily by directory and misuse case:  
  - One member focused on `marimo/_server` and error handling
  - One member focused on `marimo/_secrets/secrets.py` and error handling  
  - One focused on `marimo/_runtime` and execution behavior  
  - Others focused on Docker files, CLI scripts, and example applications  

- Sharing Semgrep and Bandit outputs through committed artifacts under `docs/5.CodeAnalysis/`, so that each team member could review findings without rerunning tools locally  

- Using pull requests, commits, and markdown documents under `docs/` to track progress, discuss interpretations of findings, and refine the final narrative  

This process helped us maintain a shared understanding of risk while still allowing focused, parallel work.

---

### 2.4 Team Reflection

Each team member answered the following questions:

- What did you learn from this assignment?  
- What did you find the most useful for your understanding of secure software engineering?

#### 2.4.1 Individual Reflections

- **Osmar**  
  Through this review I gained a much deeper, practical appreciation for   the difference between code-level security issues and deployment/operational risks. Reading       Marimo’s runtime and secrets handling showed me how design choices (e.g., storing secrets in dotenv files, or relying on deployment defaults) can create larger, emergent vulnerabilities even when the code looks reasonable.

- **Justin**  
  After reviewing the analysis from both automatic and manual review. I've determined there is a lot of value and potential missed opportunities in the code. I appreciate that we were able to put some different tools together to test this and get back some fascinating results. 

- **Dominic**  
  Gained a deeper appreciation for how execution isolation and resource limits affect real world risk in shared environments. The most useful part was tying Bandit and Semgrep findings back to specific misuse cases like data exfiltration and denial of service, and seeing how the `_runtime` execution model means that deployment choices matter as much as code-level fixes.

- **Preeti**  
  For me, this assignment finally made CWE IDs and misuse cases feel concrete instead of abstract lists. When I looked at the `marimo/_data` SQL helper modules, I had to think not just “is this code correct?” but “what happens if someone uses this helper in a public app with untrusted input?” That lens helped me see how CWE-89 (SQL injection) and CWE-200 (data exposure) actually show up in a realistic analytics tool, even when the framework itself is doing the “right” thing of just executing SQL it is given. The most useful part was learning to combine our earlier threat models with a focused manual review — it gave me a repeatable way to read code in terms of scenarios and risk, not just style or performance.

- **Zaid**  
  \<ADD REFLECTION\>

#### 2.4.2 Combined Team Reflection

As a team, we learned that effective code review is not just about running tools or reading code line by line, but about connecting multiple perspectives. Misuse cases and threat models gave us the “why,” CWEs and tooling gave us the “what,” and our open source contribution plan gave us the “so what” in terms of concrete next steps. The most useful part of the assignment was experiencing that full pipeline from architectural reasoning to concrete findings and then to proposed changes for an active open source project. It reinforced that secure software engineering is an iterative, collaborative process that depends on both technical depth and clear communication, especially when dealing with systems like Marimo that are designed to execute arbitrary code by design.
