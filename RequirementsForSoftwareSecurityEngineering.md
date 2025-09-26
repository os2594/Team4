**Requirements For SoftwareSecurity Engineering**

**Data exfiltration diagram**

**Internal Misuse Case:** Rogue Employee

A financial analyst with elevated access uses Marimo to query sensitive customer data and exports it via an 						unmonitored notebook deployment.

* **Threat** : Data exfiltration
* **Aggravating Factors** : Loose access controls
* **Mitigation** : Strict RBAC, access logging, deployment review workflows.

**External Misuse Case:** External attacker

An attacker discovers a misconfigured Marimo notebook deployed as a public web app and uses SQL injection to access backend financial data.

* **Threat** : Unauthorized data access
* **Aggravating Factors** : Unvalidated inputs
* **Mitigation** : Input sanitization

![](assets/data_exfilitration_diagram.drawio.svg)

**List of security requirements derived from data exfiltration analysis**

Derived from the internal (rogue employee) and external (hacker via SQL injection) misuse scenarios, these requirements ensure Marimo in a financial institution resists data-exfiltration:

1. **SR-1: Role-Based Access Control (RBAC)**
   The system shall restrict notebook export and data-download capabilities to explicitly authorized roles. Export attempts by users without the `Data export` privilege must be denied.
2. **SR-2: Immutable Audit Logging**
   Log every notebook execution, SQL query, and export action—capturing user ID, timestamp, query parameters—in immutable logs retained for at least 180 days.
3. **SR-3: Data Leakage Prevention (DLP) Scanning**
   Prior to any export, scan payloads for regulated or high-sensitivity fields (e.g., SSNs, credit cards). Matches must block the export and trigger a security alert.

4.  **SR-4: Input Validation & Parameterized Queries**
   All SQL cell executions shall use parameterized queries. User inputs must be sanitized or bound as parameters to eliminate injection vectors.

**Alignment with Marimo’s Advertised Features**

* **Authentication & RBAC** : Marimo offers token abstractions (`AuthToken`) and ASGI middleware hooks, but does not ship with enterprise SSO, RBAC, or MFA integrations. Maybe these implementations are done through an other environment that Institutions must put in place.
* **Input sanitization** : While Marimo’s SQL cells can leverage parameterized drivers, there is no enforcement mechanism to prevent raw string concatenation—placing the onus on notebook authors.
