# Part 1: Threat Modeling – Marimo Level 1 Threat Model (Team 4)

This section documents the Level 1 Threat Modeling Report for the Marimo application, created as part of  
**CYBR 8420 – Designing for Software Security Engineering** under **Dr. Robin Gandhi**.

The report was generated using the **Microsoft Threat Modeling Tool (TM7)** and exported as an HTML artifact.  
We provide both the **HTML preview** (for full detail) and the **diagram snapshot** for quick reference.

---

## HTML Preview – Full Threat Modeling Report

Click below to view the fully rendered threat modeling report:

**HTML Preview:**  
https://htmlpreview.github.io/?https://github.com/os2594/Team4/blob/main/docs/4.Design/Diagrams/Marimo_Threat_Modeling_Report.htm

> This preview contains the full STRIDE threat list, mitigations, assumptions, external dependencies,  
> and all auto-generated Microsoft Threat Modeling Tool content.

---

## Summary of What This Report Contains

The HTML report includes:

- High-Level System Description (Marimo architecture overview)  
- System assumptions and security boundaries  
- External dependencies  
- Full STRIDE threat enumeration  
- Mitigation justifications for each threat  
- Diagram summaries and data flow descriptions  
- Exported Microsoft TM7 data for professor review  

---

## Level 1 Data Flow Diagram (DFD)

Below is the visual representation of the Level 1 DFD used in our analysis.  
It captures the major architectural elements:

- External Web Client  
- Marimo Backend Server  
- Execution Sandbox  
- Internal File/Storage System  
- Internet and Storage Trust Boundaries  

## Microsoft TMT Project File (.tm7)

You can download the full TMT project file here:
[Level1_Marimo_Threat_Model_Diagram.tm7](./Diagrams/Level1_Marimo_Threat_Model_Diagram.tm7)

Below is a preview of the diagram contained in the `.tm7` file:

### **Level 1 Diagram**
![Marimo Level 1 Diagram](./Diagrams/Threat_Model_Diagram_Picture.png)

---

# Part 2: Observations, Collaborations, and Team Reflection

This section compares the mitigations expected from our threat model to what is actually implemented in the open-source Marimo project. It also includes our collaboration evidence and team reflection.

## Observations: Existing Security Controls in Marimo

During our review of Marimo’s open-source codebase and documentation, we identified several controls that align with the expected mitigations from our DFD-based threat analysis:

- **Execution Sandbox Isolation:**  
  Marimo executes user code inside a controlled Python runtime, preventing direct access to system resources.

- **Reactive Dependency Graph Execution:**  
  Marimo controls execution order and notebook state transitions, reducing the risk of unintended control-flow manipulation.

- **Limited File Access:**  
  File operations are scoped only to notebook-related assets.

- **Expected Deployment Behind HTTPS/TLS:**  
  Documentation assumes secure HTTPS endpoints, protecting confidentiality and integrity of client–server communication.

- **Frontend/Backend Separation:**  
  The UI only communicates through defined API routes, strengthening boundary enforcement.

- **Stateless API Behavior:**  
  Predictable backend endpoints reduce ambiguity and simplify threat modeling.

These controls address multiple threats across Spoofing, Tampering, and Elevation of Privilege categories.

## Gaps and Missing Mitigations

Our analysis also revealed that several critical security mitigations are **not** implemented directly by Marimo:

- **No Built-in Authentication or Authorization:**  
  Any user with access to the backend port can issue API commands. It's up to the organization to apply and implement the access controls.

- **No TLS Enforcement:**  
  Security depends entirely on the deployment environment and reverse proxy.

- **Minimal Logging & Audit Capabilities:**  
  Repudiation threats are insufficiently mitigated.

- **No Rate Limiting or Execution Throttling:**  
  Leaves Marimo vulnerable to resource exhaustion and DoS attacks.

- **Not OS-Level Sandboxed:**  
  Python-level sandboxing is not fully isolated (e.g., seccomp, namespaces, containers). This requires the infrastructure teams to implement a 'safe' environment.

- **Deployment-Specific Security Posture:**  
  Core mitigations depend on external infrastructure rather than Marimo itself.

These gaps represent the primary areas where Marimo differs from the ideal secure architecture defined in our threat model.

## Team Collaboration

Team 4 collaborated using a shared GitHub repository containing:

- TMT diagram files (`.tm7`)  
- HTML export of the threat model  
- Level 1 diagrams  
- Shared notes and design documents  
- Markdown documentation  
- Iterative updates and commit history
- Evaluating and resolving the potential risks

Team Repository Link:  
-> https://github.com/os2594/Team4

All work was coordinated through GitHub commits, messaging, and shared file editing.

## Individual Reflections
Below are the individual reflections from each team member based on the required questions:

**“What did you learn from this assignment?” and “What did you find most useful?”**

### **Justin Tobiason**
**What I learned:**
This assignment had it's challenges. Trying to evaluate the design of the application in the context of our use case made coming up with the level 1 diagram more of a controversial discussion regarding what does and does not belong. Once we dialed that in attempting to mitigate or deterime what wasn't applicaple in the analysis did require some thought as being a financial institution it seemed like most of these SHOULD be mitigated since our risk appetite is a lot less than other businesses would be interested in. 

**What I found most useful**
Using the Microsoft TMT tool was very valuable to me. I wasn't aware of the tool previous to this assignment so being able to get some hands on experience gave me something to add to the metaphorical tool box. Designing these diagrams and failing to capture exactly what I wanted the first couple rounds required me to reconsider the current solution for the problem. 

### **Osmar Carboney**
What I learned:
- How to apply STRIDE threat modeling to a real application architecture and map threats to trust boundaries.
- The differences between tool-generated mitigations and practical, deployment-dependent controls (such as the limits of Python-level sandboxing vs. OS/container isolation).
- The importance of balancing quick wins (TLS, auth tokens, rate limits) with structural guardrails (containerization, centralized auth, immutable logs).

What I found most useful:
- Using the Microsoft Threat Modeling Tool to generate and organize threats, then refining those findings with team discussion.
- Comparing the ideal mitigations from the model with Marimo’s actual implementation to identify actionable gaps (auth, TLS enforcement, logging).
- Learning concrete architectural controls (sandboxing strategies, per-user execution isolation, and auditability) that can be recommended to improve real deployments.
  
### **Preeti Timalsina**

### **Zaid Kakish**

### **Dominic Lanzante**
**What I learned:**  
From this assignment, I learned how to more clearly summarize Level 0 and Level 1 diagrams and how important it is to express system architecture at the right level of abstraction. I also became much more acquainted with the Microsoft Threat Modeling Tool. Although it felt difficult at first, once I understood the workflow and how the tool mapped threats to our diagrams, it became very intuitive and even enjoyable to use. This helped me build confidence in creating DFDs, interpreting threat outputs, and aligning them with our security requirements.

**What I found most useful:**  
The most useful part of this assignment was learning how the Level 1 diagram drives threat generation in TMT and how the tool highlights interactions across trust boundaries. Using the tool made the relationships between components, threats, and mitigations very clear. I also found it valuable to practice simplifying diagrams so they capture only what matters—this made the entire process smoother and aligned more directly with the goals of the assignment. Overall, getting hands-on experience with TMT made threat modeling feel far more approachable and practical.

## Team Reflection

**What we learned:**  
As a team, we gained practical experience in applying STRIDE using a real-world system. We learned how to map architectural components to trust boundaries and identify threats grounded in interactions between elements. The Microsoft TMT tool helped us better understand how threat modeling formalizes risk analysis.

**What we found most useful:**  
We found the automation of threat enumeration to be a helpful starting point, but the real value was in refining the relevance of each threat and determining appropriate mitigations. The exercise also strengthened our ability to analyze security gaps in OSS projects and improved our understanding of how architecture shapes security posture.

Overall, this assignment sharpened our skills in secure design, STRIDE analysis, and system-level reasoning key competencies for secure software engineering.

---

# Optional: AI-Assisted STRIDE Analysis (Per Interaction)

To enhance the threat modeling exercise, we applied AI-based STRIDE analysis to our Marimo Level 1 DFD.  
This aligns with the optional component and focuses on threats **per interaction** across trust boundaries.

## AI Prompt Used

The following prompt was used to generate the optional AI-assisted STRIDE analysis.  

"For the given Marimo Level 1 DFD diagram, apply STRIDE per Interaction.  
Focus only on interactions that cross a trust boundary, such as:

- External Web Client → Marimo Backend Server (API Requests)  
- Backend Server → External Web Client (API Responses)  
- Backend Server → Internal Storage (File Reads/Writes)  
- Internal Storage → Backend Server (Returned Notebook/Data)

For each interaction, enumerate plausible Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, and Elevation of Privilege threats.

For each threat, propose mitigations that align with Marimo’s architecture, not ones that fight against it.  
Your mitigation recommendations should include:

1. **Quick wins** that can be implemented immediately, and  
2. **Structural guardrails** that prevent entire classes of vulnerabilities at the architectural level.

Where appropriate, explain tradeoffs, constraints, and how Marimo’s trust boundaries shape the threat surface.

Finally, summarize global design guardrails that apply across all interactions such as authentication, sandboxing, authorization principles, logging patterns, or container isolation—that would prevent whole categories of issues rather than addressing them one at a time."


## STRIDE Analysis Per Interaction

For Marimo’s Level 1 architecture, the primary trust-boundary-crossing interactions are:

1. **External Web Client → Backend Server** (API Requests)  
2. **Backend Server → External Web Client** (API Responses)  
3. **Backend Server → Internal Storage System** (File Reads/Writes)  
4. **Internal Storage System → Backend Server** (File/Data Returned)

Below is a structured STRIDE-per-interaction analysis with mitigations aligned to the Marimo architecture.

---

### 1. Interaction: API Request (External Web Client → Backend Server)

#### Spoofing
An attacker may impersonate a legitimate user to send crafted API requests.  
**Mitigations:**  
- Require authentication/authorization before any cell execution or file operation.  
- Use session tokens or OAuth2-style bearer tokens (quick win).  
- **Structural guardrail:** centralized identity provider with token validation.

#### Tampering
User-controlled input (cell code, notebook state updates) may be modified in transit.  
**Mitigations:**  
- TLS 1.3 for all traffic.  
- Strict server-side input validation and allowlisting.  
- **Structural guardrail:** enforce server-centric business rules.

#### Repudiation
Users may deny executing certain code or issuing specific backend commands.  
**Mitigations:**  
- Authenticated request logs with timestamps and request hashing.  
- **Structural guardrail:** immutable audit storage.

#### Information Disclosure
Requests may contain sensitive notebook content.  
**Mitigations:**  
- Enforce HTTPS.  
- Avoid exposing sensitive identifiers in URLs.  
- **Structural guardrail:** data classification and access controls.

#### Denial of Service
Attackers may abuse execution endpoints.  
**Mitigations:**  
- Rate limiting and execution timeouts.  
- **Structural guardrail:** containerized per-user execution limits.

#### Elevation of Privilege
User code may escape sandbox boundaries.  
**Mitigations:**  
- Restricted Python runtime, no `eval`.  
- **Structural guardrail:** OS-level isolation (containers, seccomp).

---

### 2. Interaction: API Response (Backend Server → External Web Client)

#### Spoofing
Attackers may deliver fake pages or responses.  
**Mitigations:** TLS + HSTS; CSP.  
**Structural guardrail:** signed responses.

#### Tampering
Responses modified in transit.  
**Mitigations:** HTTPS integrity; checksums.

#### Repudiation
Backend denies sending data.  
**Mitigations:** Response logging; immutable logs.

#### Information Disclosure
Backend may leak another user’s notebook data.  
**Mitigations:** Per-record authorization checks.

#### Denial of Service
Attackers request large content repeatedly.  
**Mitigations:** Pagination; caching; async rendering.

#### Elevation of Privilege
Users access restricted fields via JS modifications.  
**Mitigations:** Enforce data-level authorization on API endpoints.

---

### 3. Interaction: File Operations (Backend → Internal Storage)

#### Spoofing
Backend may write to wrong storage location.  
**Mitigations:** Signed storage credentials; validated paths.

#### Tampering
User code may write/overwrite internal files.  
**Mitigations:** Path sanitation; workspace directory isolation.

#### Repudiation
Storage denies write occurred.  
**Mitigations:** File write logs; structured metadata.

#### Information Disclosure
Leaks through exposed paths.  
**Mitigations:** Path normalization; tokenized filenames.

#### DoS
Large writes fill disk.  
**Mitigations:** Quotas; async processing.

#### EoP
Backend file writes escalate privileges.  
**Mitigations:** Drop privileges; scoped permissions.

---

### 4. Interaction: Storage → Backend (Data Returned)

#### Spoofing
Fake files mimic notebooks.  
**Mitigations:** MIME validation.

#### Tampering
Files corrupted or maliciously modified.  
**Mitigations:** Hash validation; WORM storage.

#### Repudiation
Storage denies file return.  
**Mitigations:** Read logs with metadata.

#### Information Disclosure
Directory traversal exposes system files.  
**Mitigations:** Directory-based scoping; chroot.

#### DoS
Backend hangs on large/corrupt files.  
**Mitigations:** File size limits; staged reads.

#### EoP
Malicious file content injects privileges.  
**Mitigations:** Strict parsing; safe serialization.

---

## Structural Design Guardrails (Global Recommendations)

1. **Explicit Trust Boundaries via API Gateways**  
2. **Layered Defense (TLS, validation, WAF, logging, RBAC)**  
3. **Security-by-Design Frameworks**  
4. **Containerization & OS-Level Sandbox**  
5. **Centralized Authorization Policies**  
6. **Immutable Logging Systems**

---

## Summary of Optional AI Analysis

This AI-generated STRIDE-per-interaction analysis reveals deeper architectural threats beyond those produced by TMT, particularly around notebook execution, file handling, and cross-boundary communication.  
It complements the TM7 report by highlighting **structural mitigations**, **quick wins**, and **global guardrails** that strengthen Marimo’s security posture.

---
