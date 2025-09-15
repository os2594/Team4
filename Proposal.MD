# 📝 Project Proposal: Marimo

---

## 🌟 Introduction

Marimo is a modern, **reactive Python notebook environment** designed to improve upon traditional tools like Jupyter.  
Unlike conventional notebooks that often suffer from hidden state and reproducibility issues, Marimo emphasizes:

- **Reproducibility**: All notebooks are stored as pure Python (`.py`) files, making them transparent, version-controllable, and auditable.  
- **Reactive Execution**: A built-in dependency graph ensures that when a cell changes, all dependent cells are automatically re-executed. This eliminates hidden state and reduces user error.  
- **Deployment Flexibility**: Notebooks can run in “edit mode” for developers, “read-only mode” for safe sharing, or even fully in-browser using WebAssembly (Pyodide).  
- **Security Awareness**: Features such as token-based access, TLS/SSL support, encrypted backups, and custom authentication middleware make it suitable for sensitive environments where trust and assurance matter.  

Marimo is actively developed and widely adopted in research, education, and enterprise data science workflows. Its focus on **assurance, transparency, and collaboration** makes it a strong candidate for evaluating real-world security needs in multi-user, enterprise, and regulated environments.

---

## 📌 Repository & Collaboration
- **Team Repository Link:** [Insert your team’s GitHub repo link here]
- **Project Board:** [Insert GitHub Project Board link here]  
  (Tasks, issues, and cards linked to this board for progress tracking.)

---

## 🏢 Hypothetical Operational Environment
Describe the enterprise, hospital, government, or research setting in which Marimo will be deployed, focusing on how users expect security functionality.

- The hypothetical environment chosen for this project is a Bank, where users would use Marimo software as an enterprise analytics software.

- A bank's analytics team uses Marimo as a tool to process financial and customer data. In this situation the security features expected are sensitive data must remain confidential and in some cases encrypted depending on the type of data. The audit logs must be tracked to ensure proper utilization and access management policies. In case of any apps or software were linked to the tool, proper authentication must happen so that only authorized members are able to access data and environment.
---

## 🖥️ Systems Engineering View
Provide a diagram and narrative describing how Marimo fits into the environment:
Diagram here

---

## 🔐 Security Needs, Threats, and Features
- **Security Needs**: Identify what organizations require from Marimo in this environment (e.g., confidentiality, integrity, auditability).
- **Threats**: List potential risks perceived by users (e.g., unauthorized access, data leakage, malicious code execution).
- **Security Features**: Summarize the features already present in Marimo that address these needs (auth, TLS, hidden state elimination, etc.).

---

## 🎯 Team Motivation
Explain why your group selected Marimo:
- Popularity and active development
- Enterprise or educational use cases
- Clear security considerations
- Rich opportunities for assurance analysis

---

## 📖 OSS Project Description
Provide background on Marimo as an open-source project:
- **What is it?**
- **Contributors and community activity**
- **Popularity (stars, forks, adoption)**
- **Languages and platform**
- **Documentation sources**

---

## 📜 License Summary & Contribution Agreement
Summarize:
- Marimo’s license type (Apache 2.0)
- Contribution process (issues, pull requests, `good first issue` labels)
- Contributor agreements or CLA requirements

---

## 🕵️ Security History
Briefly cover:
- Any known vulnerabilities
- Security-relevant design decisions (e.g., hidden state elimination, `.py` file format)
- Past or ongoing enhancements related to security

---

## 📋 Project Planning, Tracking & Reflection
- **Planning & Tracking**: Use GitHub Project Board to assign tasks, link issues, and monitor progress.
- **Reflection**: Each member adds an individual reflection:
  - What did I learn from this assignment?
  - What was most useful to me?  
- **Team Reflection**: Compile into one section showing group learning outcomes.

---

# Contributing to the Marimo Project

The **Marimo project** uses the **Apache License Version 2.0**.  
This license defines the spirit of open-source software, allowing us to contribute and make changes freely.  

By leveraging this license, our team can contribute effectively, complete analysis, and improve software assurance.  

### What This License Allows
- **Use it freely**: You can use the software for personal, educational, or commercial purposes without needing permission or paying royalties.  
- **Modify it**: You can change the source code however you like.  
- **Distribute it**: You can share the original or your modified version.  
- **Sell it**: You can use it in a product you sell (including closed-source products), if you follow the rules.  
- **Sublicense**: You can bundle it with other software, including proprietary software.  

**License**: [Apache License 2.0](https://github.com/marimo-team/marimo/blob/main/LICENSE)

---

## Code of Conduct

The **Code of Conduct** outlines expectations for collaboration and contribution.  
It emphasizes being **respectful, kind, and open**.  

### Maintainers’ Responsibilities
- Project maintainers can set and enforce rules.  
- They may remove, edit, or reject contributions, and enforce commitments against the project.  

As a team, we must follow all rules associated with Marimo to remain in compliance.

### Reporting Issues
- If you encounter misconduct or issues, you can report them.  
- Use the official contact email: **contact@marimo.io**.  

**Code of Conduct**: [Contributor Covenant](https://github.com/marimo-team/marimo/blob/main/CODE_OF_CONDUCT.md)

---

## Contribution Guidelines

Contributing is defined in the **CONTRIBUTING.md** file.  
The project accepts **code, tests, documentation, bug fixes, and even typo corrections**.  

### Before Submitting a Pull Request
You are expected to:
- Run linting, typechecking, and formatting → make sure your code follows style rules.  
- Write tests for your code.  
- Run all tests to ensure nothing breaks.  
- Read and sign the **Contributor License Agreement (CLA)**.  

The documentation also provides setup instructions and common commands.  
You are expected to:
- Keep code clean and consistent.  
- Follow good programming practices (e.g., **single responsibility principle**).  
- Write and run regression tests with **Playwright scripts**.  

### Contributor License Agreement (CLA)
- You must state that you have read and signed the CLA on your **first pull request**.  
- The CLA gives Marimo the right to use your contributions forever.  
- You confirm that:
  - You have the legal rights to contribute.  
  - Any third-party code references are disclosed.  
  - Contributions are provided **“as is”** without warranty or obligation for future support.  

**CLA**: [Contributor License Agreement](https://marimo.io/cla)  
**Contributing Guide**: [CONTRIBUTING.md](https://github.com/marimo-team/marimo/blob/main/CONTRIBUTING.md)


