# Part 1 - Top Level Claims

## Assurance Case: Execution Isolation in Marimo - Justin Tobiason

### 1. Overview

This assurance case focuses on **Execution Isolation** within the Marimo project.  
The goal is to evaluate whether Marimo’s notebook execution environment can effectively prevent **untrusted user code** from accessing host system resources.

Because Marimo executes arbitrary Python code inside interactive notebook cells, strong isolation controls are required to ensure user-level code cannot escape its intended runtime environment or compromise the underlying host system.  

This claim is critical because Marimo’s primary function—reactive code execution—presents inherent risks if isolation is incomplete or misconfigured.


### 2. Top-Level Claim (C1)

**C1:**  
*The execution environment prevents host resource access by untrusted code.*

**Intent:**  
This claim asserts that when a notebook is executed, it runs within a confined environment that protects the host system’s confidentiality, integrity, and availability.


### 3. Argument Summary

The argument to support this claim is structured around **three key assurance dimensions**:

1. **Systemic Isolation Controls:**  
   The system’s containerization and sandboxing features prevent untrusted code from escaping into the host.

2. **Configuration and Deployment Assurance:**  
   Security configurations (capabilities, mount restrictions, network policies) are actively managed and verified.

3. **Runtime Safeguards:**  
   Timeouts and resource limits restrict denial-of-service or covert channel attacks.

Each of these elements is supported by subclaims and tangible evidence, with corresponding rebuttals and refutations.

### 4. Diagram

![](https://github.com/os2594/Team4/blob/main/docs/3.AssuranceCases/Diagrams/Justin%20T%20-%20Assignment%203%20-%20Execution.drawio.png)

### 5. AI Summary
I was able to use AI to help expand on futhur rebuttals that could be assessed. By challenging my current claims I proposed my claims with the guidance on how to write a good claim by providing the criteria that make up a good claim. I was able to go from simple less direct claims to something that could provide a reasonable outcome. 

---

# Part 2 - Reflection

## Justin Tobiason
This assignment challenged my ability to question everything. I had to consider avenues that were not as obvious. Considering the depth of what was possible there is a certain threshhold for accuratly mitigating risk based on evidence in the project. 

The most valuable thing in this assignment was learning how to build out one of these diagrams. Wording each piece in a way that made sense and helped with the flow of each claim, rebuttal, evidence, inference, etc. 



