# Marimo – Level 1 Threat Modeling Report (Team 4)

This section documents the Level 1 Threat Modeling Report for the Marimo application, created as part of  
**CYBR 8420 – Designing for Software Security Engineering** under **Dr. Robin Gandhi**.

The report was generated using the **Microsoft Threat Modeling Tool (TM7)** and exported as an HTML artifact.  
We provide both the **HTML preview** (for full detail) and the **diagram snapshot** for quick reference.

---

## HTML Preview – Full Threat Modeling Report

Click below to view the fully rendered threat modeling report:

**HTML Preview:**  
https://htmlpreview.github.io/?https://github.com/os2594/Team4/blob/main/docs/4.Design/Marimo_Threat_Modeling_Report_Level1.htm

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

### **Level 1 Diagram**
![Marimo Level 1 Diagram](./Diagrams/Threat_Model_Diagram_Picture.png)

---
