<div align="center">

# Phantasm-DB  
### *Autonomous Cognitive Deception Engine*

**An Active Defensive Database Architecture with Shadow Environment Redirection**

![version](https://img.shields.io/badge/version-1.0-blue.svg)
![database](https://img.shields.io/badge/database-PostgreSQL-blue.svg)
![security](https://img.shields.io/badge/security-Active--Deception-red.svg)
![backend](https://img.shields.io/badge/backend-Python-green.svg)

</div>

---

# Table of Contents

- [Project Overview](#project-overview)
- [Problem Statement](#problem-statement)
- [Architectural Innovation](#architectural-innovation)
- [System Architecture](#system-architecture)
- [Execution Workflow](#execution-workflow)
- [Technology Stack](#technology-stack)
- [Simulation Setup](#simulation-setup)
- [Expected Outcomes](#expected-outcomes)
- [Repository Structure](#repository-structure)
- [Installation](#installation)
- [Future Improvements](#future-improvements)
- [Project Team](#project-team)

---

# Project Overview

**Phantasm-DB** is a security-integrated relational database architecture designed to protect sensitive systems using **active deception-based defense**.

Instead of blocking attackers immediately, suspicious users are silently redirected into a **shadow database environment** containing synthetic data.

## Key Goals

- Protect real production data  
- Observe attacker behavior  
- Generate forensic evidence  
- Reduce real data exposure  

---

# Problem Statement

Traditional database security models rely on **static access control**.

## Limitations

- **Static Trust Model**  
  Authenticated users are trusted automatically.

- **Weak Logging Systems**  
  Logs may be modified or deleted.

- **Immediate Data Exposure**  
  Attackers gain full access after breach.

- **High Data Exfiltration Risk**  
  Sensitive data becomes vulnerable.

---

# Architectural Innovation

## Intruder Identification Engine

Detection occurs using multiple techniques.

### Signature-Based Detection

Example malicious patterns:

### Honey-Token Detection

Decoy records trigger alerts when accessed.

### Behavioral Monitoring

Tracks:

- Query frequency  
- Execution speed  
- Access timing  

---

## Schema Swap Mechanism

When risk exceeds threshold:

```sql
SET search_path TO shadow_vault, public
