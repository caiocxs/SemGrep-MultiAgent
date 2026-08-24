# Generative Static Analysis with LLMs: Optimizing Vulnerability Detection in Semgrep via a Multi-Agent Approach

> **Bachelor's Thesis (Computer Science — SENAC Santo Amaro)**  
> **Author:** Caio Xavier da Silva[cite: 1]

---

## Overview

Traditional Static Application Security Testing (SAST) tools rely heavily on rigid, handcrafted logic, limiting scalability and the detection of corner cases[cite: 1]. Conversely, direct whole-codebase scanning using Large Language Models (LLMs) incurs quadratic computational complexity ($O(n^2)$) and carries risks of hallucination[cite: 1].

This project proposes an **LLM-based multi-agent framework** designed to **automatically synthesize, validate, and optimize static analysis rules for Semgrep**, specifically targeting critical memory-safety vulnerabilities (CWEs) in the **C programming language**[cite: 1].

---

## Target CWEs (C Language)

The framework focuses on five critical memory-management weaknesses[cite: 1]:

| CWE         | Description                                                                 |
| ----------- | --------------------------------------------------------------------------- |
| **CWE-401** | _Missing Release of Memory after Effective Lifetime_ (Memory Leak)[cite: 1] |
| **CWE-415** | _Double Free_[cite: 1]                                                      |
| **CWE-416** | _Use After Free (UAF)_[cite: 1]                                             |
| **CWE-457** | _Use of Uninitialized Variable_[cite: 1]                                    |
| **CWE-476** | _NULL Pointer Dereference_[cite: 1]                                         |

---

## Multi-Agent Architecture & Pipeline

The rule generation pipeline operates through an iterative feedback loop powered by four specialized LLM agents[cite: 1]:
