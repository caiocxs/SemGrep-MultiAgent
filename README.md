# Generative Static Analysis with LLMs: Optimizing Vulnerability Detection in Semgrep via a Multi-Agent Approach

> **Bachelor's Thesis (Computer Science — SENAC Santo Amaro)**  
> **Author:** Caio Xavier da Silva

---

## Overview

Traditional Static Application Security Testing (SAST) tools rely heavily on rigid, handcrafted logic, limiting scalability and the detection of corner cases. Conversely, direct whole-codebase scanning using Large Language Models (LLMs) incurs quadratic computational complexity ($O(n^2)$) and carries risks of hallucination.

This project proposes an **LLM-based multi-agent framework** designed to **automatically synthesize, validate, and optimize static analysis rules for Semgrep**, specifically targeting critical memory-safety vulnerabilities (CWEs) in the **C programming language**.

---

## Target CWEs (C Language)

The framework focuses on five critical memory-management weaknesses

| CWE         | Description                                                        |
| ----------- | ------------------------------------------------------------------ |
| **CWE-401** | _Missing Release of Memory after Effective Lifetime_ (Memory Leak) |
| **CWE-415** | _Double Free_                                                      |
| **CWE-416** | _Use After Free (UAF)_                                             |
| **CWE-457** | _Use of Uninitialized Variable_                                    |
| **CWE-476** | _NULL Pointer Dereference_                                         |

---

## Multi-Agent Architecture & Pipeline

The rule generation pipeline operates through an iterative feedback loop powered by four specialized LLM agents
