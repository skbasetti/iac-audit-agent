# iac-audit-agent

> A LangGraph-based IaC governance agent that scans Terraform and Kubernetes manifests for security, cost, and compliance issues.

---

## Overview

`iac-audit-agent` is a flagship platform-engineering portfolio project that simulates a realistic governance tool used in modern cloud-native environments.

The agent autonomously scans Infrastructure-as-Code (IaC) files — Terraform plans and Kubernetes manifests — and produces structured reports covering:

- **Security risks** — exposed secrets, overly permissive IAM roles, missing network policies, privileged containers
- **Cost issues** — oversized instance types, untagged resources, missing auto-scaling policies
- **Tagging compliance** — enforces mandatory tag schemas (e.g., `env`, `owner`, `cost-center`, `team`)

---

## Motivation

Platform and DevOps engineers spend significant time manually reviewing IaC changes for policy violations. This project automates that review loop using an LLM-powered agent built with LangGraph, making governance fast, consistent, and auditable.

---

## Key Features

- Parses `.tf` (Terraform) and `.yaml`/`.yml` (Kubernetes) files
- Multi-step LangGraph agent with tool-calling for each check category
- Structured JSON output with severity levels (`critical`, `high`, `medium`, `low`)
- Modular rule engine — easy to add custom governance rules
- CLI interface for local use and CI/CD pipeline integration

---

## Tech Stack

| Layer | Technology |
|---|---|
| Agent Framework | LangGraph |
| LLM | Claude (Anthropic) |
| Language | Python 3.11+ |
| IaC Targets | Terraform, Kubernetes |
| Output | JSON / Markdown report |
| CI Integration | GitHub Actions (planned) |

---

## Project Status

> 🚧 In active development — this is a portfolio project showcasing platform engineering + AI agent design.

---

## Roadmap

- [ ] Terraform manifest parser
- [ ] Kubernetes manifest parser
- [ ] Security check agent node
- [ ] Cost check agent node
- [ ] Tagging compliance agent node
- [ ] LangGraph orchestration wiring
- [ ] CLI interface
- [ ] JSON + Markdown report output
- [ ] GitHub Actions CI integration
- [ ] Sample test fixtures (Terraform + K8s)

---

## Author

**skbasetti** — Platform Engineering | AI Agents | Cloud Infrastructure
