---
name: Security report
about: Report a security vulnerability in actenon-scan itself (NOT a vulnerability in a scanned repo)
title: "[Security] "
labels: ["security"]
assignees: []
---

## ⚠️ Do NOT open public issues for security vulnerabilities

If you have found a vulnerability **in actenon-scan itself** (e.g., the
scanner can be crashed, made to skip files, or made to produce
false-negatives by a malicious scanned file), please use **private
vulnerability reporting** instead:

👉 https://github.com/Actenon/actenon-scan/security/advisories/new

Or email: **security@actenon.dev**

## What this issue template is FOR

Use this template for **security-related questions** that are NOT
vulnerability disclosures, e.g.:

- Asking about the scanner's threat model
- Asking about the security of actenon-scan's dependencies
- Asking about the security of the GitHub Action
- Asking about hardening recommendations for org-wide rollout

## What to include

- A clear description of your question
- The context you're evaluating actenon-scan in (org size, industry, existing SAST tooling)
- Any specific threat model concerns

## Response time

- Security questions: 5 business days
- Vulnerability disclosures (via private channel): 48 hours acknowledgement, 90 days for a fix
