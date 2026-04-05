# API Specification — Q-Delegate

## 1. Protocol Overview

The Q-Delegate protocol defines how a client securely submits quantum computation jobs to a server and retrieves results. All messages must follow the defined schema and pass validation checks before processing.

---

## 2. Protocol Version

All messages must include:

```text
spec_version = "v0.5"
