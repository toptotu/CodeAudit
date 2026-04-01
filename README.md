# CodeAudit

**Multi-agent, skill-orchestrated Golang security audit system.**

Inspired by the oh-my-opencode architecture, CodeAudit brings a composable
multi-agent pipeline to Golang security analysis. Domain-expert knowledge is
encoded in pluggable YAML skill files and injected into specialized agents at
runtime — no recompilation needed to add new vulnerability patterns or business
rules.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                        CLI  (codeaudit scan)                        │
└──────────────────────────────┬──────────────────────────────────────┘
                               │  AuditTarget
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         Orchestrator                                │
│                                                                     │
│  1. Load skills from YAML dirs (skill.Registry)                     │
│  2. Select agents by domain + framework tags                        │
│  3. Inject matching skills into each agent                          │
│  4. Run agents in parallel (bounded goroutine pool)                 │
│  5. Aggregate & deduplicate findings                                │
│  6. Compute risk score                                              │
└──────┬──────────┬──────────┬──────────┬──────────┬─────────────────┘
       │          │          │          │          │
       ▼          ▼          ▼          ▼          ▼
  ┌─────────┐ ┌───────┐ ┌───────┐ ┌────────┐ ┌──────────┐ ...
  │ General │ │Crypto │ │Frame- │ │Contain-│ │CT Proto- │
  │ Golang  │ │Security│ │work   │ │er/K8s  │ │col (RFC  │
  │ Agent   │ │Agent  │ │Agent  │ │Agent   │ │6962/9162)│
  └────┬────┘ └───┬───┘ └───┬───┘ └───┬────┘ └────┬─────┘
       │          │         │          │            │
       └──────────┴─────────┴──────────┴────────────┘
                            │
                    ┌───────┴────────┐
                    │  Each agent    │
                    │                │
                    │ ① AST Parse    │──► Go source files
                    │ ② Static Match │──► Built-in + Skill patterns
                    │ ③ LLM Analyze  │──► OpenAI / compatible API
                    └───────┬────────┘
                            │
                    ┌───────▼────────┐
                    │  Skill System  │
                    │                │
                    │ YAML skills/   │
                    │ ├── golang/    │  general security
                    │ ├── framework/ │  gin, grpc, echo...
                    │ ├── domain/    │  ct, container...
                    │ └── business/  │  payment, auth...
                    └───────┬────────┘
                            │
                    ┌───────▼────────┐
                    │    Reporter    │
                    │                │
                    │  Text · JSON   │
                    │  Markdown      │
                    │  SARIF 2.1.0   │
                    └────────────────┘
```

---

## Agents

| ID | Name | Covers |
|----|------|--------|
| `golang-general` | Golang General Security | SQL injection, SSRF, command injection, path traversal, hardcoded secrets, weak crypto, goroutine leaks, TLS misconfig |
| `golang-crypto` | Cryptography Security | ECB mode, static IV/nonce, CBC padding oracle, weak RSA keys, JWT none-alg, PBKDF2 iteration count, timing attacks |
| `golang-framework` | Golang Framework Security | Gin, Echo, Fiber, gRPC, go-zero, chi — CORS, missing middleware, debug mode, reflection, rate limiting |
| `golang-container` | Container Security | Docker SDK privileged mode, host namespaces, Docker socket, K8s RBAC wildcards, missing seccomp, resource limits |
| `golang-ct-protocol` | CT Protocol Security | SCT forgery, Merkle tree attacks, STH verification, Log ID validation, timestamp bounds, split-view attacks |
| `golang-concurrency` | Concurrency Security | Race conditions, mutex copy, WaitGroup misuse, nil channel ops, context cancel leak, deadlocks |
| `golang-business` | Business Logic Security | **Skill-driven only** — IDOR/BOLA, payment races, float currency, MFA bypass, admin flag injection |

---

## Skill System

Skills are YAML files that encode domain-expert knowledge without modifying
Go source code. Each skill contains:

```
skills/
├── golang/
│   └── general.yaml          # Core Golang security patterns + LLM prompts
├── framework/
│   ├── gin_security.yaml     # Gin-specific patterns + LLM prompt
│   └── grpc_security.yaml    # gRPC patterns + LLM prompt
├── domain/
│   ├── ct_protocol.yaml      # Certificate Transparency (RFC 6962) patterns
│   └── container_security.yaml  # Docker/K8s patterns
└── business/
    ├── payment.yaml          # PCI-DSS, amount manipulation, TOCTOU
    └── auth_flow.yaml        # IDOR, privilege escalation, MFA bypass
```

### Skill YAML anatomy

```yaml
id: my-skill                      # unique identifier
name: "My Expert Skill"
version: "1.0.0"
domain: "my-domain"               # matches agent SupportedDomains
tags: [my-domain, framework]      # additional injection tags

patterns:                         # static matching (no LLM needed)
  - id: rule-001
    name: "Dangerous Pattern"
    pattern: 'someFunc\('         # regex or literal
    is_regex: true
    severity: HIGH
    description: "Why it's bad"
    suggestion: "How to fix it"
    references: ["CWE-123"]
    tags: [my-domain]

prompts:                          # LLM-assisted analysis
  - id: llm-prompt-001
    name: "Deep LLM Review"
    system_msg: |
      You are a domain expert. Find vulnerabilities.
      Format: FINDING: / SEVERITY: / LINE: / DESCRIPTION: / SUGGESTION: / ---
    user_msg_tmpl: |
      File: {{.FilePath}}
      ```go
      {{.Source}}
      ```
```

### Adding a new domain skill (zero Go code)

```bash
cat > skills/domain/my_domain.yaml << 'EOF'
id: my-domain-skill
name: "My Domain Expert"
version: "1.0.0"
domain: my-domain
tags: [my-domain]

patterns:
  - id: my-rule-001
    name: "Dangerous API Call"
    pattern: 'dangerousFunc\('
    is_regex: true
    severity: HIGH
    description: "This function is dangerous because..."
    suggestion: "Use safeFunc() instead."

prompts:
  - id: my-llm-001
    name: "My Domain LLM Review"
    system_msg: |
      You are an expert in my domain. Find vulnerabilities.
      ...
    user_msg_tmpl: "File: {{.FilePath}}\n```go\n{{.Source}}\n```"
EOF

codeaudit scan ./myproject --domains my-domain --skills ./skills/
```

---

## Installation

```bash
# From source
git clone https://github.com/codeaudit/codeaudit
cd codeaudit
go build -o codeaudit ./cmd/codeaudit
sudo mv codeaudit /usr/local/bin/

# Verify
codeaudit list
```

---

## Usage

```bash
# Basic scan (static patterns only)
codeaudit scan ./myproject --no-llm

# Full scan with AI analysis
OPENAI_API_KEY=sk-... codeaudit scan ./myproject

# Target specific domains
codeaudit scan ./myproject --domains ct,container,crypto

# Framework-aware scan
codeaudit scan ./myproject --frameworks gin,grpc

# Markdown report for review
codeaudit scan ./myproject --format markdown --output report.md

# SARIF for GitHub Advanced Security / Defect Dojo
codeaudit scan ./myproject --format sarif --output results.sarif

# JSON for programmatic consumption
codeaudit scan ./myproject --format json --output findings.json

# Load custom business skills
codeaudit scan ./myproject --skills ./company-skills/ --domains business

# Parallel workers for large codebases
codeaudit scan ./myproject --workers 16 --verbose

# Run only specific agents
codeaudit scan ./myproject --agents golang-general,golang-crypto
```

---

## Configuration File

Place `.codeaudit.yaml` in your project root:

```yaml
llm:
  provider: openai
  model: gpt-4o
  max_tokens: 2048
  temperature: 0.2

scan:
  skill_dirs:
    - ./skills
    - ./company-skills
  enabled_domains:
    - ct
    - container
    - crypto
  frameworks:
    - gin
    - grpc
  skip_paths:
    - vendor
    - testdata
    - .git
  max_workers: 8

report:
  format: markdown
  output: security-report.md
  verbose: false

log_level: info
```

---

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Audit
on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Go
        uses: actions/setup-go@v5
        with: { go-version: '1.22' }

      - name: Build CodeAudit
        run: go build -o codeaudit ./cmd/codeaudit

      - name: Run audit (SARIF)
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
        run: ./codeaudit scan . --format sarif --output results.sarif
        continue-on-error: true   # let next step upload even on findings

      - name: Upload SARIF to GitHub Security tab
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

---

## Multi-Agent Design Principles

### 1. Agent = Domain Expert + Skill Consumer

Each agent owns a narrow domain. It ships with built-in static patterns for
the most common issues, then **augments** its analysis with whatever skills
are injected at runtime. This means:

- A `golang-general` agent can receive a custom `finance-injection.yaml` skill
  that adds payment-specific SQL injection patterns without any code change.
- The `golang-business` agent ships with **zero** built-in patterns — it is
  100% skill-driven, embodying the pure "expert experience import" model.

### 2. Skill Injection by Domain Tag

```
Orchestrator                  Skill Registry
     │                              │
     │  agent.SupportedDomains()    │
     │  → ["ct", "protocol", "tls"] │
     │──────────────────────────────►│
     │  skill.ByDomain("ct")        │
     │  skill.ByDomain("protocol")  │
     │◄──────────────────────────────│
     │  [ct-protocol-expert,        │
     │   tls-hardening, ...]        │
     │                              │
     │  agent.InjectSkills(skills)  │
```

### 3. Two Complementary Analysis Modes

```
Static Pattern Matching          LLM-Assisted Analysis
─────────────────────────────    ─────────────────────────────────────
• Deterministic, fast            • Non-deterministic, thorough
• Works offline                  • Requires API key
• No false negative on known     • Catches novel/contextual issues
  patterns                       • Understands multi-line data flows
• Regex + literal + AST modes    • Skill prompts inject domain context
• No API cost                    • Configurable per-file trigger
```

### 4. The Business Logic Agent Pattern

The `golang-business` agent demonstrates a key design insight: **business
logic vulnerabilities cannot be statically enumerated** because they depend
on the application's specific domain model. Instead:

1. Security team writes `skills/business/myapp-rules.yaml` with LLM prompts
   describing the application's expected invariants.
2. The agent runs each prompt template against every Go source file.
3. The LLM reasons about whether the code violates those invariants.

This gives you the equivalent of a senior security engineer who knows your
specific application's business rules reviewing every file.

---

## Extending the System

### Adding a New Agent (code path)

1. Create `internal/agent/myagent.go`:

```go
package agent

import (
    "context"
    "github.com/codeaudit/codeaudit/internal/llm"
    "github.com/codeaudit/codeaudit/pkg/types"
)

type MyAgent struct {
    BaseAgent
    llm llm.Client
}

func NewMyAgent(llmClient llm.Client) *MyAgent {
    return &MyAgent{
        BaseAgent: NewBaseAgent(
            "my-agent",
            "My Domain Agent",
            "Detects XYZ vulnerabilities",
            []string{"my-domain", "golang"},
        ),
        llm: llmClient,
    }
}

// Auto-register on package import.
func init() { Register(NewMyAgent(llm.NewFromEnv())) }

func (a *MyAgent) Analyze(ctx context.Context, target *types.AuditTarget) (*types.AgentResult, error) {
    // 1. Parse AST
    // 2. Match built-in + skill patterns
    // 3. Run LLM on interesting files
    // 4. Return AgentResult
}
```

2. Import in `cmd/codeaudit/commands/scan.go`:
```go
_ "github.com/codeaudit/codeaudit/internal/agent"
```

No orchestrator changes needed — the `init()` auto-registers the agent.

---

## Output Formats

| Format | Use Case |
|--------|----------|
| `text` | Terminal review during development |
| `json` | Programmatic consumption, dashboards |
| `markdown` | PR reviews, security reports, Confluence |
| `sarif` | GitHub Advanced Security, Defect Dojo, SonarQube |

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Scan complete, no HIGH/CRITICAL findings |
| `1` | HIGH or CRITICAL findings detected (use in CI gates) |

---

## Project Structure

```
codeaudit/
├── cmd/
│   └── codeaudit/
│       ├── main.go
│       └── commands/
│           ├── root.go        # cobra root command
│           ├── scan.go        # scan subcommand + orchestrator wiring
│           └── list.go        # list agents subcommand
├── internal/
│   ├── agent/
│   │   ├── agent.go           # Agent interface + BaseAgent
│   │   ├── registry.go        # global agent registry
│   │   ├── golang_general.go  # General Golang security agent
│   │   ├── framework_agent.go # Gin/Echo/Fiber/gRPC/go-zero agent
│   │   ├── crypto_agent.go    # Cryptographic security agent
│   │   ├── container_agent.go # Container/K8s security agent
│   │   ├── ct_protocol_agent.go # CT protocol (RFC 6962) agent
│   │   ├── concurrency_agent.go # Race/deadlock/goroutine agent
│   │   └── business_agent.go  # Skill-driven business logic agent
│   ├── orchestrator/
│   │   └── orchestrator.go    # Parallel execution + skill injection
│   ├── skill/
│   │   └── skill.go           # YAML loader + skill registry
│   ├── analyzer/
│   │   └── ast.go             # Go AST parser + pattern matcher
│   ├── llm/
│   │   └── client.go          # OpenAI client + stub
│   ├── report/
│   │   └── report.go          # JSON/Markdown/SARIF/Text generators
│   └── config/
│       └── config.go          # Viper-based configuration
├── pkg/
│   └── types/
│       └── types.go           # Shared data structures
├── skills/                    # Built-in domain expert skill files
│   ├── golang/
│   │   └── general.yaml
│   ├── framework/
│   │   ├── gin_security.yaml
│   │   └── grpc_security.yaml
│   ├── domain/
│   │   ├── ct_protocol.yaml
│   │   └── container_security.yaml
│   └── business/
│       ├── payment.yaml
│       └── auth_flow.yaml
├── testdata/
│   └── samples/
│       └── vulnerable.go      # Intentionally vulnerable test file
└── go.mod
```

---

## Security Finding Schema

```json
{
  "id": "uuid",
  "agent_id": "golang-crypto",
  "skill_id": "ct-protocol-expert",
  "rule_id": "crypto-static-iv",
  "title": "Static/Hardcoded IV",
  "description": "...",
  "severity": "CRITICAL",
  "category": "crypto",
  "file_path": "pkg/crypto/aes.go",
  "line": 42,
  "column": 0,
  "code_snippet": "iv := []byte{0x00, 0x01, ...}",
  "suggestion": "Generate IV with crypto/rand per encryption operation.",
  "references": ["CWE-330"],
  "confidence": 0.85,
  "metadata": {}
}
```

---

## Roadmap

- [ ] `codeaudit explain <finding-id>` — LLM-generated exploit scenario + fix
- [ ] `codeaudit diff` — only scan files changed in a PR
- [ ] `codeaudit skill pull <registry-url>` — download community skills
- [ ] Taint analysis engine for precise data-flow tracking
- [ ] Semgrep rule import for pattern migration
- [ ] VS Code extension with inline findings
- [ ] MCP (Model Context Protocol) server mode for IDE agent integration
