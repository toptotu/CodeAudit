// Package types defines the core data structures shared across all agents and subsystems.
package types

import "time"

// Severity represents the risk level of a finding.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// Category classifies findings by domain.
type Category string

const (
	CategoryGeneral    Category = "general"
	CategoryFramework  Category = "framework"
	CategoryDomain     Category = "domain"
	CategoryBusiness   Category = "business"
	CategoryCrypto     Category = "crypto"
	CategoryContainer  Category = "container"
	CategoryProtocol   Category = "protocol"
	CategoryConcurrency Category = "concurrency"
)

// Finding represents a single security issue discovered during audit.
type Finding struct {
	ID          string            `json:"id"`
	AgentID     string            `json:"agent_id"`
	SkillID     string            `json:"skill_id,omitempty"`
	Title       string            `json:"title"`
	Description string            `json:"description"`
	Severity    Severity          `json:"severity"`
	Category    Category          `json:"category"`
	FilePath    string            `json:"file_path"`
	Line        int               `json:"line"`
	Column      int               `json:"column"`
	CodeSnippet string            `json:"code_snippet,omitempty"`
	Suggestion  string            `json:"suggestion,omitempty"`
	References  []string          `json:"references,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	Confidence  float64           `json:"confidence"` // 0.0–1.0
	RuleID      string            `json:"rule_id,omitempty"`
}

// AuditTarget describes what to scan.
type AuditTarget struct {
	Path        string            `json:"path"`
	Module      string            `json:"module,omitempty"`
	Frameworks  []string          `json:"frameworks,omitempty"`
	Domains     []string          `json:"domains,omitempty"`
	SkipPaths   []string          `json:"skip_paths,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// AuditResult is the aggregated output from all agents.
type AuditResult struct {
	Target      AuditTarget `json:"target"`
	Findings    []*Finding  `json:"findings"`
	AgentResults []*AgentResult `json:"agent_results"`
	StartTime   time.Time   `json:"start_time"`
	EndTime     time.Time   `json:"end_time"`
	Duration    string      `json:"duration"`
	Summary     Summary     `json:"summary"`
}

// AgentResult is the output from a single agent run.
type AgentResult struct {
	AgentID   string     `json:"agent_id"`
	AgentName string     `json:"agent_name"`
	Findings  []*Finding `json:"findings"`
	Error     string     `json:"error,omitempty"`
	Duration  string     `json:"duration"`
	SkillsUsed []string  `json:"skills_used,omitempty"`
}

// Summary provides a statistical overview of findings.
type Summary struct {
	TotalFiles   int            `json:"total_files"`
	TotalFindings int           `json:"total_findings"`
	BySeverity   map[string]int `json:"by_severity"`
	ByCategory   map[string]int `json:"by_category"`
	ByAgent      map[string]int `json:"by_agent"`
	RiskScore    float64        `json:"risk_score"`
}

// SkillPattern defines a static code pattern for matching.
type SkillPattern struct {
	ID          string   `yaml:"id"`
	Name        string   `yaml:"name"`
	Pattern     string   `yaml:"pattern"`
	IsRegex     bool     `yaml:"is_regex"`
	IsAST       bool     `yaml:"is_ast"`
	Language    string   `yaml:"language"`
	Severity    Severity `yaml:"severity"`
	Description string   `yaml:"description"`
	Suggestion  string   `yaml:"suggestion"`
	References  []string `yaml:"references"`
	Tags        []string `yaml:"tags"`
}

// Skill encapsulates domain expert knowledge injectable into an agent.
type Skill struct {
	ID          string         `yaml:"id"`
	Name        string         `yaml:"name"`
	Version     string         `yaml:"version"`
	Domain      string         `yaml:"domain"`
	Description string         `yaml:"description"`
	Author      string         `yaml:"author"`
	Tags        []string       `yaml:"tags"`
	Patterns    []SkillPattern `yaml:"patterns"`
	Prompts     []SkillPrompt  `yaml:"prompts"`
	Rules       []SkillRule    `yaml:"rules"`
}

// SkillPrompt is a structured LLM prompt template injected into an agent.
type SkillPrompt struct {
	ID          string `yaml:"id"`
	Name        string `yaml:"name"`
	SystemMsg   string `yaml:"system_msg"`
	UserMsgTmpl string `yaml:"user_msg_tmpl"`
	Severity    Severity `yaml:"severity"`
	Category    Category `yaml:"category"`
}

// SkillRule is a semantic rule checked against parsed code context.
type SkillRule struct {
	ID          string   `yaml:"id"`
	Name        string   `yaml:"name"`
	Description string   `yaml:"description"`
	Severity    Severity `yaml:"severity"`
	Condition   string   `yaml:"condition"` // DSL expression
	Suggestion  string   `yaml:"suggestion"`
	References  []string `yaml:"references"`
}

// CodeContext holds parsed information about a Go source file.
type CodeContext struct {
	FilePath    string
	PackageName string
	Imports     []string
	Functions   []FuncInfo
	Types       []TypeInfo
	Constants   []ConstInfo
	Variables   []VarInfo
	RawSource   string
	Lines       []string
}

// FuncInfo holds metadata about a function.
type FuncInfo struct {
	Name       string
	Receiver   string
	Params     []string
	Returns    []string
	Line       int
	IsExported bool
	Body       string
}

// TypeInfo holds metadata about a type declaration.
type TypeInfo struct {
	Name       string
	Kind       string // struct, interface, alias
	Line       int
	IsExported bool
	Fields     []string
}

// ConstInfo holds metadata about a constant.
type ConstInfo struct {
	Name  string
	Value string
	Line  int
}

// VarInfo holds metadata about a variable declaration.
type VarInfo struct {
	Name  string
	Type  string
	Line  int
}
