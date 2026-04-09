package agent

import (
	"context"
	"fmt"
	"time"

	"github.com/codeaudit/codeaudit/internal/analyzer"
	"github.com/codeaudit/codeaudit/internal/llm"
	"github.com/codeaudit/codeaudit/pkg/types"
)

// BusinessLogicAgent is a fully skill-driven agent: it has no built-in static
// patterns. All its knowledge comes from domain-expert skill YAML files.
// This design allows security teams to encode proprietary business rules,
// industry-specific abuse patterns, and custom compliance checks without
// modifying any Go source code.
//
// Typical skill files for this agent:
//   - skills/business/payment.yaml    (PCI-DSS, amount manipulation)
//   - skills/business/auth-flow.yaml  (privilege escalation, MFA bypass)
//   - skills/business/rate-limit.yaml (abuse of business tiers)
//   - skills/business/inventory.yaml  (TOCTOU in stock checks)
type BusinessLogicAgent struct {
	BaseAgent
	llm llm.Client
}

func NewBusinessLogicAgent(llmClient llm.Client) *BusinessLogicAgent {
	return &BusinessLogicAgent{
		BaseAgent: NewBaseAgent(
			"golang-business",
			"Business Logic Security",
			"Skill-driven agent: detects business-logic vulnerabilities encoded in YAML skill files. No built-in patterns — all knowledge is imported from domain experts.",
			[]string{"business", "golang"},
		),
		llm: llmClient,
	}
}

func init() {
	Register(NewBusinessLogicAgent(llm.NewFromEnv()))
}

func (a *BusinessLogicAgent) Analyze(ctx context.Context, target *types.AuditTarget) (*types.AgentResult, error) {
	start := time.Now()
	result := &types.AgentResult{
		AgentID:    a.ID(),
		AgentName:  a.Name(),
		SkillsUsed: a.SkillsUsed(),
	}

	// This agent skips if no business skills are loaded.
	skillPatterns := a.GetSkillPatterns()
	skillPrompts := a.GetSkillPrompts()
	if len(skillPatterns) == 0 && len(skillPrompts) == 0 {
		result.Duration = time.Since(start).String()
		return result, nil
	}

	contexts, err := analyzer.ParseDir(target.Path, target.SkipPaths)
	if err != nil {
		return nil, fmt.Errorf("parsing target: %w", err)
	}

	// Static pattern matching from skills.
	for _, fileCtx := range contexts {
		for _, pat := range skillPatterns {
			findings := analyzer.MatchPattern(fileCtx, pat, a.ID())
			result.Findings = append(result.Findings, findings...)
		}
	}

	// LLM analysis driven by skill prompt templates.
	for _, fileCtx := range contexts {
		for _, prompt := range skillPrompts {
			llmFindings := a.runSkillPrompt(ctx, fileCtx, prompt)
			result.Findings = append(result.Findings, llmFindings...)
		}
	}

	result.Duration = time.Since(start).String()
	return result, nil
}

func (a *BusinessLogicAgent) runSkillPrompt(ctx context.Context, fileCtx *types.CodeContext, prompt types.SkillPrompt) []*types.Finding {
	src := fileCtx.RawSource
	if len(src) > 8000 {
		src = src[:8000] + "\n// [truncated]"
	}

	userMsg := fmt.Sprintf("File: %s\n\n```go\n%s\n```", fileCtx.FilePath, src)

	resp, err := a.llm.Complete(ctx, &llm.Request{
		SystemMsg: prompt.SystemMsg,
		UserMsg:   userMsg,
		MaxTokens: 2048,
	})
	if err != nil || resp == nil {
		return nil
	}
	findings := parseLLMFindings(resp.Content, fileCtx.FilePath, a.ID())
	// Tag findings with the originating skill prompt.
	for _, f := range findings {
		f.SkillID = prompt.ID
		if f.Category == "" {
			f.Category = types.CategoryBusiness
		}
	}
	return findings
}
