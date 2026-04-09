package agent

import (
	"context"
	"fmt"
	"time"

	"github.com/codeaudit/codeaudit/internal/analyzer"
	"github.com/codeaudit/codeaudit/internal/llm"
	"github.com/codeaudit/codeaudit/pkg/types"
)

// ConcurrencyAgent audits Go concurrency patterns for race conditions,
// deadlocks, goroutine leaks, channel misuse, and sync primitive abuse.
type ConcurrencyAgent struct {
	BaseAgent
	llm llm.Client
}

func NewConcurrencyAgent(llmClient llm.Client) *ConcurrencyAgent {
	return &ConcurrencyAgent{
		BaseAgent: NewBaseAgent(
			"golang-concurrency",
			"Concurrency Security",
			"Detects race conditions, deadlocks, goroutine leaks, mutex misuse, and unsafe channel operations in Go code.",
			[]string{"concurrency", "golang"},
		),
		llm: llmClient,
	}
}

func init() {
	Register(NewConcurrencyAgent(llm.NewFromEnv()))
}

func (a *ConcurrencyAgent) Analyze(ctx context.Context, target *types.AuditTarget) (*types.AgentResult, error) {
	start := time.Now()
	result := &types.AgentResult{
		AgentID:    a.ID(),
		AgentName:  a.Name(),
		SkillsUsed: a.SkillsUsed(),
	}

	contexts, err := analyzer.ParseDir(target.Path, target.SkipPaths)
	if err != nil {
		return nil, fmt.Errorf("parsing target: %w", err)
	}

	allPatterns := append(a.builtinPatterns(), a.GetSkillPatterns("concurrency")...)

	for _, fileCtx := range contexts {
		for _, pat := range allPatterns {
			findings := analyzer.MatchPattern(fileCtx, pat, a.ID())
			result.Findings = append(result.Findings, findings...)
		}

		if a.hasConcurrencyCode(fileCtx) {
			llmFindings := a.runLLMAnalysis(ctx, fileCtx)
			result.Findings = append(result.Findings, llmFindings...)
		}
	}

	result.Duration = time.Since(start).String()
	return result, nil
}

func (a *ConcurrencyAgent) hasConcurrencyCode(ctx *types.CodeContext) bool {
	for _, imp := range ctx.Imports {
		if imp == "sync" || imp == "sync/atomic" || imp == "runtime" {
			return true
		}
	}
	for _, line := range ctx.Lines {
		if len(line) > 2 && (line[:2] == "go" || containsStr(line, "chan ") || containsStr(line, "sync.")) {
			return true
		}
	}
	return false
}

func (a *ConcurrencyAgent) runLLMAnalysis(ctx context.Context, fileCtx *types.CodeContext) []*types.Finding {
	systemMsg := `You are a Go concurrency security expert. Analyze for:
- Data races: shared variables accessed concurrently without synchronization
- Mutex copy: passing sync.Mutex by value (should be pointer)
- Double lock: calling Lock() twice on the same mutex without Unlock()
- Lock/defer ordering issues: defer mu.Unlock() after fallible operations
- Channel deadlock: sending to an unbuffered channel with no receiver
- Goroutine leak: goroutine that never exits (missing ctx.Done or close signal)
- sync.WaitGroup misuse: Add called inside goroutine, or Delta goes negative
- atomic misuse: partial reads of multi-word structs without full atomic coverage
- Context leak: context.WithCancel cancel func never called

Format each finding exactly as:
FINDING: <title>
SEVERITY: <CRITICAL|HIGH|MEDIUM|LOW|INFO>
LINE: <line>
DESCRIPTION: <description>
SUGGESTION: <suggestion>
---`

	src := fileCtx.RawSource
	if len(src) > 8000 {
		src = src[:8000] + "\n// [truncated]"
	}
	userMsg := fmt.Sprintf("File: %s\n\n```go\n%s\n```", fileCtx.FilePath, src)

	resp, err := a.llm.Complete(ctx, &llm.Request{
		SystemMsg: systemMsg,
		UserMsg:   userMsg,
		MaxTokens: 2048,
	})
	if err != nil || resp == nil {
		return nil
	}
	return parseLLMFindings(resp.Content, fileCtx.FilePath, a.ID())
}

func (a *ConcurrencyAgent) builtinPatterns() []types.SkillPattern {
	return []types.SkillPattern{
		{
			ID: "conc-mutex-copy", Name: "Mutex Copied by Value", IsRegex: true,
			Pattern:     `sync\.Mutex\b[^*]`,
			Severity:    types.SeverityHigh,
			Description: "Copying a sync.Mutex by value invalidates its internal state and causes undefined behavior.",
			Suggestion:  "Always use a pointer to sync.Mutex: *sync.Mutex or embed it by value in a struct and never copy the struct.",
			References:  []string{"Go docs: sync.Mutex"},
			Tags:        []string{"concurrency"},
		},
		{
			ID: "conc-wg-add-in-goroutine", Name: "WaitGroup.Add Called Inside Goroutine", IsRegex: true,
			Pattern:     `go func\([\s\S]{0,50}\)[\s\S]{0,200}\.Add\(`,
			Severity:    types.SeverityHigh,
			Description: "Calling wg.Add() inside a goroutine creates a race: the WaitGroup may reach zero before all goroutines are counted.",
			Suggestion:  "Always call wg.Add() in the parent goroutine before launching the child.",
			References:  []string{"Go docs: sync.WaitGroup"},
			Tags:        []string{"concurrency"},
		},
		{
			ID: "conc-chan-nil-op", Name: "Operation on Nil Channel", IsRegex: true,
			Pattern:     `var .+ chan `,
			Severity:    types.SeverityMedium,
			Description: "Sending to or receiving from a nil channel blocks forever, causing a deadlock.",
			Suggestion:  "Always initialise channels with make(chan T) or make(chan T, n) before use.",
			References:  []string{"Go spec: channel types"},
			Tags:        []string{"concurrency"},
		},
		{
			ID: "conc-atomic-non-aligned", Name: "64-bit Atomic on Non-64-bit-aligned Variable", IsRegex: true,
			Pattern:     `atomic\.Add|atomic\.Load|atomic\.Store`,
			Severity:    types.SeverityMedium,
			Description: "On 32-bit platforms, 64-bit atomic operations require 8-byte alignment; misalignment causes crashes.",
			Suggestion:  "Use sync/atomic.Int64 type (Go 1.19+) which guarantees alignment, or ensure manual alignment.",
			References:  []string{"Go docs: sync/atomic"},
			Tags:        []string{"concurrency"},
		},
		{
			ID: "conc-context-cancel-leak", Name: "context.WithCancel cancel Not Called", IsRegex: true,
			Pattern:     `context\.WithCancel\(`,
			Severity:    types.SeverityMedium,
			Description: "If the cancel function is never called, the context and its resources leak until the parent is cancelled.",
			Suggestion:  "Always defer cancel() immediately after context.WithCancel().",
			References:  []string{"Go docs: context"},
			Tags:        []string{"concurrency"},
		},
		{
			ID: "conc-select-no-default", Name: "Blocking Select Without Timeout", IsRegex: true,
			Pattern:     `select \{[\s\S]{0,500}case <-`,
			Severity:    types.SeverityLow,
			Description: "A select statement waiting on channels without a timeout or context case may block forever under load.",
			Suggestion:  "Add a case <-ctx.Done() or a time.After timeout in long-running select loops.",
			References:  []string{"CWE-400"},
			Tags:        []string{"concurrency"},
		},
	}
}
