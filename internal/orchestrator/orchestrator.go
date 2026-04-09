// Package orchestrator coordinates multi-agent parallel execution, skill
// injection, and result aggregation — the core of the CodeAudit pipeline.
package orchestrator

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/codeaudit/codeaudit/internal/agent"
	"github.com/codeaudit/codeaudit/internal/skill"
	"github.com/codeaudit/codeaudit/pkg/types"
)

// Options controls orchestrator behaviour.
type Options struct {
	// MaxWorkers is the maximum number of agents running concurrently.
	MaxWorkers int
	// SkillDirs are directories to auto-load skill YAML files from.
	SkillDirs []string
	// EnabledAgents restricts which agent IDs are run (empty = all).
	EnabledAgents []string
	// EnabledDomains restricts by domain tag (empty = all).
	EnabledDomains []string
	// Verbose emits per-agent progress logs.
	Verbose bool
}

// Orchestrator runs agents in parallel, injects skills, and merges results.
type Orchestrator struct {
	opts   Options
	logger *zap.Logger
}

// New creates a new Orchestrator with the given options.
func New(opts Options, logger *zap.Logger) *Orchestrator {
	if opts.MaxWorkers <= 0 {
		opts.MaxWorkers = 8
	}
	return &Orchestrator{opts: opts, logger: logger}
}

// Run executes the full multi-agent audit pipeline against target.
func (o *Orchestrator) Run(ctx context.Context, target *types.AuditTarget) (*types.AuditResult, error) {
	start := time.Now()

	// Load skills from configured directories.
	for _, dir := range o.opts.SkillDirs {
		if err := skill.LoadDir(dir); err != nil {
			o.logger.Warn("loading skill dir", zap.String("dir", dir), zap.Error(err))
		}
	}

	// Select agents.
	agents := o.selectAgents(target)
	if len(agents) == 0 {
		return nil, fmt.Errorf("no agents selected for target %s", target.Path)
	}
	o.logger.Info("starting audit",
		zap.String("path", target.Path),
		zap.Int("agents", len(agents)),
	)

	// Inject skills into each agent.
	o.injectSkills(agents, target)

	// Run agents with bounded concurrency.
	agentResults := o.runParallel(ctx, agents, target)

	// Aggregate.
	result := o.aggregate(target, agentResults, start)

	o.logger.Info("audit complete",
		zap.Int("findings", result.Summary.TotalFindings),
		zap.String("duration", result.Duration),
	)
	return result, nil
}

// selectAgents returns the subset of registered agents to run.
func (o *Orchestrator) selectAgents(target *types.AuditTarget) []agent.Agent {
	allAgents := agent.All()

	enabledSet := make(map[string]bool)
	for _, id := range o.opts.EnabledAgents {
		enabledSet[id] = true
	}

	domainSet := make(map[string]bool)
	for _, d := range o.opts.EnabledDomains {
		domainSet[d] = true
	}
	for _, d := range target.Domains {
		domainSet[d] = true
	}
	for _, f := range target.Frameworks {
		domainSet[f] = true
	}

	var selected []agent.Agent
	for _, a := range allAgents {
		if len(enabledSet) > 0 && !enabledSet[a.ID()] {
			continue
		}
		if len(domainSet) > 0 {
			matched := false
			for _, d := range a.SupportedDomains() {
				if domainSet[d] {
					matched = true
					break
				}
			}
			// Always include agents with domain "general".
			for _, d := range a.SupportedDomains() {
				if d == "general" {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}
		selected = append(selected, a)
	}
	return selected
}

// injectSkills matches skills to agents by domain and injects them.
func (o *Orchestrator) injectSkills(agents []agent.Agent, target *types.AuditTarget) {
	for _, a := range agents {
		var matched []*skill.Skill
		for _, domain := range a.SupportedDomains() {
			matched = append(matched, skill.ByDomain(domain)...)
		}
		// Also inject skills explicitly listed in target domains.
		for _, d := range target.Domains {
			matched = append(matched, skill.ByDomain(d)...)
		}
		for _, f := range target.Frameworks {
			matched = append(matched, skill.ByDomain(f)...)
		}
		if len(matched) > 0 {
			a.InjectSkills(dedupeSkills(matched))
			o.logger.Debug("injected skills",
				zap.String("agent", a.ID()),
				zap.Int("skills", len(matched)),
			)
		}
	}
}

// runParallel executes all agents concurrently with a semaphore.
func (o *Orchestrator) runParallel(ctx context.Context, agents []agent.Agent, target *types.AuditTarget) []*types.AgentResult {
	sem := make(chan struct{}, o.opts.MaxWorkers)
	results := make([]*types.AgentResult, len(agents))
	var wg sync.WaitGroup

	for i, a := range agents {
		wg.Add(1)
		go func(idx int, ag agent.Agent) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			agStart := time.Now()
			if o.opts.Verbose {
				o.logger.Info("agent starting", zap.String("agent", ag.ID()))
			}

			res, err := ag.Analyze(ctx, target)
			dur := time.Since(agStart).Round(time.Millisecond).String()

			if err != nil {
				o.logger.Error("agent error",
					zap.String("agent", ag.ID()),
					zap.Error(err),
				)
				results[idx] = &types.AgentResult{
					AgentID:   ag.ID(),
					AgentName: ag.Name(),
					Error:     err.Error(),
					Duration:  dur,
				}
				return
			}

			res.Duration = dur
			results[idx] = res
			if o.opts.Verbose {
				o.logger.Info("agent done",
					zap.String("agent", ag.ID()),
					zap.Int("findings", len(res.Findings)),
					zap.String("duration", dur),
				)
			}
		}(i, a)
	}

	wg.Wait()
	return results
}

// aggregate merges per-agent results into a single AuditResult.
func (o *Orchestrator) aggregate(target *types.AuditTarget, agentResults []*types.AgentResult, start time.Time) *types.AuditResult {
	end := time.Now()
	result := &types.AuditResult{
		Target:       *target,
		AgentResults: agentResults,
		StartTime:    start,
		EndTime:      end,
		Duration:     end.Sub(start).Round(time.Millisecond).String(),
		Summary: types.Summary{
			BySeverity: make(map[string]int),
			ByCategory: make(map[string]int),
			ByAgent:    make(map[string]int),
		},
	}

	seen := make(map[string]bool) // deduplicate by file+line+ruleID
	for _, ar := range agentResults {
		if ar == nil {
			continue
		}
		for _, f := range ar.Findings {
			key := fmt.Sprintf("%s:%d:%s", f.FilePath, f.Line, f.RuleID)
			if seen[key] {
				continue
			}
			seen[key] = true
			result.Findings = append(result.Findings, f)
			result.Summary.BySeverity[string(f.Severity)]++
			result.Summary.ByCategory[string(f.Category)]++
			result.Summary.ByAgent[ar.AgentID]++
		}
		result.Summary.ByAgent[ar.AgentID] += 0 // ensure key exists
	}

	result.Summary.TotalFindings = len(result.Findings)
	result.Summary.RiskScore = computeRiskScore(result.Summary.BySeverity)
	return result
}

func computeRiskScore(bySeverity map[string]int) float64 {
	weights := map[string]float64{
		"CRITICAL": 10.0,
		"HIGH":     5.0,
		"MEDIUM":   2.0,
		"LOW":      0.5,
		"INFO":     0.1,
	}
	var score float64
	for sev, count := range bySeverity {
		score += weights[sev] * float64(count)
	}
	return score
}

func dedupeSkills(skills []*skill.Skill) []*skill.Skill {
	seen := make(map[string]bool)
	var out []*skill.Skill
	for _, s := range skills {
		if !seen[s.ID] {
			seen[s.ID] = true
			out = append(out, s)
		}
	}
	return out
}
