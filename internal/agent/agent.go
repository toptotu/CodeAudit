// Package agent defines the Agent interface and base implementation that every
// specialized security-audit agent must satisfy.
package agent

import (
	"context"

	"github.com/codeaudit/codeaudit/internal/skill"
	"github.com/codeaudit/codeaudit/pkg/types"
)

// Agent is the contract every audit agent must implement.
type Agent interface {
	// ID returns a stable, machine-readable identifier (e.g. "golang-general").
	ID() string
	// Name returns a human-readable display name.
	Name() string
	// Description returns what this agent detects.
	Description() string
	// SupportedDomains lists the domain tags this agent handles.
	SupportedDomains() []string
	// Analyze runs the audit on target and returns per-agent results.
	Analyze(ctx context.Context, target *types.AuditTarget) (*types.AgentResult, error)
	// InjectSkills attaches additional skill sets loaded at runtime.
	InjectSkills(skills []*skill.Skill)
}

// BaseAgent provides shared state and helpers for all concrete agents.
type BaseAgent struct {
	id          string
	name        string
	description string
	domains     []string
	Skills      []*skill.Skill
}

func NewBaseAgent(id, name, description string, domains []string) BaseAgent {
	return BaseAgent{
		id:          id,
		name:        name,
		description: description,
		domains:     domains,
	}
}

func (b *BaseAgent) ID() string                { return b.id }
func (b *BaseAgent) Name() string              { return b.name }
func (b *BaseAgent) Description() string       { return b.description }
func (b *BaseAgent) SupportedDomains() []string { return b.domains }

func (b *BaseAgent) InjectSkills(skills []*skill.Skill) {
	b.Skills = append(b.Skills, skills...)
}

// GetSkillPatterns returns all patterns from injected skills matching the given tags.
func (b *BaseAgent) GetSkillPatterns(tags ...string) []types.SkillPattern {
	tagSet := make(map[string]bool)
	for _, t := range tags {
		tagSet[t] = true
	}
	var patterns []types.SkillPattern
	for _, s := range b.Skills {
		for _, p := range s.Patterns {
			if len(tags) == 0 {
				patterns = append(patterns, p)
				continue
			}
			for _, pt := range p.Tags {
				if tagSet[pt] {
					patterns = append(patterns, p)
					break
				}
			}
		}
	}
	return patterns
}

// GetSkillPrompts returns all LLM prompt templates from injected skills.
func (b *BaseAgent) GetSkillPrompts() []types.SkillPrompt {
	var prompts []types.SkillPrompt
	for _, s := range b.Skills {
		prompts = append(prompts, s.Prompts...)
	}
	return prompts
}

// SkillsUsed returns the IDs of all injected skills.
func (b *BaseAgent) SkillsUsed() []string {
	ids := make([]string, 0, len(b.Skills))
	for _, s := range b.Skills {
		ids = append(ids, s.ID)
	}
	return ids
}
