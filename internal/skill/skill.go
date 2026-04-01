// Package skill implements the skill loading, registry, and injection system.
// Skills are YAML-defined bundles of domain expert knowledge (patterns, prompt
// templates, semantic rules) that are injected into agents at runtime.
package skill

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/codeaudit/codeaudit/pkg/types"
)

// Skill re-exports types.Skill for convenience within this package.
type Skill = types.Skill

// Registry stores all loaded skills indexed by ID and domain tag.
type Registry struct {
	mu     sync.RWMutex
	byID   map[string]*Skill
	byDomain map[string][]*Skill
}

var globalRegistry = &Registry{
	byID:     make(map[string]*Skill),
	byDomain: make(map[string][]*Skill),
}

// LoadDir recursively loads all *.yaml skill files from dir into the global registry.
func LoadDir(dir string) error {
	return globalRegistry.LoadDir(dir)
}

// Get returns a skill by ID.
func Get(id string) (*Skill, error) {
	return globalRegistry.Get(id)
}

// ByDomain returns all skills tagged with the given domain.
func ByDomain(domain string) []*Skill {
	return globalRegistry.ByDomain(domain)
}

// All returns every loaded skill.
func All() []*Skill {
	return globalRegistry.All()
}

// Register manually registers a skill.
func Register(s *Skill) {
	globalRegistry.Register(s)
}

func (r *Registry) LoadDir(dir string) error {
	return filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		ext := filepath.Ext(path)
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}
		return r.loadFile(path)
	})
}

func (r *Registry) loadFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading skill file %s: %w", path, err)
	}
	var s Skill
	if err := yaml.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("parsing skill file %s: %w", path, err)
	}
	if s.ID == "" {
		return fmt.Errorf("skill file %s missing required field 'id'", path)
	}
	r.Register(&s)
	return nil
}

func (r *Registry) Register(s *Skill) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.byID[s.ID] = s
	for _, tag := range s.Tags {
		r.byDomain[tag] = append(r.byDomain[tag], s)
	}
	if s.Domain != "" {
		r.byDomain[s.Domain] = appendUnique(r.byDomain[s.Domain], s)
	}
}

func (r *Registry) Get(id string) (*Skill, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.byID[id]
	if !ok {
		return nil, fmt.Errorf("skill %q not found", id)
	}
	return s, nil
}

func (r *Registry) ByDomain(domain string) []*Skill {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.byDomain[domain]
}

func (r *Registry) All() []*Skill {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*Skill, 0, len(r.byID))
	for _, s := range r.byID {
		out = append(out, s)
	}
	return out
}

func appendUnique(existing []*Skill, s *Skill) []*Skill {
	for _, e := range existing {
		if e.ID == s.ID {
			return existing
		}
	}
	return append(existing, s)
}
