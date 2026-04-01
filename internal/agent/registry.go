package agent

import (
	"fmt"
	"sync"
)

// Registry holds all registered agents and allows lookup by ID or domain.
type Registry struct {
	mu     sync.RWMutex
	agents map[string]Agent
}

var globalRegistry = &Registry{agents: make(map[string]Agent)}

// Register adds an agent to the global registry.
func Register(a Agent) {
	globalRegistry.Register(a)
}

// All returns all agents in the global registry.
func All() []Agent {
	return globalRegistry.All()
}

// Get returns an agent by ID from the global registry.
func Get(id string) (Agent, error) {
	return globalRegistry.Get(id)
}

// ByDomain returns agents that handle the given domain tag.
func ByDomain(domain string) []Agent {
	return globalRegistry.ByDomain(domain)
}

func (r *Registry) Register(a Agent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.agents[a.ID()] = a
}

func (r *Registry) All() []Agent {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Agent, 0, len(r.agents))
	for _, a := range r.agents {
		out = append(out, a)
	}
	return out
}

func (r *Registry) Get(id string) (Agent, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	a, ok := r.agents[id]
	if !ok {
		return nil, fmt.Errorf("agent %q not found in registry", id)
	}
	return a, nil
}

func (r *Registry) ByDomain(domain string) []Agent {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []Agent
	for _, a := range r.agents {
		for _, d := range a.SupportedDomains() {
			if d == domain {
				out = append(out, a)
				break
			}
		}
	}
	return out
}
