// Package config loads and validates the CodeAudit configuration.
package config

import (
	"fmt"
	"os"

	"github.com/spf13/viper"
)

// Config is the top-level configuration structure.
type Config struct {
	// LLM provider settings.
	LLM LLMConfig `mapstructure:"llm"`
	// Scan settings.
	Scan ScanConfig `mapstructure:"scan"`
	// Reporting settings.
	Report ReportConfig `mapstructure:"report"`
	// Logging.
	LogLevel string `mapstructure:"log_level"`
}

// LLMConfig configures the language model backend.
type LLMConfig struct {
	Provider    string  `mapstructure:"provider"`    // openai | azure | anthropic | none
	APIKey      string  `mapstructure:"api_key"`     // overridden by OPENAI_API_KEY env
	BaseURL     string  `mapstructure:"base_url"`    // for Azure/proxy endpoints
	Model       string  `mapstructure:"model"`       // e.g. gpt-4o
	MaxTokens   int     `mapstructure:"max_tokens"`
	Temperature float32 `mapstructure:"temperature"`
}

// ScanConfig controls which agents run and scan scope.
type ScanConfig struct {
	SkillDirs      []string `mapstructure:"skill_dirs"`
	EnabledAgents  []string `mapstructure:"enabled_agents"`
	EnabledDomains []string `mapstructure:"enabled_domains"`
	SkipPaths      []string `mapstructure:"skip_paths"`
	MaxWorkers     int      `mapstructure:"max_workers"`
	Frameworks     []string `mapstructure:"frameworks"`
	Domains        []string `mapstructure:"domains"`
}

// ReportConfig controls output.
type ReportConfig struct {
	Format  string `mapstructure:"format"`  // json | markdown | sarif | text
	Output  string `mapstructure:"output"`  // file path or "-" for stdout
	Verbose bool   `mapstructure:"verbose"`
}

// Load reads configuration from a YAML file (if provided) and environment variables.
func Load(cfgFile string) (*Config, error) {
	v := viper.New()

	// Defaults.
	v.SetDefault("llm.provider", "openai")
	v.SetDefault("llm.model", "gpt-4o")
	v.SetDefault("llm.max_tokens", 2048)
	v.SetDefault("llm.temperature", 0.2)
	v.SetDefault("scan.max_workers", 8)
	v.SetDefault("scan.skill_dirs", []string{"./skills"})
	v.SetDefault("report.format", "text")
	v.SetDefault("report.output", "-")
	v.SetDefault("log_level", "info")

	// Environment variable overrides (CODEAUDIT_ prefix).
	v.SetEnvPrefix("CODEAUDIT")
	v.AutomaticEnv()

	// Explicit API key from standard env vars.
	if key := os.Getenv("OPENAI_API_KEY"); key != "" {
		v.Set("llm.api_key", key)
	}

	if cfgFile != "" {
		v.SetConfigFile(cfgFile)
		if err := v.ReadInConfig(); err != nil {
			return nil, fmt.Errorf("reading config file %s: %w", cfgFile, err)
		}
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshalling config: %w", err)
	}
	return &cfg, nil
}
