// Package commands defines the CLI commands for CodeAudit.
package commands

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	cfgFile string
)

var rootCmd = &cobra.Command{
	Use:   "codeaudit",
	Short: "Multi-agent Golang security auditing system",
	Long: `CodeAudit is a multi-agent, skill-orchestrated Golang security audit system.

It combines static AST analysis, LLM-assisted deep review, and pluggable
domain-expert skill YAML files to detect vulnerabilities across:

  • General Golang security (injection, crypto, SSRF, race conditions)
  • Web frameworks (Gin, Echo, Fiber, gRPC, go-zero, chi)
  • Cryptography (weak ciphers, IV reuse, JWT misuse, side channels)
  • Container & Kubernetes (privileged pods, RBAC wildcards, Docker Socket)
  • CT Protocol (SCT forgery, Merkle tree attacks, RFC 6962 compliance)
  • Concurrency (race conditions, deadlocks, goroutine leaks)
  • Business logic (IDOR, payment races, MFA bypass) — via skill files

QUICK START:
  codeaudit scan ./myproject
  codeaudit scan ./myproject --format markdown --output report.md
  codeaudit scan ./myproject --domains ct,container --skills ./my-skills/
  codeaudit scan ./myproject --agents golang-general,golang-crypto
`,
}

// Execute runs the root command.
func Execute() error {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return err
	}
	return nil
}

func init() {
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default: .codeaudit.yaml)")
}
