package commands

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/codeaudit/codeaudit/internal/config"
	"github.com/codeaudit/codeaudit/internal/orchestrator"
	"github.com/codeaudit/codeaudit/internal/report"
	"github.com/codeaudit/codeaudit/pkg/types"

	// Register all agents via their init() functions.
	_ "github.com/codeaudit/codeaudit/internal/agent"
)

var (
	flagFormat         string
	flagOutput         string
	flagAgents         string
	flagDomains        string
	flagFrameworks     string
	flagSkillDirs      string
	flagSkipPaths      string
	flagMaxWorkers     int
	flagVerbose        bool
	flagNoLLM          bool
	flagTimeout        int
)

var scanCmd = &cobra.Command{
	Use:   "scan <path>",
	Short: "Run a multi-agent security audit on a Go codebase",
	Args:  cobra.ExactArgs(1),
	Example: `  # Basic scan, output to terminal
  codeaudit scan ./myproject

  # Markdown report
  codeaudit scan ./myproject --format markdown --output report.md

  # SARIF for GitHub Code Scanning
  codeaudit scan ./myproject --format sarif --output results.sarif

  # Focus on specific domains with custom skills
  codeaudit scan ./myproject --domains ct,container --skills ./skills/

  # Run only specific agents
  codeaudit scan ./myproject --agents golang-general,golang-crypto

  # Verbose with 16 parallel workers
  codeaudit scan ./myproject --verbose --workers 16`,
	RunE: runScan,
}

func init() {
	rootCmd.AddCommand(scanCmd)

	scanCmd.Flags().StringVarP(&flagFormat, "format", "f", "text", "Output format: text|json|markdown|sarif")
	scanCmd.Flags().StringVarP(&flagOutput, "output", "o", "-", "Output file path (default: stdout)")
	scanCmd.Flags().StringVar(&flagAgents, "agents", "", "Comma-separated agent IDs to run (default: all)")
	scanCmd.Flags().StringVar(&flagDomains, "domains", "", "Comma-separated domain tags to include (e.g. ct,container,crypto)")
	scanCmd.Flags().StringVar(&flagFrameworks, "frameworks", "", "Comma-separated framework tags (e.g. gin,grpc,echo)")
	scanCmd.Flags().StringVar(&flagSkillDirs, "skills", "", "Comma-separated skill directories (appended to config skill_dirs)")
	scanCmd.Flags().StringVar(&flagSkipPaths, "skip", "vendor,testdata,.git", "Comma-separated paths to skip")
	scanCmd.Flags().IntVar(&flagMaxWorkers, "workers", 8, "Maximum number of parallel agents")
	scanCmd.Flags().BoolVarP(&flagVerbose, "verbose", "v", false, "Verbose agent progress output")
	scanCmd.Flags().BoolVar(&flagNoLLM, "no-llm", false, "Disable LLM-assisted analysis (static patterns only)")
	scanCmd.Flags().IntVar(&flagTimeout, "timeout", 300, "Scan timeout in seconds")
}

func runScan(cmd *cobra.Command, args []string) error {
	targetPath := args[0]

	if _, err := os.Stat(targetPath); err != nil {
		return fmt.Errorf("target path %q not found: %w", targetPath, err)
	}

	// Load config.
	cfg, err := config.Load(cfgFile)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	// Build logger.
	logger := buildLogger(cfg.LogLevel, flagVerbose)
	defer logger.Sync() //nolint:errcheck

	// Merge CLI flags into config.
	if flagNoLLM {
		os.Setenv("OPENAI_API_KEY", "")
	}

	skillDirs := cfg.Scan.SkillDirs
	if flagSkillDirs != "" {
		skillDirs = append(skillDirs, splitCSV(flagSkillDirs)...)
	}

	// Build orchestrator options.
	opts := orchestrator.Options{
		MaxWorkers:     flagMaxWorkers,
		SkillDirs:      skillDirs,
		EnabledAgents:  splitCSV(flagAgents),
		EnabledDomains: splitCSV(flagDomains),
		Verbose:        flagVerbose,
	}

	// Build audit target.
	target := &types.AuditTarget{
		Path:       targetPath,
		Frameworks: splitCSV(flagFrameworks),
		Domains:    splitCSV(flagDomains),
		SkipPaths:  splitCSV(flagSkipPaths),
	}

	// Run with timeout.
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(flagTimeout)*time.Second)
	defer cancel()

	printBanner(targetPath)

	orch := orchestrator.New(opts, logger)
	result, err := orch.Run(ctx, target)
	if err != nil {
		return fmt.Errorf("audit failed: %w", err)
	}

	// Determine output format.
	format := report.Format(flagFormat)
	if cfg.Report.Format != "" && flagFormat == "text" {
		format = report.Format(cfg.Report.Format)
	}
	outPath := flagOutput
	if cfg.Report.Output != "" && flagOutput == "-" {
		outPath = cfg.Report.Output
	}

	gen := report.New()
	if err := gen.Write(result, format, outPath); err != nil {
		return fmt.Errorf("writing report: %w", err)
	}

	// Print summary to stderr so it's always visible even when report goes to a file.
	if outPath != "-" {
		printSummary(result)
	}

	// Exit code 1 if CRITICAL or HIGH findings.
	if result.Summary.BySeverity["CRITICAL"] > 0 || result.Summary.BySeverity["HIGH"] > 0 {
		os.Exit(1)
	}
	return nil
}

func printBanner(path string) {
	bold := color.New(color.Bold)
	cyan := color.New(color.FgCyan, color.Bold)
	cyan.Println("\n╔══════════════════════════════════════════════════════╗")
	cyan.Println("║       CodeAudit — Multi-Agent Security Scanner       ║")
	cyan.Println("╚══════════════════════════════════════════════════════╝")
	bold.Printf("\nScanning: %s\n\n", path)
}

func printSummary(result *types.AuditResult) {
	red := color.New(color.FgRed, color.Bold)
	yellow := color.New(color.FgYellow)
	green := color.New(color.FgGreen)

	fmt.Fprintln(os.Stderr, "\n── Audit Summary ──────────────────────────────────────")
	red.Fprintf(os.Stderr, "  CRITICAL : %d\n", result.Summary.BySeverity["CRITICAL"])
	red.Fprintf(os.Stderr, "  HIGH     : %d\n", result.Summary.BySeverity["HIGH"])
	yellow.Fprintf(os.Stderr, "  MEDIUM   : %d\n", result.Summary.BySeverity["MEDIUM"])
	green.Fprintf(os.Stderr, "  LOW      : %d\n", result.Summary.BySeverity["LOW"])
	fmt.Fprintf(os.Stderr, "  INFO     : %d\n", result.Summary.BySeverity["INFO"])
	fmt.Fprintf(os.Stderr, "  Total    : %d  (Risk Score: %.1f)\n", result.Summary.TotalFindings, result.Summary.RiskScore)
	fmt.Fprintf(os.Stderr, "  Duration : %s\n\n", result.Duration)
}

func buildLogger(level string, verbose bool) *zap.Logger {
	lvl := zapcore.InfoLevel
	if verbose {
		lvl = zapcore.DebugLevel
	}
	if level == "debug" {
		lvl = zapcore.DebugLevel
	}

	cfg := zap.NewProductionConfig()
	cfg.Level = zap.NewAtomicLevelAt(lvl)
	cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	logger, _ := cfg.Build()
	return logger
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	var result []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			result = append(result, part)
		}
	}
	return result
}
