package agent

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/codeaudit/codeaudit/internal/analyzer"
	"github.com/codeaudit/codeaudit/internal/llm"
	"github.com/codeaudit/codeaudit/pkg/types"
)

// GolangGeneralAgent performs broad Golang security auditing:
// injection, crypto misuse, insecure deserialization, race conditions,
// error handling, SSRF, command injection, path traversal, etc.
type GolangGeneralAgent struct {
	BaseAgent
	llm llm.Client
}

func NewGolangGeneralAgent(llmClient llm.Client) *GolangGeneralAgent {
	a := &GolangGeneralAgent{
		BaseAgent: NewBaseAgent(
			"golang-general",
			"Golang General Security",
			"Detects common Golang security vulnerabilities: injection, crypto misuse, race conditions, SSRF, insecure deserialization, etc.",
			[]string{"general", "golang"},
		),
		llm: llmClient,
	}
	return a
}

func init() {
	Register(NewGolangGeneralAgent(llm.NewFromEnv()))
}

func (a *GolangGeneralAgent) Analyze(ctx context.Context, target *types.AuditTarget) (*types.AgentResult, error) {
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

	// Built-in static patterns.
	builtinPatterns := a.builtinPatterns()
	// Skill-injected patterns.
	skillPatterns := a.GetSkillPatterns()

	allPatterns := append(builtinPatterns, skillPatterns...)

	for _, fileCtx := range contexts {
		for _, pat := range allPatterns {
			findings := analyzer.MatchPattern(fileCtx, pat, a.ID())
			result.Findings = append(result.Findings, findings...)
		}

		// AI-assisted deep analysis on files with suspicious imports.
		if a.looksRisky(fileCtx) {
			llmFindings := a.runLLMAnalysis(ctx, fileCtx)
			result.Findings = append(result.Findings, llmFindings...)
		}
	}

	result.Duration = time.Since(start).String()
	return result, nil
}

// looksRisky returns true when a file imports any potentially dangerous packages.
func (a *GolangGeneralAgent) looksRisky(ctx *types.CodeContext) bool {
	risky := []string{
		"os/exec", "net/http", "crypto/md5", "crypto/sha1", "crypto/des",
		"database/sql", "encoding/gob", "unsafe", "reflect", "syscall",
	}
	for _, r := range risky {
		if analyzer.HasImport(ctx, r) {
			return true
		}
	}
	return false
}

func (a *GolangGeneralAgent) runLLMAnalysis(ctx context.Context, fileCtx *types.CodeContext) []*types.Finding {
	if a.llm == nil {
		return nil
	}

	systemMsg := `You are an expert Golang security auditor. Analyze the provided Go source file and identify
security vulnerabilities. Focus on:
- Command injection (os/exec with user input)
- SQL injection (fmt.Sprintf in queries)
- Path traversal (user-controlled file paths)
- SSRF (user-controlled URLs)
- Insecure crypto (MD5, SHA1, DES, hardcoded keys/IVs)
- Race conditions (unsynchronized shared state)
- Insecure deserialization (gob, encoding/json with interface{})
- Information disclosure (error messages, stack traces)
- Unsafe memory operations

For each issue found, respond in this exact format:
FINDING: <title>
SEVERITY: <CRITICAL|HIGH|MEDIUM|LOW|INFO>
LINE: <line number>
DESCRIPTION: <detailed description>
SUGGESTION: <remediation>
---`

	// Truncate very large files to avoid token limits.
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
	if err != nil || resp.Content == "" {
		return nil
	}

	return parseLLMFindings(resp.Content, fileCtx.FilePath, a.ID())
}

func (a *GolangGeneralAgent) builtinPatterns() []types.SkillPattern {
	return []types.SkillPattern{
		{
			ID: "go-exec-cmd", Name: "OS Command Injection Risk", IsAST: true,
			Pattern:     "exec.Command",
			Severity:    types.SeverityHigh,
			Description: "exec.Command may be vulnerable to command injection if arguments include user-controlled data.",
			Suggestion:  "Validate and sanitize all arguments. Avoid constructing command strings dynamically.",
			References:  []string{"CWE-78"},
			Tags:        []string{"injection", "general"},
		},
		{
			ID: "go-md5-use", Name: "Weak Hash: MD5", IsAST: true,
			Pattern:     "md5.New",
			Severity:    types.SeverityMedium,
			Description: "MD5 is cryptographically broken and should not be used for security-sensitive operations.",
			Suggestion:  "Use SHA-256 or SHA-3 from crypto/sha256 or crypto/sha3.",
			References:  []string{"CWE-327"},
			Tags:        []string{"crypto", "general"},
		},
		{
			ID: "go-sha1-use", Name: "Weak Hash: SHA1", IsAST: true,
			Pattern:     "sha1.New",
			Severity:    types.SeverityMedium,
			Description: "SHA1 is deprecated for security use and vulnerable to collision attacks.",
			Suggestion:  "Use SHA-256 or stronger.",
			References:  []string{"CWE-327"},
			Tags:        []string{"crypto", "general"},
		},
		{
			ID: "go-des-use", Name: "Weak Cipher: DES", IsAST: true,
			Pattern:     "des.NewCipher",
			Severity:    types.SeverityHigh,
			Description: "DES has a 56-bit key and is considered insecure against brute-force attacks.",
			Suggestion:  "Use AES-GCM (crypto/aes with cipher.NewGCM).",
			References:  []string{"CWE-326"},
			Tags:        []string{"crypto", "general"},
		},
		{
			ID: "go-math-rand", Name: "Insecure Random: math/rand", IsAST: true,
			Pattern:     "rand.Intn",
			Severity:    types.SeverityMedium,
			Description: "math/rand is not cryptographically secure and must not be used for tokens, keys, or salts.",
			Suggestion:  "Use crypto/rand for cryptographic randomness.",
			References:  []string{"CWE-338"},
			Tags:        []string{"crypto", "general"},
		},
		{
			ID: "go-unsafe-use", Name: "Unsafe Package Usage", IsRegex: true,
			Pattern:     `"unsafe"`,
			Severity:    types.SeverityMedium,
			Description: "The unsafe package bypasses Go's type safety and can introduce memory corruption.",
			Suggestion:  "Avoid unsafe unless absolutely necessary and document the invariants that keep it safe.",
			References:  []string{"CWE-119"},
			Tags:        []string{"memory", "general"},
		},
		{
			ID: "go-sql-fmt", Name: "Potential SQL Injection via fmt.Sprintf", IsRegex: true,
			Pattern:     `fmt\.Sprintf.*SELECT|fmt\.Sprintf.*INSERT|fmt\.Sprintf.*UPDATE|fmt\.Sprintf.*DELETE`,
			Severity:    types.SeverityHigh,
			Description: "SQL query built with fmt.Sprintf may be vulnerable to SQL injection.",
			Suggestion:  "Use parameterized queries (db.Query with ? placeholders).",
			References:  []string{"CWE-89"},
			Tags:        []string{"injection", "general"},
		},
		{
			ID: "go-tls-insecure", Name: "InsecureSkipVerify TLS", IsRegex: true,
			Pattern:     `InsecureSkipVerify:\s*true`,
			Severity:    types.SeverityCritical,
			Description: "TLS certificate verification is disabled, making connections vulnerable to MITM attacks.",
			Suggestion:  "Remove InsecureSkipVerify or implement proper certificate pinning.",
			References:  []string{"CWE-295"},
			Tags:        []string{"tls", "general"},
		},
		{
			ID: "go-hardcoded-pass", Name: "Hardcoded Password/Secret", IsRegex: true,
			Pattern:     `(?i)(password|secret|apikey|api_key|token)\s*=\s*"[^"]+"`,
			Severity:    types.SeverityCritical,
			Description: "Hardcoded credentials in source code can be extracted by attackers.",
			Suggestion:  "Use environment variables or a secrets manager.",
			References:  []string{"CWE-798"},
			Tags:        []string{"secrets", "general"},
		},
		{
			ID: "go-http-redirect", Name: "Open Redirect Risk", IsRegex: true,
			Pattern:     `http\.Redirect\(.*r\.URL|http\.Redirect\(.*r\.FormValue`,
			Severity:    types.SeverityMedium,
			Description: "Redirect target derived from user input may enable open redirect attacks.",
			Suggestion:  "Validate redirect URLs against an allowlist of trusted destinations.",
			References:  []string{"CWE-601"},
			Tags:        []string{"web", "general"},
		},
		{
			ID: "go-goroutine-leak", Name: "Potential Goroutine Leak", IsRegex: true,
			Pattern:     `go func\(\)`,
			Severity:    types.SeverityLow,
			Description: "Goroutine launched without a Done/cancel signal may leak on shutdown.",
			Suggestion:  "Use context.Context cancellation or sync.WaitGroup to track goroutine lifecycle.",
			References:  []string{"CWE-400"},
			Tags:        []string{"concurrency", "general"},
		},
		{
			ID: "go-panic-recover-missing", Name: "Missing Panic Recovery in Goroutine", IsRegex: true,
			Pattern:     `go func\(\)[\s\S]{0,200}}{`,
			Severity:    types.SeverityLow,
			Description: "Goroutines without recover() will crash the entire process on panic.",
			Suggestion:  "Add defer recover() inside long-running goroutines.",
			References:  []string{"CWE-755"},
			Tags:        []string{"concurrency", "general"},
		},
		{
			ID: "go-ioutil-readall", Name: "Unbounded io.ReadAll", IsRegex: true,
			Pattern:     `io\.ReadAll|ioutil\.ReadAll`,
			Severity:    types.SeverityMedium,
			Description: "Reading entire response body without size limit enables memory exhaustion attacks.",
			Suggestion:  "Use io.LimitReader to cap response size before reading.",
			References:  []string{"CWE-400"},
			Tags:        []string{"dos", "general"},
		},
		{
			ID: "go-path-join-user", Name: "Path Traversal via filepath.Join with User Input", IsRegex: true,
			Pattern:     `filepath\.Join\(.*(?:r\.URL|FormValue|PathParam|Param)`,
			Severity:    types.SeverityHigh,
			Description: "filepath.Join with user-controlled input may allow traversal outside intended directory.",
			Suggestion:  "Use filepath.Clean and verify the result is still under the intended base directory.",
			References:  []string{"CWE-22"},
			Tags:        []string{"injection", "general"},
		},
	}
}

// parseLLMFindings extracts structured findings from the LLM's free-text response.
func parseLLMFindings(content, filePath, agentID string) []*types.Finding {
	var findings []*types.Finding
	blocks := strings.Split(content, "---")
	for _, block := range blocks {
		block = strings.TrimSpace(block)
		if !strings.Contains(block, "FINDING:") {
			continue
		}
		f := &types.Finding{
			AgentID:    agentID,
			FilePath:   filePath,
			Confidence: 0.7,
		}
		for _, line := range strings.Split(block, "\n") {
			line = strings.TrimSpace(line)
			switch {
			case strings.HasPrefix(line, "FINDING:"):
				f.Title = strings.TrimSpace(strings.TrimPrefix(line, "FINDING:"))
			case strings.HasPrefix(line, "SEVERITY:"):
				f.Severity = types.Severity(strings.TrimSpace(strings.TrimPrefix(line, "SEVERITY:")))
			case strings.HasPrefix(line, "LINE:"):
				fmt.Sscanf(strings.TrimPrefix(line, "LINE:"), "%d", &f.Line)
			case strings.HasPrefix(line, "DESCRIPTION:"):
				f.Description = strings.TrimSpace(strings.TrimPrefix(line, "DESCRIPTION:"))
			case strings.HasPrefix(line, "SUGGESTION:"):
				f.Suggestion = strings.TrimSpace(strings.TrimPrefix(line, "SUGGESTION:"))
			}
		}
		if f.Title != "" && f.Severity != "" {
			findings = append(findings, f)
		}
	}
	return findings
}
