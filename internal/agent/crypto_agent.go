package agent

import (
	"context"
	"fmt"
	"time"

	"github.com/codeaudit/codeaudit/internal/analyzer"
	"github.com/codeaudit/codeaudit/internal/llm"
	"github.com/codeaudit/codeaudit/pkg/types"
)

// CryptoAgent specializes in deep cryptographic security analysis:
// key management, IV/nonce reuse, padding oracle, JWT vulnerabilities,
// certificate validation, and side-channel risks.
type CryptoAgent struct {
	BaseAgent
	llm llm.Client
}

func NewCryptoAgent(llmClient llm.Client) *CryptoAgent {
	return &CryptoAgent{
		BaseAgent: NewBaseAgent(
			"golang-crypto",
			"Cryptography Security",
			"Detects cryptographic weaknesses: weak algorithms, IV reuse, key exposure, JWT misuse, padding oracles, and side channels.",
			[]string{"crypto", "golang"},
		),
		llm: llmClient,
	}
}

func init() {
	Register(NewCryptoAgent(llm.NewFromEnv()))
}

func (a *CryptoAgent) Analyze(ctx context.Context, target *types.AuditTarget) (*types.AgentResult, error) {
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

	allPatterns := append(a.builtinPatterns(), a.GetSkillPatterns("crypto")...)

	for _, fileCtx := range contexts {
		for _, pat := range allPatterns {
			findings := analyzer.MatchPattern(fileCtx, pat, a.ID())
			result.Findings = append(result.Findings, findings...)
		}

		if a.usesCrypto(fileCtx) {
			llmFindings := a.runLLMAnalysis(ctx, fileCtx)
			result.Findings = append(result.Findings, llmFindings...)
		}
	}

	result.Duration = time.Since(start).String()
	return result, nil
}

func (a *CryptoAgent) usesCrypto(ctx *types.CodeContext) bool {
	cryptoPkgs := []string{
		"crypto/", "encoding/pem", "crypto/x509",
		"golang.org/x/crypto", "jwt", "tls",
	}
	for _, imp := range ctx.Imports {
		for _, cp := range cryptoPkgs {
			if containsStr(imp, cp) {
				return true
			}
		}
	}
	return false
}

func (a *CryptoAgent) runLLMAnalysis(ctx context.Context, fileCtx *types.CodeContext) []*types.Finding {
	systemMsg := `You are a cryptographic security expert specializing in Go. Analyze the provided source code for:
- ECB mode usage (cipher.NewECBEncrypter — no such stdlib function, custom implementations)
- Static/hardcoded IV or nonce
- IV reuse across multiple encryptions
- CBC without HMAC (padding oracle vulnerability)
- Weak key derivation (short keys, no salt)
- JWT: alg=none, RS256→HS256 confusion, weak signing secret, no expiry check
- Missing certificate revocation checking (x509 without OCSP/CRL)
- Side-channel risks (time-constant comparison missing: use subtle.ConstantTimeCompare)
- Entropy issues (seeding math/rand with time.Now().Unix())
- RSA PKCS#1 v1.5 encryption (vulnerable to Bleichenbacher)

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

func (a *CryptoAgent) builtinPatterns() []types.SkillPattern {
	return []types.SkillPattern{
		{
			ID: "crypto-ecb-mode", Name: "ECB Mode Usage", IsRegex: true,
			Pattern:     `NewECBEncrypter|NewECBDecrypter|ECB`,
			Severity:    types.SeverityHigh,
			Description: "ECB mode does not provide semantic security — identical plaintext blocks produce identical ciphertext.",
			Suggestion:  "Use AES-GCM (cipher.NewGCM) for authenticated encryption.",
			References:  []string{"CWE-327"},
			Tags:        []string{"crypto"},
		},
		{
			ID: "crypto-static-iv", Name: "Static/Hardcoded IV", IsRegex: true,
			Pattern:     `iv\s*:?=\s*\[\]byte\{|nonce\s*:?=\s*\[\]byte\{`,
			Severity:    types.SeverityCritical,
			Description: "A static or hardcoded IV/nonce destroys confidentiality when the same key is reused.",
			Suggestion:  "Generate a fresh random IV/nonce with crypto/rand for each encryption operation.",
			References:  []string{"CWE-330"},
			Tags:        []string{"crypto"},
		},
		{
			ID: "crypto-cbc-no-mac", Name: "CBC Without MAC (Padding Oracle Risk)", IsRegex: true,
			Pattern:     `cipher\.NewCBCEncrypter`,
			Severity:    types.SeverityHigh,
			Description: "CBC encryption without an authentication tag is vulnerable to padding oracle attacks.",
			Suggestion:  "Use AES-GCM which provides authenticated encryption, or apply HMAC-SHA256 over the ciphertext.",
			References:  []string{"CWE-696", "CVE-2013-0169"},
			Tags:        []string{"crypto"},
		},
		{
			ID: "crypto-time-constant-missing", Name: "Non-Constant Time Comparison of Secrets", IsRegex: true,
			Pattern:     `bytes\.Equal\(.*(?:mac|hmac|token|secret|sig)`,
			Severity:    types.SeverityHigh,
			Description: "bytes.Equal leaks timing information about secret values. Use subtle.ConstantTimeCompare instead.",
			Suggestion:  "Use crypto/subtle.ConstantTimeCompare for all secret/MAC comparisons.",
			References:  []string{"CWE-208"},
			Tags:        []string{"crypto"},
		},
		{
			ID: "crypto-weak-rsa-key", Name: "RSA Key Size < 2048 bits", IsRegex: true,
			Pattern:     `rsa\.GenerateKey\([^,]+,\s*(?:512|768|1024)\b`,
			Severity:    types.SeverityHigh,
			Description: "RSA keys smaller than 2048 bits are considered weak by current standards.",
			Suggestion:  "Use at minimum 2048-bit RSA keys. Consider migrating to ECDSA P-256.",
			References:  []string{"NIST SP 800-131A"},
			Tags:        []string{"crypto"},
		},
		{
			ID: "crypto-jwt-none-alg", Name: "JWT Algorithm 'none' Acceptance", IsRegex: true,
			Pattern:     `(?i)alg.*none|ParseWithClaims.*(?:nil|none)`,
			Severity:    types.SeverityCritical,
			Description: "Accepting JWT tokens with algorithm 'none' allows forgery without a signature.",
			Suggestion:  "Always specify an allowed algorithm list when parsing JWTs.",
			References:  []string{"CVE-2015-9235"},
			Tags:        []string{"crypto", "jwt"},
		},
		{
			ID: "crypto-jwt-hmac-secret-short", Name: "Short JWT HMAC Secret", IsRegex: true,
			Pattern:     `jwt\.NewWithClaims.*HS256.*"[^"]{1,15}"`,
			Severity:    types.SeverityCritical,
			Description: "A short HMAC secret makes JWT tokens vulnerable to brute-force attacks.",
			Suggestion:  "Use a random secret of at least 256 bits generated by crypto/rand.",
			References:  []string{"CWE-326"},
			Tags:        []string{"crypto", "jwt"},
		},
		{
			ID: "crypto-rand-seed-time", Name: "math/rand Seeded with Time", IsRegex: true,
			Pattern:     `rand\.Seed\(time\.`,
			Severity:    types.SeverityHigh,
			Description: "Seeding math/rand with time.Now().UnixNano() is predictable and not suitable for security.",
			Suggestion:  "Use crypto/rand for all security-sensitive random value generation.",
			References:  []string{"CWE-338"},
			Tags:        []string{"crypto"},
		},
		{
			ID: "crypto-x509-skip-verify", Name: "x509 Certificate Verification Skipped", IsRegex: true,
			Pattern:     `InsecureSkipVerify:\s*true`,
			Severity:    types.SeverityCritical,
			Description: "Disabling TLS certificate verification allows man-in-the-middle attacks.",
			Suggestion:  "Load trusted CA certificates and set RootCAs in tls.Config.",
			References:  []string{"CWE-295"},
			Tags:        []string{"crypto", "tls"},
		},
		{
			ID: "crypto-pbkdf-low-iter", Name: "PBKDF2 Low Iteration Count", IsRegex: true,
			Pattern:     `pbkdf2\.Key\([^,]+,[^,]+,[^,]+,\s*(?:[1-9]\d{0,3})\b`,
			Severity:    types.SeverityHigh,
			Description: "PBKDF2 with fewer than 10,000 iterations is susceptible to brute-force attacks.",
			Suggestion:  "Use at least 100,000 iterations with SHA-256, or prefer Argon2id.",
			References:  []string{"NIST SP 800-132"},
			Tags:        []string{"crypto"},
		},
	}
}
