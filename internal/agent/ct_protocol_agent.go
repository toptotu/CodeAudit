package agent

import (
	"context"
	"fmt"
	"time"

	"github.com/codeaudit/codeaudit/internal/analyzer"
	"github.com/codeaudit/codeaudit/internal/llm"
	"github.com/codeaudit/codeaudit/pkg/types"
)

// CTProtocolAgent audits Certificate Transparency (CT) and broader PKI/TLS
// protocol implementations in Go: ct-go, trillian, certificate parsing,
// Merkle tree operations, timestamp validation, and RFC 6962 compliance.
//
// This is the domain-expert agent for CT-specific security patterns that
// general security scanners never catch.
type CTProtocolAgent struct {
	BaseAgent
	llm llm.Client
}

func NewCTProtocolAgent(llmClient llm.Client) *CTProtocolAgent {
	return &CTProtocolAgent{
		BaseAgent: NewBaseAgent(
			"golang-ct-protocol",
			"CT Protocol Security",
			"Detects Certificate Transparency (CT) protocol vulnerabilities: timestamp manipulation, Merkle tree attacks, SCT forgery, and RFC 6962 compliance violations.",
			[]string{"ct", "protocol", "pki", "tls", "golang"},
		),
		llm: llmClient,
	}
}

func init() {
	Register(NewCTProtocolAgent(llm.NewFromEnv()))
}

func (a *CTProtocolAgent) Analyze(ctx context.Context, target *types.AuditTarget) (*types.AgentResult, error) {
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

	allPatterns := append(a.builtinPatterns(), a.GetSkillPatterns("ct", "protocol", "pki")...)

	for _, fileCtx := range contexts {
		for _, pat := range allPatterns {
			findings := analyzer.MatchPattern(fileCtx, pat, a.ID())
			result.Findings = append(result.Findings, findings...)
		}

		if a.usesCTLibs(fileCtx) {
			llmFindings := a.runLLMAnalysis(ctx, fileCtx)
			result.Findings = append(result.Findings, llmFindings...)
		}
	}

	result.Duration = time.Since(start).String()
	return result, nil
}

func (a *CTProtocolAgent) usesCTLibs(ctx *types.CodeContext) bool {
	ctPkgs := []string{
		"google/certificate-transparency-go",
		"transparency-dev/trillian",
		"certificate-transparency",
		"ct-go",
		"crypto/x509",
		"crypto/tls",
	}
	for _, imp := range ctx.Imports {
		for _, cp := range ctPkgs {
			if containsStr(imp, cp) {
				return true
			}
		}
	}
	return false
}

func (a *CTProtocolAgent) runLLMAnalysis(ctx context.Context, fileCtx *types.CodeContext) []*types.Finding {
	systemMsg := `You are a Certificate Transparency (CT) and PKI protocol security expert.
You specialize in Go implementations of RFC 6962 and RFC 9162 (CT v2).

Analyze the provided source for these CT-specific vulnerabilities:

1. SCT (Signed Certificate Timestamp) Forgery Risk
   - Accepting SCTs without verifying the log ID against a known-good log list
   - Missing signature verification on SCTs (DSA/ECDSA)
   - Ignoring SCT timestamp freshness (accepting old or future-dated SCTs)

2. Merkle Tree Integrity
   - Missing proof validation (inclusion proofs, consistency proofs)
   - Off-by-one errors in tree size calculations
   - Accepting unverified tree heads from the log server
   - Missing STH (Signed Tree Head) signature verification

3. Certificate Parsing Vulnerabilities
   - x509 parsing without size limits (DDoS via large cert)
   - Accepting certificates with critical unrecognised extensions
   - Name constraint bypass in leaf cert validation
   - Missing PKIX path validation steps

4. Timestamp Manipulation
   - Accepting SCTs with timestamps far in the future
   - Clock skew not bounded (accepting timestamps > MaxSCTFutureDrift)
   - Replay of old SCTs beyond the maximum merge delay

5. Log Server Client Security
   - Missing TLS verification when connecting to CT logs
   - No retry backoff (causing thundering herd on log unavailability)
   - Missing response size limits on get-entries calls

6. Trillian / Merkle backend
   - Missing hash function agility checks
   - Unvalidated Leaf identity hashes
   - Missing mutex on concurrent tree head updates

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
		MaxTokens: 3000,
	})
	if err != nil || resp == nil {
		return nil
	}
	return parseLLMFindings(resp.Content, fileCtx.FilePath, a.ID())
}

func (a *CTProtocolAgent) builtinPatterns() []types.SkillPattern {
	return []types.SkillPattern{
		{
			ID: "ct-sct-no-verify", Name: "CT: SCT Signature Not Verified", IsRegex: true,
			Pattern:     `VerifySignature|CheckSignature|VerifySCT`,
			Severity:    types.SeverityInfo,
			Description: "Ensure SCT cryptographic signatures are verified against the log's public key before trusting the timestamp.",
			Suggestion:  "Use ct.SignatureVerifier.VerifySignedCertificateTimestamp() from certificate-transparency-go.",
			References:  []string{"RFC 6962 §2.1.3"},
			Tags:        []string{"ct", "protocol"},
		},
		{
			ID: "ct-no-inclusion-proof", Name: "CT: Missing Inclusion Proof Verification", IsRegex: true,
			Pattern:     `GetProofByHash|GetEntryAndProof`,
			Severity:    types.SeverityMedium,
			Description: "Fetching inclusion proofs without verifying them provides no security guarantee.",
			Suggestion:  "Always call merkle.VerifyInclusion() after retrieving a proof.",
			References:  []string{"RFC 6962 §2.1.3"},
			Tags:        []string{"ct", "protocol"},
		},
		{
			ID: "ct-sth-no-verify", Name: "CT: STH Not Verified", IsRegex: true,
			Pattern:     `GetSTH\b`,
			Severity:    types.SeverityHigh,
			Description: "An unverified Signed Tree Head allows a malicious CT log to present a split view.",
			Suggestion:  "Verify the STH signature with the log's public key and check consistency with previous STHs.",
			References:  []string{"RFC 6962 §3.5"},
			Tags:        []string{"ct", "protocol"},
		},
		{
			ID: "ct-timestamp-no-bounds", Name: "CT: SCT Timestamp Not Bounded", IsRegex: true,
			Pattern:     `Timestamp|SCTTimestamp`,
			Severity:    types.SeverityMedium,
			Description: "SCT timestamps must be checked: not more than MaxSCTFutureDrift seconds in the future, and not older than log's maximum merge delay.",
			Suggestion:  "Add bounds checking: reject SCTs with timestamps outside [now-MMD, now+drift].",
			References:  []string{"RFC 6962 §3.1"},
			Tags:        []string{"ct", "protocol"},
		},
		{
			ID: "ct-log-id-no-check", Name: "CT: Log ID Not Validated", IsRegex: true,
			Pattern:     `LogID|log_id`,
			Severity:    types.SeverityHigh,
			Description: "Accepting SCTs with arbitrary Log IDs enables spoofing by rogue CT logs not in the known-good log list.",
			Suggestion:  "Validate the Log ID against Chrome's or Apple's trusted CT log list.",
			References:  []string{"RFC 6962 §3.2", "Chrome CT Policy"},
			Tags:        []string{"ct", "protocol"},
		},
		{
			ID: "ct-tls-no-verify-log", Name: "CT: TLS Verification Missing for Log Connection", IsRegex: true,
			Pattern:     `jsonclient\.New\(|client\.New\(`,
			Severity:    types.SeverityHigh,
			Description: "CT log HTTP client created without explicit TLS verification configuration.",
			Suggestion:  "Pass an http.Client with tls.Config.RootCAs set to the trusted CA pool.",
			References:  []string{"CWE-295"},
			Tags:        []string{"ct", "protocol"},
		},
		{
			ID: "ct-cert-size-no-limit", Name: "CT: Certificate Parsing Without Size Limit", IsRegex: true,
			Pattern:     `x509\.ParseCertificate\b`,
			Severity:    types.SeverityMedium,
			Description: "Parsing untrusted X.509 certificates without size limits can cause excessive CPU/memory consumption.",
			Suggestion:  "Limit certificate DER byte size before calling x509.ParseCertificate (e.g. max 64KB).",
			References:  []string{"CWE-400"},
			Tags:        []string{"ct", "pki", "protocol"},
		},
		{
			ID: "ct-merkle-no-consistency", Name: "CT: No Consistency Proof Between STHs", IsRegex: true,
			Pattern:     `GetSTHConsistency`,
			Severity:    types.SeverityMedium,
			Description: "Fetching consistency proofs without verifying them allows a log to silently fork its tree.",
			Suggestion:  "Call merkle.VerifyConsistency() with both old and new STHs after retrieving the proof.",
			References:  []string{"RFC 6962 §2.1.2"},
			Tags:        []string{"ct", "protocol"},
		},
		// General TLS / PKI patterns relevant to CT clients.
		{
			ID: "tls-min-version-old", Name: "TLS: Minimum Version Below 1.2", IsRegex: true,
			Pattern:     `MinVersion:\s*tls\.VersionTLS10|MinVersion:\s*tls\.VersionTLS11|MinVersion:\s*0\b`,
			Severity:    types.SeverityHigh,
			Description: "TLS 1.0 and 1.1 are deprecated and vulnerable to BEAST, POODLE, and other attacks.",
			Suggestion:  "Set MinVersion: tls.VersionTLS12 (or tls.VersionTLS13 where possible).",
			References:  []string{"RFC 8996"},
			Tags:        []string{"tls", "protocol"},
		},
		{
			ID: "tls-cipher-no-forward-secrecy", Name: "TLS: Cipher Suite Without Forward Secrecy", IsRegex: true,
			Pattern:     `tls\.TLS_RSA_WITH_AES|tls\.TLS_RSA_WITH_RC4`,
			Severity:    types.SeverityHigh,
			Description: "RSA key exchange ciphers lack forward secrecy — compromise of the private key reveals all past sessions.",
			Suggestion:  "Use only ECDHE cipher suites with ephemeral keys.",
			References:  []string{"CWE-311"},
			Tags:        []string{"tls", "protocol"},
		},
	}
}
