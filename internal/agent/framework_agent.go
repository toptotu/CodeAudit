package agent

import (
	"context"
	"fmt"
	"time"

	"github.com/codeaudit/codeaudit/internal/analyzer"
	"github.com/codeaudit/codeaudit/internal/llm"
	"github.com/codeaudit/codeaudit/pkg/types"
)

// FrameworkAgent audits Golang web and RPC frameworks:
// Gin, Echo, Fiber, gRPC, go-zero, Hertz, chi.
// It detects framework-specific misconfigurations and missing security controls.
type FrameworkAgent struct {
	BaseAgent
	llm llm.Client
}

func NewFrameworkAgent(llmClient llm.Client) *FrameworkAgent {
	return &FrameworkAgent{
		BaseAgent: NewBaseAgent(
			"golang-framework",
			"Golang Framework Security",
			"Detects security misconfigurations in Gin, Echo, Fiber, gRPC, go-zero, chi and other Go web/RPC frameworks.",
			[]string{"framework", "gin", "echo", "fiber", "grpc", "go-zero", "hertz", "chi", "golang"},
		),
		llm: llmClient,
	}
}

func init() {
	Register(NewFrameworkAgent(llm.NewFromEnv()))
}

func (a *FrameworkAgent) Analyze(ctx context.Context, target *types.AuditTarget) (*types.AgentResult, error) {
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

	allPatterns := append(a.builtinPatterns(), a.GetSkillPatterns()...)

	for _, fileCtx := range contexts {
		for _, pat := range allPatterns {
			findings := analyzer.MatchPattern(fileCtx, pat, a.ID())
			result.Findings = append(result.Findings, findings...)
		}

		if a.usesFramework(fileCtx) {
			llmFindings := a.runLLMAnalysis(ctx, fileCtx)
			result.Findings = append(result.Findings, llmFindings...)
		}
	}

	result.Duration = time.Since(start).String()
	return result, nil
}

func (a *FrameworkAgent) usesFramework(ctx *types.CodeContext) bool {
	for _, imp := range ctx.Imports {
		for _, fw := range []string{
			"gin-gonic/gin", "labstack/echo", "gofiber/fiber",
			"google.golang.org/grpc", "go-zero", "cloudwego/hertz",
			"go-chi/chi",
		} {
			if contains(imp, fw) {
				return true
			}
		}
	}
	return false
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && (s[len(s)-len(sub):] == sub || containsStr(s, sub)))
}

func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func (a *FrameworkAgent) runLLMAnalysis(ctx context.Context, fileCtx *types.CodeContext) []*types.Finding {
	systemMsg := `You are an expert in Golang web framework security (Gin, Echo, Fiber, gRPC, go-zero, chi).
Analyze the provided Go source file and identify:
- Missing authentication/authorization middleware
- CORS misconfiguration (allow all origins, allow credentials with wildcard)
- Missing rate limiting
- gRPC: missing interceptors for auth, logging, panic recovery
- Missing CSRF protection on state-changing endpoints
- Debug endpoints exposed in production (pprof, swagger without auth)
- Template injection (html/template with RawHTML)
- Improper Content-Type handling (json binding without validation)
- Missing TLS/mTLS on gRPC server
- go-zero: missing JWT or API key middleware

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

func (a *FrameworkAgent) builtinPatterns() []types.SkillPattern {
	return []types.SkillPattern{
		// Gin
		{
			ID: "gin-cors-all-origins", Name: "Gin: CORS All Origins Allowed", IsRegex: true,
			Pattern:     `cors\.New\(cors\.Config\{[^}]*AllowAllOrigins:\s*true`,
			Severity:    types.SeverityHigh,
			Description: "Allowing all CORS origins enables cross-origin data theft when combined with credentials.",
			Suggestion:  "Specify an explicit AllowOrigins allowlist instead of AllowAllOrigins:true.",
			References:  []string{"CWE-942"},
			Tags:        []string{"framework", "gin"},
		},
		{
			ID: "gin-debug-mode", Name: "Gin: Debug Mode in Production", IsRegex: true,
			Pattern:     `gin\.Default\(\)|gin\.SetMode\("debug"\)`,
			Severity:    types.SeverityMedium,
			Description: "Gin debug mode exposes verbose route logs and stack traces, aiding attackers.",
			Suggestion:  "Use gin.SetMode(gin.ReleaseMode) in production.",
			References:  []string{"CWE-489"},
			Tags:        []string{"framework", "gin"},
		},
		{
			ID: "gin-no-auth-middleware", Name: "Gin: Route Group Without Auth Middleware", IsRegex: true,
			Pattern:     `\.Group\("[^"]*"\)\s*\{`,
			Severity:    types.SeverityInfo,
			Description: "Route group defined without explicit authentication middleware applied.",
			Suggestion:  "Attach JWT/session middleware to route groups that serve protected resources.",
			References:  []string{"CWE-306"},
			Tags:        []string{"framework", "gin"},
		},
		// Echo
		{
			ID: "echo-no-csrf", Name: "Echo: Missing CSRF Middleware", IsRegex: true,
			Pattern:     `echo\.New\(\)`,
			Severity:    types.SeverityInfo,
			Description: "Echo instance created without CSRF middleware — verify CSRF protection is applied.",
			Suggestion:  "Use middleware.CSRFWithConfig on state-changing routes.",
			References:  []string{"CWE-352"},
			Tags:        []string{"framework", "echo"},
		},
		{
			ID: "echo-bind-no-validate", Name: "Echo: Bind Without Validation", IsRegex: true,
			Pattern:     `c\.Bind\(&`,
			Severity:    types.SeverityMedium,
			Description: "echo.Context.Bind() deserializes input without explicit validation.",
			Suggestion:  "Follow Bind with c.Validate() or use a validation middleware.",
			References:  []string{"CWE-20"},
			Tags:        []string{"framework", "echo"},
		},
		// Fiber
		{
			ID: "fiber-cors-all-origins", Name: "Fiber: CORS All Origins", IsRegex: true,
			Pattern:     `cors\.New\(\)`,
			Severity:    types.SeverityMedium,
			Description: "Default fiber cors.New() allows all origins — review CORS config explicitly.",
			Suggestion:  "Configure fiber cors.Config with a specific AllowOrigins list.",
			References:  []string{"CWE-942"},
			Tags:        []string{"framework", "fiber"},
		},
		// gRPC
		{
			ID: "grpc-no-creds", Name: "gRPC: Insecure Server (No TLS)", IsRegex: true,
			Pattern:     `grpc\.NewServer\(\)`,
			Severity:    types.SeverityHigh,
			Description: "gRPC server started without transport credentials — all traffic is plaintext.",
			Suggestion:  "Pass grpc.Creds(credentials.NewTLS(tlsCfg)) when creating the server.",
			References:  []string{"CWE-319"},
			Tags:        []string{"framework", "grpc"},
		},
		{
			ID: "grpc-no-interceptor", Name: "gRPC: No Unary Interceptor", IsRegex: true,
			Pattern:     `grpc\.NewServer\(\)`,
			Severity:    types.SeverityMedium,
			Description: "gRPC server has no unary interceptor — authentication and logging may be missing.",
			Suggestion:  "Add grpc.UnaryInterceptor() for auth, logging and panic recovery.",
			References:  []string{"CWE-306"},
			Tags:        []string{"framework", "grpc"},
		},
		// pprof exposure
		{
			ID: "pprof-exposed", Name: "pprof Debug Endpoint Exposed", IsRegex: true,
			Pattern:     `_ "net/http/pprof"`,
			Severity:    types.SeverityHigh,
			Description: "Importing net/http/pprof registers profiling endpoints on the default ServeMux, exposing heap/goroutine data.",
			Suggestion:  "Serve pprof on a separate internal port or protect with authentication.",
			References:  []string{"CWE-200"},
			Tags:        []string{"framework", "general"},
		},
		// Swagger without auth
		{
			ID: "swagger-exposed", Name: "Swagger UI Potentially Exposed", IsRegex: true,
			Pattern:     `swaggerFiles|swagger-ui`,
			Severity:    types.SeverityMedium,
			Description: "Swagger UI may expose API schema in production without access control.",
			Suggestion:  "Gate Swagger endpoints behind authentication or disable in production builds.",
			References:  []string{"CWE-200"},
			Tags:        []string{"framework", "general"},
		},
	}
}
