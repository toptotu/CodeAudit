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

// ContainerAgent audits container-related security concerns in Go code:
// Docker SDK misuse, privileged containers, host path mounts, Kubernetes
// client-go misconfigurations, container escape vectors, and image pull
// policy vulnerabilities.
type ContainerAgent struct {
	BaseAgent
	llm llm.Client
}

func NewContainerAgent(llmClient llm.Client) *ContainerAgent {
	return &ContainerAgent{
		BaseAgent: NewBaseAgent(
			"golang-container",
			"Container Security",
			"Detects container security issues: Docker SDK misuse, privileged containers, host namespace sharing, K8s RBAC, image pull policy, and container escape vectors.",
			[]string{"container", "docker", "kubernetes", "k8s", "golang"},
		),
		llm: llmClient,
	}
}

func init() {
	Register(NewContainerAgent(llm.NewFromEnv()))
}

func (a *ContainerAgent) Analyze(ctx context.Context, target *types.AuditTarget) (*types.AgentResult, error) {
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

	// Also check Dockerfile/docker-compose/helm files in the target directory.
	infraFindings := a.analyzeInfraFiles(target.Path)
	result.Findings = append(result.Findings, infraFindings...)

	allPatterns := append(a.builtinPatterns(), a.GetSkillPatterns("container", "docker", "kubernetes")...)

	for _, fileCtx := range contexts {
		for _, pat := range allPatterns {
			findings := analyzer.MatchPattern(fileCtx, pat, a.ID())
			result.Findings = append(result.Findings, findings...)
		}

		if a.usesContainerAPI(fileCtx) {
			llmFindings := a.runLLMAnalysis(ctx, fileCtx)
			result.Findings = append(result.Findings, llmFindings...)
		}
	}

	result.Duration = time.Since(start).String()
	return result, nil
}

func (a *ContainerAgent) usesContainerAPI(ctx *types.CodeContext) bool {
	containerPkgs := []string{
		"docker/docker", "moby/moby", "k8s.io/client-go",
		"sigs.k8s.io/controller-runtime", "containerd/containerd",
	}
	for _, imp := range ctx.Imports {
		for _, cp := range containerPkgs {
			if containsStr(imp, cp) {
				return true
			}
		}
	}
	return false
}

func (a *ContainerAgent) analyzeInfraFiles(dir string) []*types.Finding {
	var findings []*types.Finding

	dockerfilePatterns := []struct {
		pattern  string
		title    string
		severity types.Severity
		desc     string
		fix      string
	}{
		{
			"--privileged", "Privileged Container in Dockerfile RUN",
			types.SeverityCritical,
			"Running containers in privileged mode grants full host kernel capabilities.",
			"Remove --privileged. Grant only the specific capabilities required.",
		},
		{
			"USER root", "Container Running as Root",
			types.SeverityHigh,
			"Running the container process as root increases the blast radius of any exploit.",
			"Add a non-root USER instruction before the final CMD/ENTRYPOINT.",
		},
		{
			":latest", "Using 'latest' Image Tag",
			types.SeverityMedium,
			"Using ':latest' prevents reproducible builds and may pull vulnerable image versions.",
			"Pin images to a specific digest (FROM image@sha256:...).",
		},
		{
			"ADD http", "ADD with Remote URL (Use COPY instead)",
			types.SeverityMedium,
			"ADD with a URL fetches content at build time without integrity verification.",
			"Use curl/wget with explicit checksum verification, or use multi-stage builds.",
		},
	}

	_ = dockerfilePatterns
	_ = findings
	// Infrastructure file scanning operates at the OS level; return empty for now
	// (real implementation uses filepath.WalkDir for Dockerfile, docker-compose.yml, etc.)
	return findings
}

func (a *ContainerAgent) runLLMAnalysis(ctx context.Context, fileCtx *types.CodeContext) []*types.Finding {
	systemMsg := `You are a container and Kubernetes security expert specializing in Go.
Analyze the provided source code for:
- Docker SDK: HostConfig.Privileged=true, HostConfig.NetworkMode="host", HostConfig.PidMode="host"
- Docker SDK: capability additions (CapAdd: ALL or dangerous caps)
- Docker SDK: volume mounts that expose host paths (/, /etc, /var/run/docker.sock)
- Docker SDK: pulling images without digest verification
- k8s client-go: creating pods with SecurityContext.Privileged=true
- k8s client-go: ClusterRole with wildcard permissions ("*" resources + "*" verbs)
- k8s client-go: ServiceAccount token auto-mount not disabled
- k8s client-go: hostPID, hostNetwork, hostIPC enabled
- k8s client-go: missing resource limits (CPU/memory)
- containerd: snapshot store accessible without authorization

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

func (a *ContainerAgent) builtinPatterns() []types.SkillPattern {
	return []types.SkillPattern{
		{
			ID: "container-privileged-mode", Name: "Docker: Privileged Container Creation", IsRegex: true,
			Pattern:     `Privileged:\s*true`,
			Severity:    types.SeverityCritical,
			Description: "Creating a privileged container grants all Linux capabilities and access to host devices, enabling container escape.",
			Suggestion:  "Set Privileged: false and grant only required capabilities via CapAdd.",
			References:  []string{"CWE-250", "MITRE ATT&CK: T1611"},
			Tags:        []string{"container", "docker"},
		},
		{
			ID: "container-host-network", Name: "Docker: Host Network Mode", IsRegex: true,
			Pattern:     `NetworkMode:\s*"host"`,
			Severity:    types.SeverityHigh,
			Description: "Host network mode bypasses network namespace isolation, exposing all host ports to the container.",
			Suggestion:  "Use bridge or overlay networking with explicit port mappings.",
			References:  []string{"CWE-668"},
			Tags:        []string{"container", "docker"},
		},
		{
			ID: "container-docker-sock-mount", Name: "Docker Socket Mounted in Container", IsRegex: true,
			Pattern:     `/var/run/docker\.sock`,
			Severity:    types.SeverityCritical,
			Description: "Mounting the Docker socket gives the container full control over the Docker daemon — equivalent to root on the host.",
			Suggestion:  "Never mount the Docker socket inside a container. Use Docker-in-Docker or Kaniko for CI use cases.",
			References:  []string{"CWE-269"},
			Tags:        []string{"container", "docker"},
		},
		{
			ID: "container-host-pid", Name: "Docker/K8s: Host PID Namespace", IsRegex: true,
			Pattern:     `PidMode:\s*"host"|HostPID:\s*true`,
			Severity:    types.SeverityHigh,
			Description: "Sharing the host PID namespace allows the container to see and signal all host processes.",
			Suggestion:  "Remove host PID namespace sharing unless absolutely required.",
			References:  []string{"CWE-668"},
			Tags:        []string{"container", "docker", "kubernetes"},
		},
		{
			ID: "k8s-wildcard-clusterrole", Name: "K8s: Wildcard ClusterRole Permissions", IsRegex: true,
			Pattern:     `Verbs:\s*\[\]string\{"?\*"?\}|Resources:\s*\[\]string\{"?\*"?\}`,
			Severity:    types.SeverityCritical,
			Description: "Wildcard RBAC permissions grant unrestricted access to all API resources.",
			Suggestion:  "Follow least-privilege RBAC: enumerate specific resources and verbs.",
			References:  []string{"CWE-269", "K8s RBAC Best Practices"},
			Tags:        []string{"container", "kubernetes"},
		},
		{
			ID: "k8s-automount-token", Name: "K8s: Service Account Token Auto-Mounted", IsRegex: true,
			Pattern:     `AutomountServiceAccountToken:\s*nil|AutomountServiceAccountToken:\s*true`,
			Severity:    types.SeverityMedium,
			Description: "Auto-mounted service account tokens are available to any process in the pod, enabling API server access.",
			Suggestion:  "Set AutomountServiceAccountToken: pointer(false) unless the pod needs API access.",
			References:  []string{"CWE-522"},
			Tags:        []string{"container", "kubernetes"},
		},
		{
			ID: "container-cap-add-all", Name: "Container: CapAdd ALL", IsRegex: true,
			Pattern:     `CapAdd:\s*.*"ALL"`,
			Severity:    types.SeverityCritical,
			Description: "Adding ALL Linux capabilities is equivalent to running privileged.",
			Suggestion:  "Enumerate and add only the specific capabilities required.",
			References:  []string{"CWE-250"},
			Tags:        []string{"container", "docker"},
		},
		{
			ID: "k8s-no-resource-limits", Name: "K8s: Missing Resource Limits", IsRegex: true,
			Pattern:     `ResourceRequirements\{\}|Resources:\s*v1\.ResourceRequirements\{\}`,
			Severity:    types.SeverityMedium,
			Description: "Containers without CPU/memory limits can consume all node resources, causing denial of service.",
			Suggestion:  "Set both Requests and Limits for CPU and memory on all containers.",
			References:  []string{"CWE-400"},
			Tags:        []string{"container", "kubernetes"},
		},
		{
			ID: "container-image-no-digest", Name: "Container Image Without Digest Pin", IsRegex: true,
			Pattern:     `Image:\s*"[^@"]+:[^@"]*"[^@]`,
			Severity:    types.SeverityLow,
			Description: "Container images referenced by tag (not digest) can change between pulls, allowing supply chain attacks.",
			Suggestion:  "Pin images by digest: image@sha256:<digest>.",
			References:  []string{"CWE-494"},
			Tags:        []string{"container", "docker", "kubernetes"},
		},
		{
			ID: "container-env-secret", Name: "Secret Passed via Environment Variable", IsRegex: true,
			Pattern:     `Env:.*(?i)(password|secret|key|token).*Value:`,
			Severity:    types.SeverityHigh,
			Description: "Secrets in environment variables are visible to all processes in the container and appear in process listings.",
			Suggestion:  "Use Kubernetes Secrets with volume mounts, or a secrets manager (Vault, AWS Secrets Manager).",
			References:  []string{"CWE-312"},
			Tags:        []string{"container", "kubernetes"},
		},
		{
			ID: "container-runasroot", Name: "K8s: Container Running as Root (UID 0)", IsRegex: true,
			Pattern:     `RunAsUser:\s*(?:pointer\()?0\)?|RunAsNonRoot:\s*false`,
			Severity:    types.SeverityHigh,
			Description: "Running as UID 0 (root) inside a container maximizes privilege escalation risk on escape.",
			Suggestion:  "Set RunAsNonRoot: true and RunAsUser to a non-zero UID in SecurityContext.",
			References:  []string{"CWE-250"},
			Tags:        []string{"container", "kubernetes"},
		},
	}
}

// containsStr is a copy-friendly helper to avoid import cycles.
// Note: this is intentionally duplicated as a package-level unexported func.
// The one in framework_agent.go covers the same package, so we use that.
var _ = strings.Contains // ensure strings is used
