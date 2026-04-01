// Package llm provides a thin abstraction over LLM backends used for AI-assisted
// vulnerability analysis. Currently supports OpenAI-compatible APIs.
package llm

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	openai "github.com/sashabaranov/go-openai"
)

// Client is the interface every LLM backend must satisfy.
type Client interface {
	Complete(ctx context.Context, req *Request) (*Response, error)
}

// Request is an LLM completion request.
type Request struct {
	SystemMsg   string
	UserMsg     string
	Model       string
	MaxTokens   int
	Temperature float32
}

// Response wraps the LLM output.
type Response struct {
	Content string
	Model   string
	Tokens  int
}

// OpenAIClient wraps the openai SDK.
type OpenAIClient struct {
	client  *openai.Client
	model   string
	baseURL string
}

// NewFromEnv creates an LLM client from environment variables.
// Supported env vars: OPENAI_API_KEY, OPENAI_BASE_URL, OPENAI_MODEL.
// Falls back to a no-op stub when the key is absent.
func NewFromEnv() Client {
	key := os.Getenv("OPENAI_API_KEY")
	if key == "" {
		return &stubClient{}
	}

	cfg := openai.DefaultConfig(key)
	if base := os.Getenv("OPENAI_BASE_URL"); base != "" {
		cfg.BaseURL = base
	}

	model := os.Getenv("OPENAI_MODEL")
	if model == "" {
		model = openai.GPT4o
	}

	return &OpenAIClient{
		client: openai.NewClientWithConfig(cfg),
		model:  model,
	}
}

func (c *OpenAIClient) Complete(ctx context.Context, req *Request) (*Response, error) {
	model := req.Model
	if model == "" {
		model = c.model
	}
	maxTokens := req.MaxTokens
	if maxTokens == 0 {
		maxTokens = 2048
	}
	temp := req.Temperature
	if temp == 0 {
		temp = 0.2
	}

	msgs := []openai.ChatCompletionMessage{
		{Role: openai.ChatMessageRoleSystem, Content: req.SystemMsg},
		{Role: openai.ChatMessageRoleUser, Content: req.UserMsg},
	}

	resp, err := c.client.CreateChatCompletion(ctx, openai.ChatCompletionRequest{
		Model:       model,
		Messages:    msgs,
		MaxTokens:   maxTokens,
		Temperature: temp,
	})
	if err != nil {
		return nil, fmt.Errorf("openai completion: %w", err)
	}
	if len(resp.Choices) == 0 {
		return nil, errors.New("empty response from LLM")
	}

	return &Response{
		Content: resp.Choices[0].Message.Content,
		Model:   resp.Model,
		Tokens:  resp.Usage.TotalTokens,
	}, nil
}

// stubClient returns a placeholder when no API key is configured.
type stubClient struct{}

func (s *stubClient) Complete(_ context.Context, req *Request) (*Response, error) {
	return &Response{
		Content: "[LLM analysis unavailable – set OPENAI_API_KEY to enable AI-assisted findings]",
		Model:   "stub",
	}, nil
}

// BuildPromptFromTemplate replaces {{.Field}} placeholders in a template string.
func BuildPromptFromTemplate(tmpl string, vars map[string]string) string {
	result := tmpl
	for k, v := range vars {
		result = strings.ReplaceAll(result, "{{."+k+"}}", v)
	}
	return result
}
