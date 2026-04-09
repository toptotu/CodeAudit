// Package analyzer provides Go AST parsing, static pattern matching, and
// code context extraction utilities used by all agents.
package analyzer

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/codeaudit/codeaudit/pkg/types"
)

// ParseDir walks a directory tree and returns CodeContext for every .go file.
func ParseDir(dir string, skipPaths []string) ([]*types.CodeContext, error) {
	skipSet := make(map[string]bool)
	for _, p := range skipPaths {
		skipSet[p] = true
	}

	var contexts []*types.CodeContext
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			base := filepath.Base(path)
			if skipSet[base] || base == "vendor" || base == ".git" || base == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".go" {
			return nil
		}
		ctx, err := ParseFile(path)
		if err != nil {
			return nil // skip unparseable files
		}
		contexts = append(contexts, ctx)
		return nil
	})
	return contexts, err
}

// ParseFile parses a single Go source file into a CodeContext.
func ParseFile(path string) (*types.CodeContext, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}

	ctx := &types.CodeContext{
		FilePath:    path,
		PackageName: f.Name.Name,
		RawSource:   string(src),
		Lines:       strings.Split(string(src), "\n"),
	}

	// Collect imports.
	for _, imp := range f.Imports {
		path := strings.Trim(imp.Path.Value, `"`)
		ctx.Imports = append(ctx.Imports, path)
	}

	// Walk declarations.
	for _, decl := range f.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			fi := types.FuncInfo{
				Name:       d.Name.Name,
				IsExported: d.Name.IsExported(),
				Line:       fset.Position(d.Pos()).Line,
			}
			if d.Recv != nil && len(d.Recv.List) > 0 {
				fi.Receiver = exprString(d.Recv.List[0].Type)
			}
			if d.Type.Params != nil {
				for _, p := range d.Type.Params.List {
					fi.Params = append(fi.Params, exprString(p.Type))
				}
			}
			if d.Type.Results != nil {
				for _, r := range d.Type.Results.List {
					fi.Returns = append(fi.Returns, exprString(r.Type))
				}
			}
			if d.Body != nil {
				start := fset.Position(d.Body.Pos()).Offset
				end := fset.Position(d.Body.End()).Offset
				if end <= len(src) {
					fi.Body = string(src[start:end])
				}
			}
			ctx.Functions = append(ctx.Functions, fi)

		case *ast.GenDecl:
			for _, spec := range d.Specs {
				switch s := spec.(type) {
				case *ast.TypeSpec:
					ti := types.TypeInfo{
						Name:       s.Name.Name,
						IsExported: s.Name.IsExported(),
						Line:       fset.Position(s.Pos()).Line,
					}
					switch s.Type.(type) {
					case *ast.StructType:
						ti.Kind = "struct"
					case *ast.InterfaceType:
						ti.Kind = "interface"
					default:
						ti.Kind = "alias"
					}
					ctx.Types = append(ctx.Types, ti)

				case *ast.ValueSpec:
					for i, name := range s.Names {
						vi := types.VarInfo{
							Name: name.Name,
							Line: fset.Position(s.Pos()).Line,
						}
						if s.Type != nil {
							vi.Type = exprString(s.Type)
						}
						if d.Tok == token.CONST {
							cv := types.ConstInfo{
								Name: name.Name,
								Line: fset.Position(s.Pos()).Line,
							}
							if i < len(s.Values) {
								cv.Value = exprString(s.Values[i])
							}
							ctx.Constants = append(ctx.Constants, cv)
						} else {
							ctx.Variables = append(ctx.Variables, vi)
						}
					}
				}
			}
		}
	}

	return ctx, nil
}

// MatchPattern scans lines for a pattern definition and returns any Findings.
func MatchPattern(ctx *types.CodeContext, pat types.SkillPattern, agentID string) []*types.Finding {
	if pat.IsAST {
		return matchAST(ctx, pat, agentID)
	}
	if pat.IsRegex {
		return matchRegex(ctx, pat, agentID)
	}
	return matchLiteral(ctx, pat, agentID)
}

func matchRegex(ctx *types.CodeContext, pat types.SkillPattern, agentID string) []*types.Finding {
	re, err := regexp.Compile(pat.Pattern)
	if err != nil {
		return nil
	}
	var findings []*types.Finding
	for i, line := range ctx.Lines {
		if re.MatchString(line) {
			findings = append(findings, makeFinding(ctx, pat, agentID, i+1, line))
		}
	}
	return findings
}

func matchLiteral(ctx *types.CodeContext, pat types.SkillPattern, agentID string) []*types.Finding {
	var findings []*types.Finding
	for i, line := range ctx.Lines {
		if strings.Contains(line, pat.Pattern) {
			findings = append(findings, makeFinding(ctx, pat, agentID, i+1, line))
		}
	}
	return findings
}

// matchAST performs simple function-call-level AST matching using the pattern
// as a fully-qualified call expression (e.g. "md5.New", "exec.Command").
func matchAST(ctx *types.CodeContext, pat types.SkillPattern, agentID string) []*types.Finding {
	parts := strings.SplitN(pat.Pattern, ".", 2)
	if len(parts) != 2 {
		return matchLiteral(ctx, pat, agentID)
	}
	pkg, fn := parts[0], parts[1]

	// Check the import is present.
	pkgImported := false
	for _, imp := range ctx.Imports {
		if strings.HasSuffix(imp, "/"+pkg) || imp == pkg {
			pkgImported = true
			break
		}
	}
	if !pkgImported {
		return nil
	}

	// Scan lines for the call.
	var findings []*types.Finding
	callLiteral := pkg + "." + fn
	for i, line := range ctx.Lines {
		if strings.Contains(line, callLiteral) {
			findings = append(findings, makeFinding(ctx, pat, agentID, i+1, line))
		}
	}
	return findings
}

func makeFinding(ctx *types.CodeContext, pat types.SkillPattern, agentID string, line int, snippet string) *types.Finding {
	return &types.Finding{
		AgentID:     agentID,
		SkillID:     pat.ID,
		RuleID:      pat.ID,
		Title:       pat.Name,
		Description: pat.Description,
		Severity:    pat.Severity,
		FilePath:    ctx.FilePath,
		Line:        line,
		CodeSnippet: strings.TrimSpace(snippet),
		Suggestion:  pat.Suggestion,
		References:  pat.References,
		Confidence:  0.85,
	}
}

// exprString returns a compact string representation of an AST expression.
func exprString(e ast.Expr) string {
	if e == nil {
		return ""
	}
	switch t := e.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.SelectorExpr:
		return exprString(t.X) + "." + t.Sel.Name
	case *ast.StarExpr:
		return "*" + exprString(t.X)
	case *ast.ArrayType:
		return "[]" + exprString(t.Elt)
	case *ast.MapType:
		return "map[" + exprString(t.Key) + "]" + exprString(t.Value)
	case *ast.InterfaceType:
		return "interface{}"
	case *ast.BasicLit:
		return t.Value
	default:
		return fmt.Sprintf("%T", e)
	}
}

// HasImport returns true if the context imports the given package path.
func HasImport(ctx *types.CodeContext, pkg string) bool {
	for _, imp := range ctx.Imports {
		if strings.HasSuffix(imp, "/"+pkg) || imp == pkg {
			return true
		}
	}
	return false
}

// LinesAround returns up to n lines before and after the given 1-indexed line.
func LinesAround(lines []string, lineNo, n int) string {
	start := lineNo - 1 - n
	if start < 0 {
		start = 0
	}
	end := lineNo - 1 + n
	if end >= len(lines) {
		end = len(lines) - 1
	}
	return strings.Join(lines[start:end+1], "\n")
}
