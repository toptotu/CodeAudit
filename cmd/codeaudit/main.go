// CodeAudit — Multi-agent Golang security auditing system.
package main

import (
	"os"

	"github.com/codeaudit/codeaudit/cmd/codeaudit/commands"
)

func main() {
	if err := commands.Execute(); err != nil {
		os.Exit(1)
	}
}
