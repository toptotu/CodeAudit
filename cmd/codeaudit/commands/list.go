package commands

import (
	"fmt"
	"os"
	"strings"

	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"

	"github.com/codeaudit/codeaudit/internal/agent"
	_ "github.com/codeaudit/codeaudit/internal/agent" // register agents
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List all registered agents and their domains",
	RunE: func(cmd *cobra.Command, args []string) error {
		agents := agent.All()
		if len(agents) == 0 {
			fmt.Println("No agents registered.")
			return nil
		}

		table := tablewriter.NewTable(os.Stdout)
		table.Header("ID", "Name", "Domains", "Description")

		for _, a := range agents {
			domains := strings.Join(a.SupportedDomains(), ", ")
			desc := a.Description()
			if len(desc) > 60 {
				desc = desc[:57] + "..."
			}
			table.Append(a.ID(), a.Name(), domains, desc) //nolint:errcheck
		}
		return table.Render()
	},
}

func init() {
	rootCmd.AddCommand(listCmd)
}
