package cli

import (
	"fmt"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/jclem/get/internal/session"
	"github.com/spf13/cobra"
)

var sessionCmd = &cobra.Command{
	Use:   "session",
	Short: "Manage sessions",
}

var sessionListCmd = &cobra.Command{
	Use:   "list",
	Short: "List sessions",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := session.ReadConfig()
		if err != nil {
			return fmt.Errorf("could not get configuration: %w", err)
		}

		// TSV output
		w := tabwriter.NewWriter(cmd.OutOrStdout(), 4, 4, 4, ' ', 0)
		_, _ = fmt.Fprintln(w, "Name\tHeaders")

		names := make([]string, 0, len(cfg.Sessions))
		for name := range cfg.Sessions {
			names = append(names, name)
		}

		slices.Sort(names)

		for _, name := range names {
			ssn := cfg.Sessions[name]

			headerNames := make([]string, 0, len(ssn.Headers))
			for name := range ssn.Headers {
				headerNames = append(headerNames, name)
			}

			slices.Sort(headerNames)
			headers := []string{}

			for i, name := range headerNames {
				v := ssn.Headers[name]
				for j, vv := range v {
					if i > 0 || j > 0 {
						headers = append(headers, fmt.Sprintf("\t%s: %s", name, vv))
					} else {
						headers = append(headers, fmt.Sprintf("%s: %s", name, vv))
					}
				}
			}

			_, _ = fmt.Fprintf(w, "%s\t%s\n", name, strings.Join(headers, "\n"))
		}

		if err := w.Flush(); err != nil {
			return fmt.Errorf("could not flush output: %w", err)
		}

		return nil
	},
}

var sessionDeleteCmd = &cobra.Command{
	Use:   "delete <name>",
	Short: "Delete a session by name",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]

		cfg, err := session.ReadConfig()
		if err != nil {
			return fmt.Errorf("could not get configuration: %w", err)
		}

		if _, ok := cfg.Sessions[name]; !ok {
			return fmt.Errorf("no session with name %q", name)
		}

		delete(cfg.Sessions, name)

		if err := session.WriteConfig(cfg); err != nil {
			return fmt.Errorf("could not write configuration: %w", err)
		}

		return nil
	},
}

func init() { //nolint:gochecknoinits
	sessionCmd.AddCommand(sessionListCmd)
	sessionCmd.AddCommand(sessionDeleteCmd)
	rootCmd.AddCommand(sessionCmd)
}
