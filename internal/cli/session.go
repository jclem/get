package cli

import (
	"fmt"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/jclem/get/internal/session"
	"github.com/spf13/cobra"
	"golang.org/x/exp/maps"
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

		w := tabwriter.NewWriter(cmd.OutOrStdout(), 4, 4, 4, ' ', 0)
		_, _ = fmt.Fprintln(w, "Name\tHeaders")

		names := maps.Keys(cfg.Sessions)
		slices.Sort(names)

		for _, name := range names {
			ssn := cfg.Sessions[name]

			headerNames := maps.Keys(ssn.Headers)
			slices.Sort(headerNames)

			headersList := []string{}
			for i, name := range headerNames {
				values := ssn.Headers[name]
				for j, value := range values {
					maybeTab := ""
					if i > 0 || j > 0 {
						maybeTab = "\t"
					}

					headersList = append(headersList, fmt.Sprintf("%s%s: %s", maybeTab, name, value))
				}
			}

			_, _ = fmt.Fprintf(w, "%s\t%s\n", name, strings.Join(headersList, "\n"))
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
