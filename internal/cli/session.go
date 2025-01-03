package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/jclem/get/internal/session"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/exp/maps"
)

type sessionFlags struct {
	JSON bool `mapstructure:"json"`
}

const (
	sessionFlagJSON = "json"
)

var sessionCmd = &cobra.Command{
	Use:   "session",
	Short: "Manage sessions",
}

var sessionCmdFlags sessionFlags

var sessionListCmd = &cobra.Command{
	Use:   "list",
	Short: "List sessions",
	PreRunE: func(cmd *cobra.Command, _ []string) error {
		if err := viper.BindPFlags(cmd.Flags()); err != nil {
			return fmt.Errorf("bind flags: %w", err)
		}

		if err := viper.Unmarshal(&sessionCmdFlags); err != nil {
			return fmt.Errorf("unmarshal flags: %w", err)
		}

		return nil
	},
	RunE: func(cmd *cobra.Command, _ []string) error {
		cfg, err := session.ReadConfig()
		if err != nil {
			return fmt.Errorf("get configuration: %w", err)
		}

		if sessionCmdFlags.JSON {
			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			enc.SetEscapeHTML(false)

			if err := enc.Encode(cfg.Sessions); err != nil {
				return fmt.Errorf("encode session: %w", err)
			}

			return nil
		}

		w := newTabwriter(cmd)
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
			return fmt.Errorf("flush output: %w", err)
		}

		return nil
	},
}

var sessionShowCmd = &cobra.Command{
	Use:   "show <name>",
	Short: "Show a session by name",
	Args:  cobra.ExactArgs(1),
	PreRunE: func(cmd *cobra.Command, _ []string) error {
		if err := viper.BindPFlags(cmd.Flags()); err != nil {
			return fmt.Errorf("bind flags: %w", err)
		}

		if err := viper.Unmarshal(&sessionCmdFlags); err != nil {
			return fmt.Errorf("unmarshal flags: %w", err)
		}

		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]

		cfg, err := session.ReadConfig()
		if err != nil {
			return fmt.Errorf("get configuration: %w", err)
		}

		ssn, ok := cfg.Sessions[name]
		if !ok {
			return fmt.Errorf("no session with name %q", name)
		}

		if sessionCmdFlags.JSON {
			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")

			if err := enc.Encode(ssn); err != nil {
				return fmt.Errorf("encode session: %w", err)
			}

			return nil
		}

		w := newTabwriter(cmd)

		headerNames := maps.Keys(ssn.Headers)
		slices.Sort(headerNames)

		for _, name := range headerNames {
			values := ssn.Headers[name]
			for _, value := range values {
				_, _ = fmt.Fprintf(w, "%s: %s\n", name, value)
			}
		}

		if err := w.Flush(); err != nil {
			return fmt.Errorf("flush output: %w", err)
		}

		return nil
	},
}

var sessionEditCmd = &cobra.Command{
	Use:   "edit",
	Short: "Edit session by using $EDITOR",
	RunE: func(cmd *cobra.Command, _ []string) error {
		path := session.SessionsPath()

		editor := os.Getenv("EDITOR")
		if editor == "" {
			return errors.New("no $EDITOR set")
		}

		c := exec.CommandContext(cmd.Context(), editor, path)
		c.Stdin = os.Stdin
		c.Stdout = os.Stdout
		if err := c.Run(); err != nil {
			return fmt.Errorf("run editor: %w", err)
		}

		return nil
	},
}

var sessionDeleteCmd = &cobra.Command{
	Use:   "delete <name>",
	Short: "Delete a session by name",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		name := args[0]

		cfg, err := session.ReadConfig()
		if err != nil {
			return fmt.Errorf("get configuration: %w", err)
		}

		if _, ok := cfg.Sessions[name]; !ok {
			return fmt.Errorf("no session with name %q", name)
		}

		delete(cfg.Sessions, name)

		if err := session.WriteConfig(cfg); err != nil {
			return fmt.Errorf("write configuration: %w", err)
		}

		return nil
	},
}

func init() {
	sessionListCmd.Flags().BoolP(sessionFlagJSON, "j", false, "output as JSON")
	sessionCmd.AddCommand(sessionListCmd)

	sessionShowCmd.Flags().BoolP(sessionFlagJSON, "j", false, "output as JSON")
	sessionCmd.AddCommand(sessionShowCmd)

	sessionCmd.AddCommand(sessionEditCmd)
	sessionCmd.AddCommand(sessionDeleteCmd)

	rootCmd.AddCommand(sessionCmd)
}

func newTabwriter(cmd *cobra.Command) *tabwriter.Writer {
	return tabwriter.NewWriter(cmd.OutOrStdout(), 4, 4, 4, ' ', 0) //nolint:mnd
}
