package cmd

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jclem/get/internal/sessions"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type sessionsFlags struct {
	Reveal bool `mapstructure:"reveal"`
}

const (
	flagReveal = "reveal"
)

// NewSessionsCmd creates the `get sessions` command tree.
func NewSessionsCmd() *cobra.Command {
	var flags sessionsFlags

	cmd := &cobra.Command{
		Use:   "sessions",
		Short: "Manage sessions",
		Long:  "List, show, and delete saved sessions.",
		Args:  cobra.NoArgs,
		PreRun: func(cmd *cobra.Command, _ []string) {
			v := viper.New()
			err := v.BindPFlags(cmd.Flags())
			cobra.CheckErr(err)
			err = v.Unmarshal(&flags)
			cobra.CheckErr(err)
		},
		Run: func(cmd *cobra.Command, _ []string) {
			mgr, err := sessions.NewManager()
			cobra.CheckErr(err)

			data := mgr.GetAll(flags.Reveal)

			b, err := json.MarshalIndent(data, "", "\t")
			cobra.CheckErr(err)

			_, err = fmt.Fprintln(cmd.OutOrStdout(), string(b))
			cobra.CheckErr(err)
		},
	}

	addRevealFlag(cmd)

	cmd.AddCommand(newSessionsShowCmd())
	cmd.AddCommand(newSessionsDeleteCmd())
	cmd.AddCommand(newSessionsClearCmd())
	cmd.AddCommand(newSessionsPathCmd())

	return cmd
}

func newSessionsShowCmd() *cobra.Command {
	var flags sessionsFlags

	cmd := &cobra.Command{
		Use:   "show <name>",
		Short: "Show a session by name",
		Args:  cobra.ExactArgs(1),
		PreRun: func(cmd *cobra.Command, _ []string) {
			v := viper.New()
			err := v.BindPFlags(cmd.Flags())
			cobra.CheckErr(err)
			err = v.Unmarshal(&flags)
			cobra.CheckErr(err)
		},
		Run: func(cmd *cobra.Command, args []string) {
			name := args[0]
			mgr, err := sessions.NewManager()
			cobra.CheckErr(err)

			all := mgr.GetAll(flags.Reveal)
			sess, ok := all[name]
			if !ok {
				cobra.CheckErr(fmt.Errorf("session not found: %s", name))
			}

			b, err := json.MarshalIndent(sess, "", "\t")
			cobra.CheckErr(err)

			_, err = fmt.Fprintln(cmd.OutOrStdout(), string(b))
			cobra.CheckErr(err)
		},
	}

	addRevealFlag(cmd)

	return cmd
}

func newSessionsDeleteCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete <name>",
		Short: "Delete a session by name",
		Args:  cobra.ExactArgs(1),
		Run: func(_ *cobra.Command, args []string) {
			name := args[0]
			mgr, err := sessions.NewManager()
			cobra.CheckErr(err)

			cobra.CheckErr(mgr.Delete(name))
		},
	}

	return cmd
}

func newSessionsClearCmd() *cobra.Command {
	var yes bool

	cmd := &cobra.Command{
		Use:   "clear",
		Short: "Delete all sessions",
		Run: func(cmd *cobra.Command, _ []string) {
			mgr, err := sessions.NewManager()
			cobra.CheckErr(err)

			if !yes {
				count := len(mgr.GetAll(true))

				_, err = fmt.Fprintf(cmd.OutOrStdout(), "This will delete %d session(s). Continue? [y/N]: ", count)
				cobra.CheckErr(err)

				in := cmd.InOrStdin()

				var resp string
				_, err = fmt.Fscan(in, &resp)
				cobra.CheckErr(err)

				switch strings.ToLower(strings.TrimSpace(resp)) {
				case "y", "yes":
					// Proceed.
				default:
					_, err = fmt.Fprintln(cmd.OutOrStdout(), "Aborted.")
					cobra.CheckErr(err)
					return
				}
			}

			cobra.CheckErr(mgr.Clear())
		},
	}

	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "Do not prompt for confirmation")

	return cmd
}

func addRevealFlag(cmd *cobra.Command) {
	cmd.Flags().BoolP(flagReveal, "r", false, "Reveal header values")
}

func newSessionsPathCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "path",
		Short: "Print the sessions file path",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, _ []string) {
			mgr, err := sessions.NewManager()
			cobra.CheckErr(err)

			_, err = fmt.Fprintln(cmd.OutOrStdout(), mgr.Path())
			cobra.CheckErr(err)
		},
	}

	return cmd
}
