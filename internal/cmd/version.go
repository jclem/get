package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// Version is the version of the get CLI.
// It can be overridden at build time using -ldflags:
//
//	go build -ldflags "-X github.com/jclem/get/internal/cmd.Version=1.0.0"
var Version = "dev"

// NewVersionCmd creates the `get version` command.
func NewVersionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print the version",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, _ []string) {
			_, err := fmt.Fprintln(cmd.OutOrStdout(), Version)
			cobra.CheckErr(err)
		},
	}

	return cmd
}
