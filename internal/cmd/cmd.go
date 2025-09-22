// Package cmd provides the command-line interface for the get CLI.
package cmd

import (
	"context"

	"github.com/spf13/cobra"
)

// ExecuteContext creates a new root command and executes it with the given
// context.
//
// This will run the CLI with any flags and arguments given to the current
// process.
func ExecuteContext(ctx context.Context) {
	err := NewRootCmd().ExecuteContext(ctx) //nolint:contextcheck // wrong
	cobra.CheckErr(err)
}
