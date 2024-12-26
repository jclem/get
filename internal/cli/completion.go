package cli

import "github.com/spf13/cobra"

// https://github.com/spf13/cobra/issues/1915
var enableCompletionCmd = &cobra.Command{
	Use:    "_____required_for_completion_____",
	Hidden: true,
	Run: func(_ *cobra.Command, _ []string) {
	},
}

func init() {
	rootCmd.AddCommand(enableCompletionCmd)
}
