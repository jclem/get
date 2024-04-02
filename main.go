// Package main is the entry point for the CLI.
package main

import (
	"context"
	"os"

	"github.com/jclem/get/internal/cli"
)

func main() {
	if err := cli.Execute(context.Background()); err != nil {
		os.Exit(1)
	}
}
