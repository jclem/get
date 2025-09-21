// Package main is the executable for the get CLI.
package main

import (
	"context"

	"github.com/jclem/get/internal/cmd"
)

func main() {
	ctx := context.Background()
	cmd.ExecuteContext(ctx)
}
