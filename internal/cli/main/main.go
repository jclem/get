// Package main is the entry point for the CLI.
package main

import (
	"context"
	"log"

	"github.com/jclem/get/internal/cli"
)

func main() {
	if err := cli.Execute(context.Background()); err != nil {
		log.Fatal(err)
	}
}
