package main

import (
	"fmt"
	"os"

	"github.com/genkiroid/cert"
)

func main() {
	c, err := cert.NewCerts(os.Args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	fmt.Print(c.Markdown())
}
