package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/genkiroid/cert"
)

var f = flag.String("f", "plain text", "Output format. md as markdown.")

func main() {
	flag.Parse()
	c, err := cert.NewCerts(flag.Args())
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	switch *f {
	case "md":
		fmt.Printf("%s", c.Markdown())
	default:
		fmt.Printf("%s", c)
	}
}
