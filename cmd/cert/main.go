package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/genkiroid/cert"
)

var a = flag.Bool("a", false, "Async mode. Output in no particular order.")
var f = flag.String("f", "plain text", "Output format. md as markdown.")

func main() {
	flag.Parse()

	var c cert.Certs
	var err error
	if *a {
		c, err = cert.NewAsyncCerts(flag.Args())
	} else {
		c, err = cert.NewCerts(flag.Args())
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	switch *f {
	case "md":
		fmt.Printf("%s", c.Markdown())
	case "json":
		fmt.Printf("%s", c.JSON())
	default:
		fmt.Printf("%s", c)
	}
}
