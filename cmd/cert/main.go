package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/genkiroid/cert"
)

var version = ""

func main() {
	var skipVerify bool
	var format string
	var showVersion bool

	flag.BoolVar(&skipVerify, "k", false, "Skip verification of server's certificate chain and host name.")
	flag.StringVar(&format, "f", "simple table", "Output format. md: as markdown, json: as JSON. ")
	flag.BoolVar(&showVersion, "v", false, "Show version.")
	flag.BoolVar(&showVersion, "version", false, "Show version.")
	flag.Parse()

	if showVersion {
		fmt.Println("cert version ", version)
		return
	}

	var c cert.Certs
	var err error

	cert.SkipVerify = skipVerify

	c, err = cert.NewCerts(flag.Args())
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	switch format {
	case "md":
		fmt.Printf("%s", c.Markdown())
	case "json":
		fmt.Printf("%s", c.JSON())
	default:
		fmt.Printf("%s", c)
	}
}
