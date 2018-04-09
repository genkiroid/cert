package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/genkiroid/cert"
)

var version = ""

func main() {
	var format string
	var template string
	var skipVerify bool
	var showVersion bool

	flag.StringVar(&format, "f", "simple table", "Output format. md: as markdown, json: as JSON. ")
	flag.StringVar(&format, "format", "simple table", "Output format. md: as markdown, json: as JSON. ")
	flag.StringVar(&template, "t", "", "Output format as Go template string or Go template file path.")
	flag.StringVar(&template, "template", "", "Output format as Go template string or Go template file path.")
	flag.BoolVar(&skipVerify, "k", false, "Skip verification of server's certificate chain and host name.")
	flag.BoolVar(&skipVerify, "skip-verify", false, "Skip verification of server's certificate chain and host name.")
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

	if template == "" {
		switch format {
		case "md":
			fmt.Printf("%s", c.Markdown())
		case "json":
			fmt.Printf("%s", c.JSON())
		default:
			fmt.Printf("%s", c)
		}
		return
	}

	if err := cert.SetUserTempl(template); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	fmt.Printf("%s", c)
}
