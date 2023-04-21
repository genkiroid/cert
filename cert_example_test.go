package cert

import (
	"fmt"
)

func ExampleCerts_String() {
	certs, _ := NewCerts([]string{"example.com"})

	fmt.Printf("%s", certs)
	// Output:
	// DomainName: example.com
	// IP:         127.0.0.1
	// Port:       443
	// Issuer:     CA for test
	// NotBefore:  2017-01-01 00:00:00 +0000 UTC
	// NotAfter:   2018-01-01 00:00:00 +0000 UTC
	// CommonName: example.com
	// SANs:       [example.com www.example.com]
	// Error:
}

func ExampleCerts_Markdown() {
	certs, _ := NewCerts([]string{"example.com"})

	fmt.Printf("%s", certs.Markdown())
	// Output:
	// DomainName | IP | Port | Issuer | NotBefore | NotAfter | CN | SANs | Error
	// --- | --- | --- | --- | --- | --- | --- | --- | ---
	// example.com | 127.0.0.1 | 443 | CA for test | 2017-01-01 00:00:00 +0000 UTC | 2018-01-01 00:00:00 +0000 UTC | example.com | example.com<br/>www.example.com<br/> |
}

func ExampleCerts_JSON() {
	certs, _ := NewCerts([]string{"example.com"})

	fmt.Printf("%s", certs.JSON())
	// Output:
	// [{"domainName":"example.com","ip":"127.0.0.1","port":"443","issuer":"CA for test","commonName":"example.com","sans":["example.com","www.example.com"],"notBefore":"2017-01-01 00:00:00 +0000 UTC","notAfter":"2018-01-01 00:00:00 +0000 UTC","error":""}]
}
