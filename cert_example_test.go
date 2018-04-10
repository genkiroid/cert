package cert

import (
	"fmt"
)

func ExampleCerts_String() {
	UTC = true
	stubCert()
	certs, _ := NewCerts([]string{"example.com"})

	fmt.Printf("%s", certs)
	// Output:
	// DomainName: example.com
	// IP:         127.0.0.1
	// Issuer:     CA for test
	// NotBefore:  2016-12-31 15:00:00 +0000 UTC
	// NotAfter:   2017-12-31 15:00:00 +0000 UTC
	// CommonName: example.com
	// SANs:       [example.com www.example.com]
	// Error:
}

func ExampleCerts_Markdown() {
	UTC = true
	stubCert()
	certs, _ := NewCerts([]string{"example.com"})

	fmt.Printf("%s", certs.Markdown())
	// Output:
	// DomainName | IP | Issuer | NotBefore | NotAfter | CN | SANs | Error
	// --- | --- | --- | --- | --- | --- | --- | ---
	// example.com | 127.0.0.1 | CA for test | 2016-12-31 15:00:00 +0000 UTC | 2017-12-31 15:00:00 +0000 UTC | example.com | example.com<br/>www.example.com<br/> |
}

func ExampleCerts_JSON() {
	UTC = true
	stubCert()
	certs, _ := NewCerts([]string{"example.com"})

	fmt.Printf("%s", certs.JSON())
	// Output:
	// [{"domainName":"example.com","ip":"127.0.0.1","issuer":"CA for test","commonName":"example.com","sans":["example.com","www.example.com"],"notBefore":"2016-12-31 15:00:00 +0000 UTC","notAfter":"2017-12-31 15:00:00 +0000 UTC","error":""}]
}
