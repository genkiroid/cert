package cert

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"os"
	"testing"
	"time"
)

func stubCert() {
	serverCert = func(host, port string) ([]*x509.Certificate, string, error) {
		return []*x509.Certificate{
			{
				Issuer: pkix.Name{
					CommonName: "CA for test",
				},
				Subject: pkix.Name{
					CommonName: host,
				},
				DNSNames:  []string{host, "www." + host},
				NotBefore: time.Date(2017, time.January, 1, 0, 0, 0, 0, time.UTC),
				NotAfter:  time.Date(2018, time.January, 1, 0, 0, 0, 0, time.UTC),
			},
			{
				Issuer: pkix.Name{
					CommonName: "parent of CA for test",
				},
				Subject: pkix.Name{
					CommonName: host,
				},
				DNSNames:  []string{host, "*." + host},
				NotBefore: time.Date(2017, time.January, 1, 0, 0, 0, 0, time.UTC),
				NotAfter:  time.Date(2018, time.January, 1, 0, 0, 0, 0, time.UTC),
			},
		}, "127.0.0.1", nil
	}
}

func setup() {
	UTC = true
	stubCert()
}

func TestValidate(t *testing.T) {
	if err := validate([]string{"example.com"}); err != nil {
		t.Errorf(`unexpected err %s, want nil`, err.Error())
	}
}

func TestValidateError(t *testing.T) {
	if err := validate([]string{}); err == nil {
		t.Error(`unexpected nil, want error`)
	} else if err.Error() != "Input at least one domain name." {
		t.Errorf(`unexpected err message, want %q`, "Input at least one domain name.")
	}
}

func TestSplitHostPort(t *testing.T) {
	type want struct {
		host string
		port string
		err  string
	}
	var tests = []struct {
		input string
		want  want
	}{
		{"example.com", want{"example.com", defaultPort, ""}},
		{"example.com:443", want{"example.com", "443", ""}},
		{"imap.example.com:993", want{"imap.example.com", "993", ""}},
		{"smtp.example.com:465", want{"smtp.example.com", "465", ""}},
		{"example.com:", want{"example.com", defaultPort, ""}},
		{"example.com::", want{"", "", "address example.com::: too many colons in address"}},
		{"https://example.com", want{"example.com", defaultPort, ""}},
		{"https://example.com/path/to", want{"example.com", defaultPort, ""}},
	}

	for _, test := range tests {
		host, port, err := SplitHostPort(test.input)
		errMsg := ""
		if err != nil {
			errMsg = err.Error()
		}
		got := want{
			host,
			port,
			errMsg,
		}
		if got != test.want {
			t.Errorf("SplitHostPort(%q) = %v, want %v", test.input, got, test.want)
		}
	}
}

func TestNewCert(t *testing.T) {
	input := "example.com"

	c := NewCert(input)
	certChain, _, _ := serverCert(input, defaultPort)
	origCert := certChain[0]

	if _, ok := interface{}(c).(*Cert); !ok {
		t.Errorf(`NewCert(%q) was not returned *Cert`, input)
	}
	if c.DomainName != "example.com" {
		t.Errorf(`unexpected Cert.DomainName %q, want %q`, c.DomainName, "example.com")
	}
	if c.IP != "127.0.0.1" {
		t.Errorf(`unexpected Cert.IP %q, want %q`, c.IP, "127.0.0.1")
	}
	if c.Issuer != "CA for test" {
		t.Errorf(`unexpected Cert.Issuer %q, want %q`, c.Issuer, "CA for test")
	}
	if c.CommonName != "example.com" {
		t.Errorf(`unexpected Cert.CommonName %q, want %q`, c.CommonName, "example.com")
	}
	if len(c.SANs) != 2 {
		t.Errorf(`unexpected Cert.SANs length %q, want %q`, len(c.SANs), 2)
	}
	if c.SANs[0] != "example.com" {
		t.Errorf(`unexpected Cert.SANs[0] %q, want %q`, c.SANs[0], "example.com")
	}
	if c.SANs[1] != "www.example.com" {
		t.Errorf(`unexpected Cert.SANs[1] %q, want %q`, c.SANs[1], "www.example.com")
	}
	if c.NotBefore != origCert.NotBefore.String() {
		t.Errorf(`unexpected Cert.NotBefore %q, want %q`, c.NotBefore, origCert.NotBefore.String())
	}
	if c.NotAfter != origCert.NotAfter.String() {
		t.Errorf(`unexpected Cert.NotAfter %q, want %q`, c.NotAfter, origCert.NotAfter.String())
	}
	if c.Error != "" {
		t.Errorf(`unexpected Cert.Error %q, want %q`, c.Error, "")
	}
}

func TestNewCerts(t *testing.T) {
	input := []string{"example.com"}

	certs, _ := NewCerts(input)

	if _, ok := interface{}(certs).(Certs); !ok {
		t.Errorf(`unexpected return type %T, want Certs`, certs)
	}
}

func TestCertsAsString(t *testing.T) {
	certChain, _, _ := serverCert("example.com", defaultPort)
	origCert := certChain[0]

	expected := fmt.Sprintf(`DomainName: example.com
IP:         127.0.0.1
Issuer:     CA for test
NotBefore:  %s
NotAfter:   %s
CommonName: example.com
SANs:       [example.com www.example.com]
Error:      


`, origCert.NotBefore.String(), origCert.NotAfter.String())

	certs, _ := NewCerts([]string{"example.com"})

	if certs.String() != expected {
		t.Errorf(`unexpected return value %q, want %q`, certs.String(), expected)
	}
}

func TestCertsAsMarkdown(t *testing.T) {
	certChain, _, _ := serverCert("example.com", defaultPort)
	origCert := certChain[0]

	expected := fmt.Sprintf(`DomainName | IP | Issuer | NotBefore | NotAfter | CN | SANs | Error
--- | --- | --- | --- | --- | --- | --- | ---
example.com | 127.0.0.1 | CA for test | %s | %s | example.com | example.com<br/>www.example.com<br/> | 

`, origCert.NotBefore.String(), origCert.NotAfter.String())

	certs, _ := NewCerts([]string{"example.com"})

	if certs.Markdown() != expected {
		t.Errorf(`unexpected return value %q, want %q`, certs.Markdown(), expected)
	}
}

func TestCertsAsJSON(t *testing.T) {
	certChain, _, _ := serverCert("example.com", defaultPort)
	origCert := certChain[0]

	expected := fmt.Sprintf("[{\"domainName\":\"example.com\",\"ip\":\"127.0.0.1\",\"issuer\":\"CA for test\",\"commonName\":\"example.com\",\"sans\":[\"example.com\",\"www.example.com\"],\"notBefore\":%q,\"notAfter\":%q,\"error\":\"\"}]", origCert.NotBefore.String(), origCert.NotAfter.String())

	certs, _ := NewCerts([]string{"example.com"})

	if string(certs.JSON()) != expected {
		t.Errorf(`unexpected return value %q, want %q`, certs.JSON(), expected)
	}
}

func TestCertsEscapeStarInSANs(t *testing.T) {
	certs := Certs{
		&Cert{
			SANs: []string{"*.example.com"},
		},
	}

	certs = certs.escapeStar()

	if certs[0].SANs[0] != "\\*.example.com" {
		t.Errorf(`unexpected escaped value %q, want %q`, certs[0].SANs[0], "\\*.example.com")
	}
}

func TestSetUserTempl(t *testing.T) {
	_ = SetUserTempl("{{range .}}Issuer: {{.Issuer}}{{end}}")
	expected := "Issuer: CA for test"

	certs, _ := NewCerts([]string{"example.com"})

	if certs.String() != expected {
		t.Errorf(`unexpected return value %q, want %q`, certs.String(), expected)
	}

	userTempl = ""
}

func TestDetail(t *testing.T) {
	input := "example.com"

	c := NewCert(input)
	certChain, _, _ := serverCert(input, defaultPort)
	origCert := certChain[0]
	detail := c.Detail()

	if _, ok := interface{}(detail).(*x509.Certificate); !ok {
		t.Errorf(`Cert.Detail() was not returned *x509.Certificate`)
	}

	if detail.Issuer.CommonName != origCert.Issuer.CommonName {
		t.Errorf(`unexpected issuer common name %q, want %q`, detail.Issuer.CommonName, origCert.Issuer.CommonName)
	}
}

func TestCertChain(t *testing.T) {
	input := "example.com"

	c := NewCert(input)
	expectedChain, _, _ := serverCert(input, defaultPort)
	certChain := c.CertChain()

	if _, ok := interface{}(certChain).([]*x509.Certificate); !ok {
		t.Errorf(`Cert.CertChain() was not returned []*x509.Certificate`)
	}

	if len(expectedChain) != len(certChain) {
		t.Errorf(`unexpected length %q, want %q`, len(certChain), len(expectedChain))
	}

	if certChain[0].Issuer.CommonName != "CA for test" {
		t.Errorf(`unexpected issuer common name %q, want %q`, certChain[0].Issuer.CommonName, "CA for test")
	}

	if certChain[1].Issuer.CommonName != "parent of CA for test" {
		t.Errorf(`unexpected issuer common name %q, want %q`, certChain[1].Issuer.CommonName, "parent of CA for test")
	}
}

func TestCipherSuite(t *testing.T) {
	CipherSuite = "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305"
	if _, err := cipherSuite(); err != nil {
		t.Errorf(`unexpected err %s, want nil`, err.Error())
	}
}

func TestCipherSuiteError(t *testing.T) {
	CipherSuite = "UNSUPPORTED_CIPHER_SUITE"
	want := "UNSUPPORTED_CIPHER_SUITE is unsupported cipher suite or tls1.3 cipher suite."

	if _, err := cipherSuite(); err == nil {
		t.Error(`unexpected nil, want error`)
	} else if err.Error() != want {
		t.Errorf(`unexpected err message, want %q`, want)
	}
}

func TestTlsVersion(t *testing.T) {
	type want struct {
		version uint16
	}
	var tests = []struct {
		cipherSuite string
		want        want
	}{
		{"", want{0}}, // 0 means TLS1.3 currently
		{"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305", want{tls.VersionTLS12}},
	}

	for _, test := range tests {
		CipherSuite = test.cipherSuite
		v := tlsVersion()
		got := want{v}
		if got != test.want {
			t.Errorf("tlsVersion() = %v, want %v", got, test.want)
		}
	}
}

func TestMain(m *testing.M) {
	setup()
	os.Exit(m.Run())
}
