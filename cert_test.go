package cert

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"
)

func stubCert() {
	serverCert = func(d string) (*x509.Certificate, error) {
		return &x509.Certificate{
			Issuer: pkix.Name{
				CommonName: "CA for test",
			},
			Subject: pkix.Name{
				CommonName: d,
			},
			DNSNames:  []string{d, "www." + d},
			NotBefore: time.Date(2017, time.January, 1, 0, 0, 0, 0, time.FixedZone("JST", 9*60*60)),
			NotAfter:  time.Date(2018, time.January, 1, 0, 0, 0, 0, time.FixedZone("JST", 9*60*60)),
		}, nil
	}
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

func TestNewCert(t *testing.T) {
	stubCert()

	input := "example.com"

	c := NewCert(input)

	if _, ok := interface{}(c).(*Cert); !ok {
		t.Errorf(`NewCert(%q) was not returned *Cert`, input)
	}
	if c.DomainName != "example.com" {
		t.Errorf(`unexpected Cert.DomainName %q, want %q`, c.DomainName, "example.com")
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
	if c.NotBefore != "2017-01-01 00:00:00 +0900 JST" {
		t.Errorf(`unexpected Cert.NotBefore %q, want %q`, c.NotBefore, "2017-01-01 00:00:00 +0900 JST")
	}
	if c.NotAfter != "2018-01-01 00:00:00 +0900 JST" {
		t.Errorf(`unexpected Cert.NotAfter %q, want %q`, c.NotAfter, "2018-01-01 00:00:00 +0900 JST")
	}
	if c.Error != "" {
		t.Errorf(`unexpected Cert.Error %q, want %q`, c.Error, "")
	}
}

func TestNewCerts(t *testing.T) {
	stubCert()

	input := []string{"example.com"}

	certs, _ := NewCerts(input)

	if _, ok := interface{}(certs).(Certs); !ok {
		t.Errorf(`unexpected return type %T, want Certs`, certs)
	}
}

func TestNewAsyncCerts(t *testing.T) {
	stubCert()

	input := []string{"example.com"}

	certs, _ := NewAsyncCerts(input)

	if _, ok := interface{}(certs).(Certs); !ok {
		t.Errorf(`unexpected return type %T, want Certs`, certs)
	}
}

func TestCertsAsString(t *testing.T) {
	stubCert()

	expected := `DomainName: example.com
Issuer:     CA for test
NotBefore:  2017-01-01 00:00:00 +0900 JST
NotAfter:   2018-01-01 00:00:00 +0900 JST
CommonName: example.com
SANs:       [example.com www.example.com]
Error:      


`

	certs, _ := NewCerts([]string{"example.com"})

	if certs.String() != expected {
		t.Errorf(`unexpected return value %q, want %q`, certs.String(), expected)
	}
}

func TestCertsAsMarkdown(t *testing.T) {
	stubCert()

	expected := `DomainName | Issuer | NotBefore | NotAfter | CN | SANs | Error
--- | --- | --- | --- | --- | --- | ---
example.com | CA for test | 2017-01-01 00:00:00 +0900 JST | 2018-01-01 00:00:00 +0900 JST | example.com | example.com<br/>www.example.com<br/> | 

`

	certs, _ := NewCerts([]string{"example.com"})

	if certs.Markdown() != expected {
		t.Errorf(`unexpected return value %q, want %q`, certs.Markdown(), expected)
	}
}

func TestCertsAsJSON(t *testing.T) {
	stubCert()

	expected := `[{"DomainName":"example.com","Issuer":"CA for test","CommonName":"example.com","SANs":["example.com","www.example.com"],"NotBefore":"2017-01-01 00:00:00 +0900 JST","NotAfter":"2018-01-01 00:00:00 +0900 JST","Error":""}]`

	certs, _ := NewCerts([]string{"example.com"})

	if string(certs.JSON()) != expected {
		t.Errorf(`unexpected return value %q, want %q`, certs.JSON(), expected)
	}
}

func TestCertsEscapeStarInSANs(t *testing.T) {
	serverCert = func(d string) (*x509.Certificate, error) {
		return &x509.Certificate{
			Issuer: pkix.Name{
				CommonName: "CA for test",
			},
			Subject: pkix.Name{
				CommonName: d,
			},
			DNSNames:  []string{d, "*." + d}, // include star
			NotBefore: time.Date(2017, time.January, 1, 0, 0, 0, 0, time.FixedZone("JST", 9*60*60)),
			NotAfter:  time.Date(2018, time.January, 1, 0, 0, 0, 0, time.FixedZone("JST", 9*60*60)),
		}, nil
	}

	certs, _ := NewCerts([]string{"example.com"})

	certs = certs.escapeStar()

	if certs[0].SANs[1] != "\\*.example.com" {
		t.Errorf(`unexpected escaped value %q, want %q`, certs[0].SANs[1], "\\*.example.com")
	}
}
