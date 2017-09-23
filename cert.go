package cert

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"time"

	"github.com/golang/go/src/pkg/text/template"
)

const defaultTempl = `{{range .}}DomainName: {{.DomainName}}
Issuer:     {{.Issuer}}
NotBefore:  {{.NotBefore}}
NotAfter:   {{.NotAfter}}
CommonName: {{.CommonName}}
SANs:       {{.SANs}}

{{end}}
`

const markdownTempl = `DomainName | Issuer | NotBefore | NotAfter | CN | SANs
--- | --- | --- | --- | --- | ---
{{range .}}{{.DomainName}} | {{.Issuer}} | {{.NotBefore}} | {{.NotAfter}} | {{.CommonName}} | {{range .SANs}}{{.}}<br/>{{end}} {{end}}
`

type Certs []*Cert

type Cert struct {
	DomainName string
	Issuer     string
	CommonName string
	SANs       []string
	NotBefore  string
	NotAfter   string
}

func NewCerts(s []string) (Certs, error) {
	if len(s) < 1 {
		return nil, fmt.Errorf("Input at least one domain name.")
	}
	certs := Certs{}
	for _, d := range s[:] {
		c, err := NewCert(d)
		if err != nil {
			return nil, err
		}
		certs = append(certs, c)
	}
	return certs, nil
}

func (certs Certs) String() string {
	var b bytes.Buffer
	t, err := template.New("default").Parse(defaultTempl)
	if err != nil {
		panic(err)
	}
	if err := t.Execute(&b, certs); err != nil {
		panic(err)
	}
	return b.String()
}

func (certs Certs) Markdown() string {
	var b bytes.Buffer
	t, err := template.New("markdown").Parse(markdownTempl)
	if err != nil {
		panic(err)
	}
	if err := t.Execute(&b, certs); err != nil {
		panic(err)
	}
	return b.String()
}

func NewCert(d string) (*Cert, error) {
	conn, err := tls.Dial("tcp", d+":443", &tls.Config{})
	if err != nil {
		return nil, err
	}
	cert := conn.ConnectionState().PeerCertificates[0]
	conn.Close()
	return &Cert{
		DomainName: d,
		Issuer:     cert.Issuer.Organization[0],
		CommonName: cert.Subject.CommonName,
		SANs:       cert.DNSNames,
		NotBefore:  cert.NotBefore.In(time.Local).Format("2006/01/02 15:04:05"),
		NotAfter:   cert.NotAfter.In(time.Local).Format("2006/01/02 15:04:05"),
	}, nil
}
