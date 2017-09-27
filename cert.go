package cert

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"strings"
	"time"

	"github.com/golang/go/src/pkg/text/template"
)

const defaultTempl = `{{range .}}DomainName: {{.DomainName}}
Issuer:     {{.Issuer}}
NotBefore:  {{.NotBefore}}
NotAfter:   {{.NotAfter}}
CommonName: {{.CommonName}}
SANs:       {{.SANs}}
Error:      {{.Error}}

{{end}}
`

const markdownTempl = `DomainName | Issuer | NotBefore | NotAfter | CN | SANs | Error
--- | --- | --- | --- | --- | --- | ---
{{range .}}{{.DomainName}} | {{.Issuer}} | {{.NotBefore}} | {{.NotAfter}} | {{.CommonName}} | {{range .SANs}}{{.}}<br/>{{end}} | {{.Error}}
{{end}}
`

type Certs []*Cert

type Cert struct {
	DomainName string
	Issuer     string
	CommonName string
	SANs       []string
	NotBefore  string
	NotAfter   string
	Error      string
}

func validate(s []string) error {
	if len(s) < 1 {
		return fmt.Errorf("Input at least one domain name.")
	}
	return nil
}

func NewCerts(s []string) (Certs, error) {
	if err := validate(s); err != nil {
		return nil, err
	}

	certs := Certs{}
	for _, d := range s[:] {
		certs = append(certs, NewCert(d))
	}
	return certs, nil
}

func NewAsyncCerts(s []string) (Certs, error) {
	if err := validate(s); err != nil {
		return nil, err
	}

	certs := Certs{}
	ch := make(chan *Cert, len(s))
	for _, d := range s[:] {
		go func(d string) {
			ch <- NewCert(d)
		}(d)
	}

	for range s[:] {
		c := <-ch
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
	if err := t.Execute(&b, certs.escapeStar()); err != nil {
		panic(err)
	}
	return b.String()
}

func NewCert(d string) *Cert {
	conn, err := tls.Dial("tcp", d+":443", &tls.Config{})
	if err != nil {
		return &Cert{DomainName: d, Error: err.Error()}
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
		Error:      "",
	}
}

func (certs Certs) escapeStar() Certs {
	for _, cert := range certs {
		for i, san := range cert.SANs {
			cert.SANs[i] = strings.Replace(san, "*", "\\*", -1)
		}
	}
	return certs
}
