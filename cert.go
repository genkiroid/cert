package cert

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"strings"
	"time"

	"github.com/golang/go/src/pkg/text/template"
)

const defaultTempl = `DomainName: {{.DomainName}}
Start:      {{.Start}}
End:        {{.End}}
CommonName: {{.CommonName}}
SANs:       {{.SANs}}

`

type Certs []*Cert

type Cert struct {
	DomainName string
	CommonName string
	SANs       []string
	Start      string
	End        string
}

func init() {
	loc, err := time.LoadLocation("Asia/Tokyo")
	if err != nil {
		loc = time.FixedZone("Asia/Tokyo", 9*60*60)
	}
	time.Local = loc
}

func NewCerts(s []string) (Certs, error) {
	if len(s) < 1 {
		return nil, fmt.Errorf("ドメイン名をひとつ以上指定してください。")
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
	s := ""
	for _, c := range certs {
		s += c.String()
	}
	return s
}

func (certs Certs) Markdown() string {
	s := ""
	s += "ドメイン名 | 有効期間の開始 | 有効期間の終了 | CN | SANs\n"
	s += "--- | --- | --- | --- | ---\n"
	for _, c := range certs {
		s += c.Markdown()
	}
	return s
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
		CommonName: cert.Subject.CommonName,
		SANs:       cert.DNSNames,
		Start:      cert.NotBefore.In(time.Local).Format("2006/01/02 15:04:05"),
		End:        cert.NotAfter.In(time.Local).Format("2006/01/02 15:04:05"),
	}, nil
}

func (c *Cert) String() string {
	var b bytes.Buffer
	t, err := template.New("default").Parse(defaultTempl)
	if err != nil {
		panic(err)
	}
	err = t.Execute(&b, c)
	if err != nil {
		panic(err)
	}
	return b.String()
}

func (c *Cert) Markdown() string {
	s := ""
	s += fmt.Sprintf("%s | %s | %s | %s | %s\n", c.DomainName, c.Start, c.End, c.CommonName, strings.Join(c.SANs, "<br/>"))
	return s
}
