package cert

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"time"
)

var SkipVerify = false

var userTempl string

func SetUserTempl(templ string) error {
	if templ == "" {
		return nil
	}

	path, err := filepath.Abs(templ)
	if err != nil {
		return err
	}

	content, err := ioutil.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		userTempl = templ
		return nil
	}

	userTempl = string(content)

	return nil
}

const defaultPort = "443"

func SplitHostPort(hostport string) (string, string, error) {
	if !strings.Contains(hostport, ":") {
		return hostport, defaultPort, nil
	}

	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return "", "", err
	}

	if port == "" {
		port = defaultPort
	}

	return host, port, nil
}

type Cert struct {
	DomainName string   `json:"domainName"`
	IP         string   `json:"ip"`
	Issuer     string   `json:"issuer"`
	CommonName string   `json:"commonName"`
	SANs       []string `json:"sans"`
	NotBefore  string   `json:"notBefore"`
	NotAfter   string   `json:"notAfter"`
	Error      string   `json:"error"`
	certChain  []*x509.Certificate
}

var serverCert = func(host, port string) ([]*x509.Certificate, string, error) {
	conn, err := tls.Dial("tcp", host+":"+port, &tls.Config{
		InsecureSkipVerify: SkipVerify,
	})
	if err != nil {
		return []*x509.Certificate{&x509.Certificate{}}, "", err
	}
	defer conn.Close()
	addr := conn.RemoteAddr()
	ip, _, _ := net.SplitHostPort(addr.String())
	cert := conn.ConnectionState().PeerCertificates

	return cert, ip, nil
}

func NewCert(hostport string) *Cert {
	host, port, err := SplitHostPort(hostport)
	if err != nil {
		return &Cert{DomainName: host, Error: err.Error()}
	}
	certChain, ip, err := serverCert(host, port)
	if err != nil {
		return &Cert{DomainName: host, Error: err.Error()}
	}
	cert := certChain[0]
	return &Cert{
		DomainName: host,
		IP:         ip,
		Issuer:     cert.Issuer.CommonName,
		CommonName: cert.Subject.CommonName,
		SANs:       cert.DNSNames,
		NotBefore:  cert.NotBefore.In(time.Local).String(),
		NotAfter:   cert.NotAfter.In(time.Local).String(),
		Error:      "",
		certChain:  certChain,
	}
}

func (c *Cert) Detail() *x509.Certificate {
	return c.certChain[0]
}

func (c *Cert) CertChain() []*x509.Certificate {
	return c.certChain
}

type Certs []*Cert

var tokens = make(chan struct{}, 128)

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

	type indexer struct {
		index int
		cert  *Cert
	}

	certs := make(Certs, len(s))
	ch := make(chan *indexer, len(s))
	for i, d := range s {
		go func(i int, d string) {
			tokens <- struct{}{}
			ch <- &indexer{i, NewCert(d)}
			<-tokens
		}(i, d)
	}

	for range s {
		i := <-ch
		certs[i.index] = i.cert
	}
	return certs, nil
}

const defaultTempl = `{{range .}}DomainName: {{.DomainName}}
IP:         {{.IP}}
Issuer:     {{.Issuer}}
NotBefore:  {{.NotBefore}}
NotAfter:   {{.NotAfter}}
CommonName: {{.CommonName}}
SANs:       {{.SANs}}
Error:      {{.Error}}

{{end}}
`

func (certs Certs) String() string {
	var b bytes.Buffer

	templ := defaultTempl
	if userTempl != "" {
		templ = userTempl
	}

	t := template.Must(template.New("default").Parse(templ))
	if err := t.Execute(&b, certs); err != nil {
		panic(err)
	}
	return b.String()
}

const markdownTempl = `DomainName | IP | Issuer | NotBefore | NotAfter | CN | SANs | Error
--- | --- | --- | --- | --- | --- | --- | ---
{{range .}}{{.DomainName}} | {{.IP}} | {{.Issuer}} | {{.NotBefore}} | {{.NotAfter}} | {{.CommonName}} | {{range .SANs}}{{.}}<br/>{{end}} | {{.Error}}
{{end}}
`

func (certs Certs) escapeStar() Certs {
	for _, cert := range certs {
		for i, san := range cert.SANs {
			cert.SANs[i] = strings.Replace(san, "*", "\\*", -1)
		}
	}
	return certs
}

func (certs Certs) Markdown() string {
	var b bytes.Buffer
	t := template.Must(template.New("markdown").Parse(markdownTempl))
	if err := t.Execute(&b, certs.escapeStar()); err != nil {
		panic(err)
	}
	return b.String()
}

func (certs Certs) JSON() []byte {
	data, err := json.Marshal(certs)
	if err != nil {
		panic(err)
	}
	return data
}
