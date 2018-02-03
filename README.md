# cert

[![Build Status](https://travis-ci.org/genkiroid/cert.svg?branch=master)](https://travis-ci.org/genkiroid/cert)

Get server's certificate information.

## Installation

For Mac it provide Homebrew integration.
Please install like following.

```sh
$ brew tap genkiroid/homebrew-cert
$ brew install cert
```

For other platforms, Precompiled binaries for released versions are available in the [releases](https://github.com/genkiroid/cert/releases) page.

Or `go get`.

```sh
$ go get github.com/genkiroid/cert/...
```

## Usage

Give domain names as arguments.

```sh
$ cert github.com google.co.jp
DomainName: github.com
IP:         192.30.255.113
Issuer:     DigiCert SHA2 Extended Validation Server CA
NotBefore:  2016-03-10 09:00:00 +0900 JST
NotAfter:   2018-05-17 21:00:00 +0900 JST
CommonName: github.com
SANs:       [github.com www.github.com]
Error:

DomainName: google.co.jp
IP:         216.58.196.227
Issuer:     Google Internet Authority G3
NotBefore:  2017-10-17 19:59:51 +0900 JST
NotAfter:   2018-01-09 19:00:00 +0900 JST
CommonName: *.google.co.jp
SANs:       [*.google.co.jp google.co.jp]
Error:

```

You can specify port number.
So you can get server certificate information of not only web server but also *mail server and others*.

```sh
$ cert github.com google.co.jp:443 imap.gmail.com:993
DomainName: github.com
IP:         192.30.255.113
Issuer:     DigiCert SHA2 Extended Validation Server CA
NotBefore:  2016-03-10 09:00:00 +0900 JST
NotAfter:   2018-05-17 21:00:00 +0900 JST
CommonName: github.com
SANs:       [github.com www.github.com]
Error:

DomainName: google.co.jp
IP:         172.217.27.163
Issuer:     Google Internet Authority G3
NotBefore:  2017-10-17 19:59:51 +0900 JST
NotAfter:   2018-01-09 19:00:00 +0900 JST
CommonName: *.google.co.jp
SANs:       [*.google.co.jp google.co.jp]
Error:

DomainName: imap.gmail.com
IP:         64.233.188.108
Issuer:     Google Internet Authority G2
NotBefore:  2017-10-17 19:10:29 +0900 JST
NotAfter:   2017-12-29 09:00:00 +0900 JST
CommonName: imap.gmail.com
SANs:       [imap.gmail.com]
Error:

```

Options are

```sh
$ cert -h
Usage of cert:
  -f string
        Output format. md: as markdown, json: as JSON.  (default "simple table")
  -k    Skip verification of server's certificate chain and host name.
  -t string
        Output format as Go template string or Go template file path.
  -v    Show version.
  -version
        Show version.
```

## License

[MIT](https://github.com/genkiroid/cert/blob/master/LICENSE)

## Author

[genkiroid](https://github.com/genkiroid)

