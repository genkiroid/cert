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

Options are

```sh
$ cert -h
Usage of cert:
  -a    Async mode. Output in no particular order.
  -f string
        Output format. md: as markdown, json: as JSON.  (default "simple table")
  -k    Skip verification of server's certificate chain and host name.
```

## License

[MIT](https://github.com/genkiroid/cert/blob/master/LICENSE)

## Author

[genkiroid](https://github.com/genkiroid)

