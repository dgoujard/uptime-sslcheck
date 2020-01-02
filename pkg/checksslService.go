package pkg

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"strings"
	"time"
)

type certificate struct {
	name    string
	subject string
	algo    string
	issuer  string
	expireAt int
	expireIn string
	warnAlgo    bool
	error   string
	sunset  *sunsetSignatureAlgorithm
}


func checkSSLHost(h string) (certificate, error) {
	if !strings.Contains(h, ":") {
		// default to 443
		h += ":443"
	}
	c, err := tls.Dial("tcp", h, nil)
	if err != nil {
		switch cerr := err.(type) {
		case x509.CertificateInvalidError:
			ht := createHost(h, cerr.Cert)
			ht.error = err.Error()
			return ht, nil
		case x509.UnknownAuthorityError:
			ht := createHost(h, cerr.Cert)
			ht.error = err.Error()
			return ht, nil

		case x509.HostnameError:
			ht := createHost(h, cerr.Certificate)
			ht.error = err.Error()
			return ht, nil

		}
		return certificate{}, fmt.Errorf("tcp dial %s failed: %v", h, err)
	}
	defer c.Close()

	var certToReturn certificate
	certs := make(map[string]certificate)
	for _, chain := range c.ConnectionState().VerifiedChains {
		for n, cert := range chain {
			if _, checked := certs[string(cert.Signature)]; checked {
				continue
			}
			if n >= 1 { //pas de traitement des autres certificats de la chaine
				continue
			}

			certToReturn = createHost(h, cert)
		}
	}
	return certToReturn, nil
}

func createHost(name string, cert *x509.Certificate) certificate {
	host := certificate{
		name:    name,
		subject: cert.Subject.CommonName,
		issuer:  cert.Issuer.CommonName,
		algo:    cert.SignatureAlgorithm.String(),
	}
	host.expireAt = int(cert.NotAfter.UnixNano() / 1000000000)
	expiresIn := int64(time.Until(cert.NotAfter).Hours())
	if expiresIn <= 48 {
		host.expireIn = fmt.Sprintf("%d hours", expiresIn)
	} else {
		host.expireIn = fmt.Sprintf("%d days", expiresIn/24)
	}

	// Check the signature algorithm, ignoring the root certificate.
	if alg, exists := sunsetSignatureAlgorithms[cert.SignatureAlgorithm]; exists {
		if cert.NotAfter.Equal(alg.date) || cert.NotAfter.After(alg.date) {
			host.warnAlgo = true
		}
		host.sunset = &alg
	}

	return host
}



type sunsetSignatureAlgorithm struct {
	name string    // Human readable name of the signature algorithm.
	date time.Time // Date the signature algorithm will be sunset.
}

// sunsetSignatureAlgorithms is an algorithm to string mapping for certificate
// signature algorithms which have been or are being deprecated.  See the
// following links to learn more about SHA1's inclusion on this list.
// - https://technet.microsoft.com/en-us/library/security/2880823.aspx
// - http://googleonlinesecurity.blogspot.com/2014/09/gradually-sunsetting-sha-1.html
var sunsetSignatureAlgorithms = map[x509.SignatureAlgorithm]sunsetSignatureAlgorithm{
	x509.MD2WithRSA: {
		name: "MD2 with RSA",
		date: time.Now(),
	},
	x509.MD5WithRSA: {
		name: "MD5 with RSA",
		date: time.Now(),
	},
	x509.SHA1WithRSA: {
		name: "SHA1 with RSA",
		date: time.Date(2017, 1, 1, 0, 0, 0, 0, time.UTC),
	},
	x509.DSAWithSHA1: {
		name: "DSA with SHA1",
		date: time.Date(2017, 1, 1, 0, 0, 0, 0, time.UTC),
	},
	x509.ECDSAWithSHA1: {
		name: "ECDSA with SHA1",
		date: time.Date(2017, 1, 1, 0, 0, 0, 0, time.UTC),
	},
}