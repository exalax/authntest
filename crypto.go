package authntest

import (
	"crypto"
	"crypto/x509"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
)

type Algorithm struct {
	Name      string
	Hash      crypto.Hash
	Signature x509.SignatureAlgorithm
}

var knownAlgorithms = map[webauthncose.COSEAlgorithmIdentifier]Algorithm{
	// webauthncose.AlgRS1:   {"SHA1-RSA", crypto.SHA1, x509.SHA1WithRSA},
	// webauthncose.AlgRS256: {"SHA256-RSA", crypto.SHA256, x509.SHA256WithRSA},
	// webauthncose.AlgRS384: {"SHA384-RSA", crypto.SHA384, x509.SHA384WithRSA},
	// webauthncose.AlgRS512: {"SHA512-RSA", crypto.SHA512, x509.SHA512WithRSA},
	// webauthncose.AlgPS256: {"SHA256-RSAPSS", crypto.SHA256, x509.SHA256WithRSAPSS},
	// webauthncose.AlgPS384: {"SHA384-RSAPSS", crypto.SHA384, x509.SHA384WithRSAPSS},
	// webauthncose.AlgPS512: {"SHA512-RSAPSS", crypto.SHA512, x509.SHA512WithRSAPSS},
	webauthncose.AlgES256: {"ECDSA-SHA256", crypto.SHA256, x509.ECDSAWithSHA256},
	// webauthncose.AlgES384: {"ECDSA-SHA384", crypto.SHA384, x509.ECDSAWithSHA384},
	// webauthncose.AlgES512: {"ECDSA-SHA512", crypto.SHA512, x509.ECDSAWithSHA512},
	// webauthncose.AlgEdDSA: {"EdDSA", crypto.SHA512, x509.PureEd25519},
}

func searchForAlgorithm(params []protocol.CredentialParameter) (Algorithm, bool) {
	for _, p := range params {
		alg, ok := knownAlgorithms[p.Algorithm]
		if ok {
			return alg, true
		}
	}

	return Algorithm{}, false
}
