package sjwt

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"

	"go-micro.dev/v4/errors"
)

func DecodeKeyPair(pub string, priv string) (any, any, error) {
	b, err := base64.StdEncoding.DecodeString(pub)
	if err != nil {
		return nil, nil, errors.InternalServerError("shared/sjwt/DecodeKeyPair.base64", fmt.Sprintf("%s", err))
	}

	block, _ := pem.Decode(b)
	if block == nil {
		return nil, nil, errors.InternalServerError("shared/sjwt/DecodeKeyPair.pem", "failed to parse PEM block containing the key")
	}

	pubResult, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, nil, errors.InternalServerError("shared/sjwt/DecodeKeyPair.ParsePKIXPublicKey", fmt.Sprintf("%s", err))
	}

	b, err = base64.StdEncoding.DecodeString(priv)
	if err != nil {
		return nil, nil, errors.InternalServerError("shared/sjwt/DecodeKeyPair.base64_priv", fmt.Sprintf("%s", err))
	}
	block, _ = pem.Decode(b)
	if block == nil {
		return nil, nil, errors.InternalServerError("shared/sjwt/DecodeKeyPair.pem_priv", "failed to parse PEM block containing the key")
	}
	privResult, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, errors.InternalServerError("shared/sjwt/DecodeKeyPair.ParsePKCS8PrivateKey", fmt.Sprintf("%s", err))
	}

	return pubResult, privResult, nil
}
