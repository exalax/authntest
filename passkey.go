package authntest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
)

type AttestationObject struct {
	AttestationStatementFormatID string         `cbor:"fmt"`
	AttestationStatement         map[string]any `cbor:"attStmt"`
	AuthenticatorData            []byte         `cbor:"authData"`
}

type Passkey struct {
	ID             []byte
	RelyingPartyID string
	Alg            Algorithm
	UserID         any
	PrivateKey     *ecdsa.PrivateKey
	Challenge      protocol.URLEncodedBase64
}

func NewPasskey(creationOptions io.Reader) (*Passkey, error) {
	options := protocol.CredentialCreation{}

	err := json.NewDecoder(creationOptions).Decode(&options)
	if err != nil {
		return nil, fmt.Errorf("unmarshal creation options: %w", err)
	}

	if options.Response.RelyingParty.ID == "" {
		return nil, ErrEmptyRelyingPartyID
	}

	if options.Response.User.ID == "" {
		return nil, ErrEmptyUserID
	}

	alg, ok := searchForAlgorithm(options.Response.Parameters)
	if !ok {
		return nil, ErrUnsupportedAlgorithm
	}

	switch options.Response.Attestation {
	case "", protocol.PreferNoAttestation, protocol.PreferIndirectAttestation:
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedAttestation, options.Response.Attestation)
	}

	id := make([]byte, 32)
	_, err = rand.Read(id)
	if err != nil {
		return nil, fmt.Errorf("generate id: %w", err)
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate private key: %w", err)
	}

	return &Passkey{
		ID:             id,
		RelyingPartyID: options.Response.RelyingParty.ID,
		UserID:         options.Response.User.ID,
		Alg:            alg,
		PrivateKey:     privateKey,
		Challenge:      options.Response.Challenge,
	}, nil
}

func (p *Passkey) CreationResponse() ([]byte, error) {
	clientData := protocol.CollectedClientData{
		Type:         "webauthn.create",
		Challenge:    base64.RawURLEncoding.EncodeToString(p.Challenge),
		Origin:       "https://localhost",
		TopOrigin:    "",
		CrossOrigin:  false,
		TokenBinding: nil,
		Hint:         "",
	}

	clientDataJSON, err := json.Marshal(clientData)
	if err != nil {
		return nil, fmt.Errorf("marshal client data: %w", err)
	}

	authData := bytes.NewBuffer(nil)
	rpHash := sha256.Sum256([]byte(p.RelyingPartyID))
	_, err = authData.Write(rpHash[:])
	if err != nil {
		return nil, fmt.Errorf("write relying party id hash to auth data: %w", err)
	}

	err = authData.WriteByte(byte(protocol.FlagAttestedCredentialData | protocol.FlagUserPresent | protocol.FlagUserVerified))
	if err != nil {
		return nil, fmt.Errorf("write flag to auth data: %w", err)
	}

	_, err = authData.Write(make([]byte, 4))
	if err != nil {
		return nil, fmt.Errorf("write sing counter to auth data: %w", err)
	}

	_, err = authData.Write(make([]byte, 16))
	if err != nil {
		return nil, fmt.Errorf("write aaguid counter to auth data: %w", err)
	}

	idLen := make([]byte, 2)
	binary.BigEndian.PutUint16(idLen, uint16(len(p.ID)))

	_, err = authData.Write(idLen)
	if err != nil {
		return nil, fmt.Errorf("write credential id length to auth data: %w", err)
	}

	_, err = authData.Write(p.ID)
	if err != nil {
		return nil, fmt.Errorf("write credential id to auth data: %w", err)
	}

	pkData, err := webauthncbor.Marshal(webauthncose.EC2PublicKeyData{
		PublicKeyData: webauthncose.PublicKeyData{
			KeyType:   int64(webauthncose.EllipticKey),
			Algorithm: int64(webauthncose.AlgES256),
		},
		Curve:  int64(webauthncose.P256),
		XCoord: p.PrivateKey.X.Bytes(),
		YCoord: p.PrivateKey.Y.Bytes(),
	})
	if err != nil {
		return nil, fmt.Errorf("marshal credential public key: %w", err)
	}

	_, err = authData.Write(pkData)
	if err != nil {
		return nil, fmt.Errorf("write credential public key to auth data: %w", err)
	}

	attObject := &AttestationObject{
		AuthenticatorData:            authData.Bytes(),
		AttestationStatementFormatID: string(protocol.AttestationFormatNone),
		AttestationStatement:         nil,
	}

	attObjectMarshalled, err := webauthncbor.Marshal(attObject)
	if err != nil {
		return nil, fmt.Errorf("marshal attestation object: %w", err)
	}

	resp := &protocol.CredentialCreationResponse{
		PublicKeyCredential: protocol.PublicKeyCredential{
			Credential: protocol.Credential{
				ID:   base64.RawURLEncoding.EncodeToString(p.ID),
				Type: "public-key",
			},
			RawID:                   p.ID,
			ClientExtensionResults:  protocol.AuthenticationExtensionsClientOutputs{},
			AuthenticatorAttachment: string(protocol.Platform),
		},
		AttestationResponse: protocol.AuthenticatorAttestationResponse{
			AuthenticatorResponse: protocol.AuthenticatorResponse{
				ClientDataJSON: clientDataJSON,
			},
			Transports:         []string{"internal"},
			AuthenticatorData:  nil,
			PublicKey:          nil,
			PublicKeyAlgorithm: 0,
			AttestationObject:  attObjectMarshalled,
		},
	}

	respBytes, err := json.Marshal(resp)
	if err != nil {
		return nil, fmt.Errorf("marshal response object: %w", err)
	}

	return respBytes, nil
}
