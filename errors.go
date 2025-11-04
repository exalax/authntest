package authntest

import "errors"

var (
	ErrUnsupportedAlgorithm   = errors.New("unsupported authentication algorithm")
	ErrUnsupportedAttestation = errors.New("unsupported attestation")
	ErrEmptyRelyingPartyID    = errors.New("relying party id is empty")
	ErrEmptyUserID            = errors.New("user id is empty")
)
