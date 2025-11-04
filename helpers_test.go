package authntest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
)

type testUser struct {
	id          string
	name        string
	credentials []webauthn.Credential
	mx          sync.RWMutex
}

func newTestUser() *testUser {
	id := uuid.NewString()

	return &testUser{
		id:          id,
		name:        id + "@example.com",
		credentials: make([]webauthn.Credential, 1),
		mx:          sync.RWMutex{},
	}
}

func (u *testUser) WebAuthnID() []byte {
	return []byte(u.id)
}

func (u *testUser) WebAuthnName() string {
	return u.name
}

func (u *testUser) WebAuthnDisplayName() string {
	return u.name
}

func (u *testUser) WebAuthnCredentials() []webauthn.Credential {
	u.mx.RLock()
	defer u.mx.RUnlock()

	return u.credentials
}

func (u *testUser) AddCredential(c webauthn.Credential) {
	u.mx.Lock()
	defer u.mx.Unlock()

	u.credentials = append(u.credentials, c)
}

type authnServer struct {
	authn       *webauthn.WebAuthn
	mx          sync.RWMutex
	regSessions map[string]*webauthn.SessionData
	user        *testUser
}

func newAuthnServer(user *testUser) (*authnServer, error) {
	trueValue := true

	authn, err := webauthn.New(&webauthn.Config{
		RPID:                        "example.com",
		RPDisplayName:               "Webauthn Test",
		RPOrigins:                   []string{"https://localhost"},
		RPTopOrigins:                []string{"https://localhost"},
		RPTopOriginVerificationMode: protocol.TopOriginAutoVerificationMode,
		AttestationPreference:       protocol.PreferIndirectAttestation,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			AuthenticatorAttachment: "",
			RequireResidentKey:      &trueValue,
			ResidentKey:             protocol.ResidentKeyRequirementRequired,
			UserVerification:        protocol.VerificationRequired,
		},
		Debug:                false,
		EncodeUserIDAsString: false,
		Timeouts: webauthn.TimeoutsConfig{
			Login: webauthn.TimeoutConfig{
				Enforce:    true,
				Timeout:    time.Minute,
				TimeoutUVD: time.Minute,
			},
			Registration: webauthn.TimeoutConfig{
				Enforce:    true,
				Timeout:    time.Minute,
				TimeoutUVD: time.Minute,
			},
		},
		MDS: nil,
	})
	if err != nil {
		return nil, fmt.Errorf("init webauthn: %w", err)
	}

	return &authnServer{
		authn:       authn,
		mx:          sync.RWMutex{},
		regSessions: make(map[string]*webauthn.SessionData),
		user:        user,
	}, nil
}

func (as *authnServer) handleRegBegin(w http.ResponseWriter, r *http.Request) {
	creation, session, wErr := as.authn.BeginRegistration(as.user)
	if wErr != nil {
		http.Error(w, wErr.Error(), http.StatusBadRequest)
		return
	}

	encoded, wErr := json.Marshal(creation)
	if wErr != nil {
		http.Error(w, wErr.Error(), http.StatusInternalServerError)
		return
	}

	as.mx.Lock()
	as.regSessions[session.Challenge] = session
	as.mx.Unlock()

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(encoded)))
	_, _ = w.Write(encoded)
}

func (as *authnServer) handleRegFinish(w http.ResponseWriter, r *http.Request) {
	response, err := protocol.ParseCredentialCreationResponse(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	as.mx.RLock()
	session, ok := as.regSessions[response.Response.CollectedClientData.Challenge]
	as.mx.RUnlock()
	if !ok {
		http.Error(w, "session not found", http.StatusBadRequest)
		return
	}

	credential, err := as.authn.CreateCredential(as.user, *session, response)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	as.user.AddCredential(*credential)

	w.WriteHeader(http.StatusCreated)
}
