package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mini-pasuki2/binid"
	"mini-pasuki2/ent"
	"mini-pasuki2/form"
	"mini-pasuki2/pasuki2"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"entgo.io/ent/dialect"
	"github.com/go-playground/validator/v10"
	"github.com/go-redis/redismock/v9"
	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	_ "github.com/mattn/go-sqlite3"
)

// setupTestApp initializes a new App with in-memory sqlite and mocked redis for testing.
func setupTestApp(t *testing.T) (*App, redismock.ClientMock, func()) {
	client, err := ent.Open(dialect.SQLite, "file:ent?mode=memory&cache=shared&_fk=1")
	if err != nil {
		t.Fatalf("Failed to open sqlite: %v", err)
	}
	if err := client.Schema.Create(context.Background()); err != nil {
		t.Fatalf("Failed to create schema: %v", err)
	}

	redisClient, redisMock := redismock.NewClientMock()

	rpId := "localhost"
	rpIdHash := sha256.Sum256([]byte(rpId))
	app := &App{
		ent:                client,
		redis:              redisClient,
		validator:          validator.New(),
		origin:             "https://localhost",
		relyingParty:       "localhost",
		relyingPartyIdHash: rpIdHash[:],
	}

	teardown := func() {
		client.Close()
		redisClient.Close()
	}

	return app, redisMock, teardown
}

// newTestContext creates a new echo.Context for testing handlers.
func newTestContext(e *echo.Echo, method, path string, body io.Reader) (echo.Context, *httptest.ResponseRecorder) {
	req := httptest.NewRequest(method, path, body)
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	return e.NewContext(req, rec), rec
}

func TestRegisterStart(t *testing.T) {
	e := echo.New()
	app, mock, teardown := setupTestApp(t)
	defer teardown()

	// Monkey-patch GenerateChallenge to return a predictable value
	originalGenerateChallenge := pasuki2.GenerateChallenge
	pasuki2.GenerateChallenge = func() ([]byte, error) {
		return []byte("fixed-challenge-for-testing-1234"), nil
	}
	defer func() { pasuki2.GenerateChallenge = originalGenerateChallenge }()

	t.Run("success", func(t *testing.T) {
		formBody := &form.RegisterStartRequest{
			Email: "test@example.com",
			Name:  "Test User",
		}
		jsonBody, _ := json.Marshal(formBody)
		c, rec := newTestContext(e, http.MethodPost, "/register/start", bytes.NewReader(jsonBody))

		// Now we can predict the exact challenge
		expectedChallenge, _ := pasuki2.GenerateChallenge()
		expectedEncChallenge := base64.RawURLEncoding.EncodeToString(expectedChallenge)

		key := fmt.Sprintf("%s:%s", __REDIS_REGISTRATION_CHALLENGE_KEY, formBody.Email)
		mock.ExpectSetArgs(key, expectedEncChallenge, redis.SetArgs{
			Mode: "NX",
			TTL:  time.Millisecond * pasuki2.DEFAULT_TIME_OUT_MIL,
		}).SetVal("OK")

		err := app.RegisterStart(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)

		var resp pasuki2.RegistrationOptions
		err = json.Unmarshal(rec.Body.Bytes(), &resp)
		assert.NoError(t, err)
		assert.Equal(t, expectedEncChallenge, resp.Challenge)
		assert.Equal(t, "localhost", resp.Rp.Name)
	})

	t.Run("bad request - invalid form", func(t *testing.T) {
		c, _ := newTestContext(e, http.MethodPost, "/register/start", strings.NewReader(`{"email":""}`))
		err := app.RegisterStart(c)
		assert.Error(t, err)
		httpErr, ok := err.(*echo.HTTPError)
		assert.True(t, ok)
		assert.Equal(t, http.StatusBadRequest, httpErr.Code)
	})

	t.Run("redis error - challenge already exists", func(t *testing.T) {
		formBody := &form.RegisterStartRequest{
			Email: "test2@example.com",
			Name:  "Test User 2",
		}
		jsonBody, _ := json.Marshal(formBody)
		c, _ := newTestContext(e, http.MethodPost, "/register/start", bytes.NewReader(jsonBody))

		expectedChallenge, _ := pasuki2.GenerateChallenge()
		expectedEncChallenge := base64.RawURLEncoding.EncodeToString(expectedChallenge)

		key := fmt.Sprintf("%s:%s", __REDIS_REGISTRATION_CHALLENGE_KEY, formBody.Email)
		mock.ExpectSetArgs(key, expectedEncChallenge, redis.SetArgs{
			Mode: "NX",
			TTL:  time.Millisecond * pasuki2.DEFAULT_TIME_OUT_MIL,
		}).SetErr(redis.Nil)

		err := app.RegisterStart(c)
		assert.Error(t, err)
		httpErr, ok := err.(*echo.HTTPError)
		assert.True(t, ok)
		assert.Equal(t, http.StatusBadRequest, httpErr.Code)
	})
}

func TestRegisterFinish(t *testing.T) {
	e := echo.New()
	app, mock, teardown := setupTestApp(t)
	defer teardown()

	dummyAttestation := base64.RawURLEncoding.EncodeToString(make([]byte, 120))
	testForm := &form.RegisterFinishRequest{
		RegisterRequest: form.RegisterRequest{
			Email: "finish@example.com",
			Name:  "Finish User",
		},
		Id:                "TEST-ID-STRING-SUFFIX",
		Type:              "public-key",
		AttestationObject: dummyAttestation,
		ClientDataJson:    dummyAttestation,
	}

	t.Run("pasuki2 validation fails", func(t *testing.T) {
		jsonBody, _ := json.Marshal(testForm)
		c, _ := newTestContext(e, http.MethodPost, "/register/finish", bytes.NewReader(jsonBody))

		key := fmt.Sprintf("%s:%s", __REDIS_REGISTRATION_CHALLENGE_KEY, testForm.Email)
		mock.ExpectGetDel(key).SetVal("mock-challenge")

		err := app.RegisterFinish(c)
		httpErr, ok := err.(*echo.HTTPError)
		assert.True(t, ok)
		assert.Equal(t, http.StatusBadRequest, httpErr.Code)
	})

	t.Run("redis error - challenge not found", func(t *testing.T) {
		jsonBody, _ := json.Marshal(testForm)
		c, _ := newTestContext(e, http.MethodPost, "/register/finish", bytes.NewReader(jsonBody))

		key := fmt.Sprintf("%s:%s", __REDIS_REGISTRATION_CHALLENGE_KEY, testForm.Email)
		mock.ExpectGetDel(key).SetErr(redis.Nil)

		err := app.RegisterFinish(c)
		httpErr, ok := err.(*echo.HTTPError)
		assert.True(t, ok)
		assert.Equal(t, http.StatusBadRequest, httpErr.Code)
	})
}

func TestVerifyStart(t *testing.T) {
	e := echo.New()
	app, mock, teardown := setupTestApp(t)
	defer teardown()

	originalGenerateChallenge := pasuki2.GenerateChallenge
	pasuki2.GenerateChallenge = func() ([]byte, error) {
		return []byte("fixed-challenge-for-verify-5678"), nil
	}
	defer func() { pasuki2.GenerateChallenge = originalGenerateChallenge }()

	t.Run("success", func(t *testing.T) {
		c, rec := newTestContext(e, http.MethodPost, "/verify/start", nil)

		expectedChallenge, _ := pasuki2.GenerateChallenge()
		expectedEncChallenge := base64.RawURLEncoding.EncodeToString(expectedChallenge)

		key := fmt.Sprintf("%s:%x", __REDIS_VERIFY_CHALLENGE_KEY, []byte(__SESSION_PLACEHOLDER))
		mock.ExpectSetArgs(key, expectedEncChallenge, redis.SetArgs{
			Mode: "NX",
			TTL:  time.Millisecond * pasuki2.DEFAULT_TIME_OUT_MIL,
		}).SetVal("OK")

		err := app.VerifyStart(c)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)

		var resp pasuki2.VerifyOptions
		err = json.Unmarshal(rec.Body.Bytes(), &resp)
		assert.NoError(t, err)
		assert.Equal(t, expectedEncChallenge, resp.Challenge)
	})
}

func TestVerifyFinish(t *testing.T) {
	e := echo.New()
	app, mock, teardown := setupTestApp(t)
	defer teardown()

	credIdBytes := []byte("a-valid-credential-id-bytes-123")
	encodedCredId := base64.RawURLEncoding.EncodeToString(credIdBytes)

	testForm := &form.VerifyFinishRequest{
		Id:                encodedCredId,
		Type:              "public-key",
		AuthenticatorData: base64.RawURLEncoding.EncodeToString(make([]byte, 40)),
		ClientDataJson:    base64.RawURLEncoding.EncodeToString(make([]byte, 120)),
		Signature:         base64.RawURLEncoding.EncodeToString(make([]byte, 50)),
	}

	userId, err := binid.NewSequential()
	assert.NoError(t, err)
	testUser, err := app.ent.User.Create().SetID(userId).SetName("test").SetEmail("test@test.com").Save(context.Background())
	assert.NoError(t, err)

	passkeyId, err := binid.NewSequential()
	assert.NoError(t, err)
	_, err = app.ent.Passkey.Create().
		SetID(passkeyId).
		SetCredentialID(credIdBytes).
		SetPublicKey([]byte("test-public-key")).
		SetSignCount(10).
		SetOrigin("test").
		SetAttestationFmt("none").
		SetBackupEligibilityBit(false).
		SetBackupStateBit(false).
		SetAaguid(make([]byte, 16)).
		SetUserID(testUser.ID).
		Save(context.Background())
	assert.NoError(t, err)

	t.Run("passkey not found", func(t *testing.T) {
		badForm := *testForm
		badForm.Id = base64.RawURLEncoding.EncodeToString([]byte("unfindable-id"))
		jsonBody, _ := json.Marshal(&badForm)
		c, _ := newTestContext(e, http.MethodPost, "/verify/finish", bytes.NewReader(jsonBody))

		err := app.VerifyFinish(c)
		httpErr, ok := err.(*echo.HTTPError)
		assert.True(t, ok)
		assert.Equal(t, http.StatusBadRequest, httpErr.Code)
	})

	t.Run("redis error - challenge not found", func(t *testing.T) {
		jsonBody, _ := json.Marshal(testForm)
		c, _ := newTestContext(e, http.MethodPost, "/verify/finish", bytes.NewReader(jsonBody))

		key := fmt.Sprintf("%s:%x", __REDIS_VERIFY_CHALLENGE_KEY, []byte(__SESSION_PLACEHOLDER))
		mock.ExpectGetDel(key).SetErr(redis.Nil)

		err := app.VerifyFinish(c)
		httpErr, ok := err.(*echo.HTTPError)
		assert.True(t, ok)
		assert.Equal(t, http.StatusBadRequest, httpErr.Code)
	})

	t.Run("pasuki2 validation fails", func(t *testing.T) {
		jsonBody, _ := json.Marshal(testForm)
		c, _ := newTestContext(e, http.MethodPost, "/verify/finish", bytes.NewReader(jsonBody))

		key := fmt.Sprintf("%s:%x", __REDIS_VERIFY_CHALLENGE_KEY, []byte(__SESSION_PLACEHOLDER))
		mock.ExpectGetDel(key).SetVal("mock-challenge")

		err := app.VerifyFinish(c)
		httpErr, ok := err.(*echo.HTTPError)
		assert.True(t, ok)
		assert.Equal(t, http.StatusBadRequest, httpErr.Code)
	})
}
