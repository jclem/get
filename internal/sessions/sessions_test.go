package sessions_test

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/jclem/get/internal/sessions"
	"github.com/stretchr/testify/require"
)

func tempSessionsPath(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	return filepath.Join(dir, "sessions.json")
}

func TestNewManager_CreatesEmptyFile(t *testing.T) {
	t.Parallel()

	path := tempSessionsPath(t)

	_, err := sessions.NewManager(sessions.WithSessionsPath(path))
	require.NoError(t, err)

	b, err := os.ReadFile(path) //nolint:gosec // test file
	require.NoError(t, err)
	require.NotEmpty(t, b)

	type diskFile struct {
		Sessions map[string]sessions.Session `json:"sessions"`
	}
	var df diskFile
	require.NoError(t, json.Unmarshal(b, &df))
	require.NotNil(t, df.Sessions)
	require.Empty(t, df.Sessions)
}

func TestWriteRequest_SavesAuthorizationByDefault(t *testing.T) {
	t.Parallel()

	path := tempSessionsPath(t)
	mgr, err := sessions.NewManager(sessions.WithSessionsPath(path))
	require.NoError(t, err)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://example.com/", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "abc")
	req.Header.Set("X-Custom", "nope")

	require.NoError(t, mgr.WriteRequest(req))

	// Reload and verify only Authorization persisted.
	mgr2, err := sessions.NewManager(sessions.WithSessionsPath(path))
	require.NoError(t, err)

	s := mgr2.Get("example.com")
	require.NotNil(t, s)
	require.Equal(t, []string{"abc"}, s.Headers["Authorization"])
	_, hasCustom := s.Headers["X-Custom"]
	require.False(t, hasCustom)
}

func TestWriteRequest_SaveAllHeaders_StoresAll(t *testing.T) {
	t.Parallel()

	path := tempSessionsPath(t)
	mgr, err := sessions.NewManager(sessions.WithSessionsPath(path))
	require.NoError(t, err)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://api.example.com/", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "token")
	req.Header.Set("X-Env", "staging")

	require.NoError(t, mgr.WriteRequest(req,
		sessions.WithSaveAllHeaders(true),
		sessions.WithSessionName("my-session"),
	))

	mgr2, err := sessions.NewManager(sessions.WithSessionsPath(path))
	require.NoError(t, err)

	s := mgr2.Get("my-session")
	require.NotNil(t, s)
	require.Equal(t, []string{"token"}, s.Headers["Authorization"])
	require.Equal(t, []string{"staging"}, s.Headers["X-Env"])
}

func TestWriteRequest_NoHeaders_DoesNotPersist(t *testing.T) {
	t.Parallel()

	path := tempSessionsPath(t)
	mgr, err := sessions.NewManager(sessions.WithSessionsPath(path))
	require.NoError(t, err)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://api.example.com/", nil)
	require.NoError(t, err)

	require.NoError(t, mgr.WriteRequest(req))
	require.Nil(t, mgr.Get("api.example.com"))
}

func TestGetAll_RedactionAndReveal(t *testing.T) {
	t.Parallel()

	path := tempSessionsPath(t)
	mgr, err := sessions.NewManager(sessions.WithSessionsPath(path))
	require.NoError(t, err)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://svc.local/", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "secret")
	req.Header.Set("X-Env", "stage")

	require.NoError(t, mgr.WriteRequest(req,
		sessions.WithSaveAllHeaders(true),
		sessions.WithSessionName("svc"),
	))

	// Redacted
	redacted := mgr.GetAll(false)
	got := redacted["svc"].Headers
	require.Equal(t, []string{"******"}, got["Authorization"]) // len("secret") == 6
	require.Equal(t, []string{"*****"}, got["X-Env"])          // len("stage") == 5

	// Revealed
	revealed := mgr.GetAll(true)
	got2 := revealed["svc"].Headers
	require.Equal(t, []string{"secret"}, got2["Authorization"])
	require.Equal(t, []string{"stage"}, got2["X-Env"])
}

func TestDelete_PersistsRemoval(t *testing.T) {
	t.Parallel()

	path := tempSessionsPath(t)
	mgr, err := sessions.NewManager(sessions.WithSessionsPath(path))
	require.NoError(t, err)

	reqA, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://a.com/", nil)
	reqA.Header.Set("Authorization", "a")
	require.NoError(t, mgr.WriteRequest(reqA, sessions.WithSessionName("a")))

	reqB, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://b.com/", nil)
	reqB.Header.Set("Authorization", "b")
	require.NoError(t, mgr.WriteRequest(reqB, sessions.WithSessionName("b")))

	require.NoError(t, mgr.Delete("a"))

	mgr2, err := sessions.NewManager(sessions.WithSessionsPath(path))
	require.NoError(t, err)
	require.Nil(t, mgr2.Get("a"))
	require.NotNil(t, mgr2.Get("b"))
}

func TestClear_RemovesAll(t *testing.T) {
	t.Parallel()

	path := tempSessionsPath(t)
	mgr, err := sessions.NewManager(sessions.WithSessionsPath(path))
	require.NoError(t, err)

	reqA, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://a.com/", nil)
	reqA.Header.Set("Authorization", "a")
	require.NoError(t, mgr.WriteRequest(reqA, sessions.WithSessionName("a")))

	reqB, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://b.com/", nil)
	reqB.Header.Set("Authorization", "b")
	require.NoError(t, mgr.WriteRequest(reqB, sessions.WithSessionName("b")))

	require.NoError(t, mgr.Clear())

	mgr2, err := sessions.NewManager(sessions.WithSessionsPath(path))
	require.NoError(t, err)
	require.Empty(t, mgr2.GetAll(true))
}

func TestGet_NotFound(t *testing.T) {
	t.Parallel()

	path := tempSessionsPath(t)
	mgr, err := sessions.NewManager(sessions.WithSessionsPath(path))
	require.NoError(t, err)

	require.Nil(t, mgr.Get("missing"))
}
