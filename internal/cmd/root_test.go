package cmd_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	cmdpkg "github.com/jclem/get/internal/cmd"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNoRedirects_StopsOnFirstRedirect(t *testing.T) {
	t.Parallel()

	var finalHit bool
	srv := newRedirectServer(t, 0, &finalHit)
	t.Cleanup(srv.Close)

	// -R should not follow the first 302.
	runCLI(t, "-R", srv.URL+"/r0")

	assert.False(t, finalHit)
}

func TestMaxRedirects_StopsAtN(t *testing.T) {
	t.Parallel()
	var finalHit bool
	srv := newRedirectServer(t, 5, &finalHit)
	t.Cleanup(srv.Close)

	// Allow at most 2 redirects. Chain has 4 redirects then final; should stop early.
	runCLI(t, "--max-redirects=2", srv.URL+"/r0")

	assert.False(t, finalHit)
}

func TestMaxRedirects_UnlimitedFollowsAll(t *testing.T) {
	t.Parallel()
	var finalHit bool
	srv := newRedirectServer(t, 15, &finalHit)
	t.Cleanup(srv.Close)

	runCLI(t, "--max-redirects=0", srv.URL+"/r0")

	assert.True(t, finalHit)
}

func runCLI(t *testing.T, args ...string) {
	t.Helper()

	cmd := cmdpkg.NewRootCmd()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs(args)

	err := cmd.ExecuteContext(context.Background())
	require.NoError(t, err)
}

// newRedirectServer creates an HTTP server that serves a chain of redirects of
// length n, ending in a 200 OK at /final. Requests begin at /r0 and each step
// responds with 302 and a Location header to the next step. When the chain is
// exhausted, /final returns 200.
//
// This is not thread-safe; create a new server for each test.
func newRedirectServer(t *testing.T, count int, finalHit *bool) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()

	// Handlers for each redirect step: /r0 -> /r1 -> ... -> /r{n-1} -> /final
	mux.HandleFunc("/final", func(w http.ResponseWriter, _ *http.Request) {
		*finalHit = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Expect path like /r{idx}
		path := strings.TrimPrefix(r.URL.Path, "/")
		if !strings.HasPrefix(path, "r") {
			http.NotFound(w, r)
			return
		}

		idxStr := strings.TrimPrefix(path, "r")
		idx, err := strconv.Atoi(idxStr)
		if err != nil {
			http.Error(w, "bad index", http.StatusBadRequest)
			return
		}

		if idx < count-1 {
			// Redirect to next step
			next := fmt.Sprintf("/r%d", idx+1)
			http.Redirect(w, r, next, http.StatusFound)
			return
		}

		// Last redirect in chain goes to /final
		http.Redirect(w, r, "/final", http.StatusFound)
	})

	return httptest.NewServer(mux)
}
