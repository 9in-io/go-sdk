package nine

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Version is the version of this SDK, sent in the User-Agent header.
const Version = "0.1.0"

const (
	defaultTimeout = 10 * time.Second
	// Largest response body read from 9in (JWKS, discovery, API answers).
	maxResponseBody = 4 << 20
	userAgent       = "9in-go/" + Version + " (+https://github.com/9in-io/go-sdk)"
)

// newHTTPClient returns a copy of c (or a new client) that never follows redirects, sends
// no cookies and has a timeout (10 seconds unless c sets one). Requests carry client
// secrets and tokens, so a redirect is never followed: it is reported as an error.
func newHTTPClient(c *http.Client) *http.Client {
	var out http.Client
	if c != nil {
		out = *c
	}
	if out.Timeout == 0 {
		out.Timeout = defaultTimeout
	}
	out.Jar = nil
	out.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &out
}

type httpResult struct {
	status int
	header http.Header
	body   []byte
}

func (r *httpResult) ok() bool { return r.status >= 200 && r.status < 300 }

// send performs a request and reads the whole (bounded) body. Network and context errors
// become an *Error with failCode that wraps the cause.
func send(ctx context.Context, client *http.Client, method, target string, header http.Header, body []byte, failCode string) (*httpResult, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, reader)
	if err != nil {
		return nil, &Error{Code: failCode, Description: "bad request URL", cause: err}
	}
	for name, values := range header {
		req.Header[name] = values
	}
	req.Header.Set("User-Agent", userAgent)
	res, err := client.Do(req)
	if err != nil {
		return nil, &Error{Code: failCode, Description: describeNetworkError(err), cause: err}
	}
	defer res.Body.Close()
	data, err := io.ReadAll(io.LimitReader(res.Body, maxResponseBody+1))
	if err != nil {
		return nil, &Error{Code: failCode, Description: "reading the response failed", cause: err}
	}
	if len(data) > maxResponseBody {
		return nil, &Error{Code: failCode, Description: "response too large", Status: res.StatusCode}
	}
	return &httpResult{status: res.StatusCode, header: res.Header, body: data}, nil
}

// describeNetworkError keeps the reason but not the URL (which may carry a query).
func describeNetworkError(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "request timed out"
	}
	if errors.Is(err, context.Canceled) {
		return "request canceled"
	}
	return err.Error()
}

// oauthError turns a non-2xx answer into an *Error: the body's error and
// error_description when it has them, else failCode and the HTTP status.
func oauthError(res *httpResult, failCode string) *Error {
	var body struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
		Message          string `json:"message"`
		Details          any    `json:"details"`
	}
	_ = json.Unmarshal(res.body, &body)
	e := &Error{Code: body.Error, Description: body.ErrorDescription, Status: res.status, Details: body.Details}
	if e.Code == "" {
		e.Code = failCode
	}
	if e.Description == "" {
		e.Description = body.Message
	}
	if e.Description == "" {
		if res.status >= 300 && res.status < 400 {
			e.Description = fmt.Sprintf("HTTP %d (redirects are not followed)", res.status)
		} else {
			e.Description = fmt.Sprintf("HTTP %d", res.status)
		}
	}
	return e
}

// getJSON fetches a JSON document with GET.
func getJSON(ctx context.Context, client *http.Client, target string, header http.Header, failCode string, out any) error {
	h := http.Header{"Accept": {"application/json"}}
	for k, v := range header {
		h[k] = v
	}
	res, err := send(ctx, client, http.MethodGet, target, h, nil, failCode)
	if err != nil {
		return err
	}
	if !res.ok() {
		return oauthError(res, failCode)
	}
	if err := json.Unmarshal(res.body, out); err != nil {
		return &Error{Code: failCode, Description: "the response is not JSON", Status: res.status, cause: err}
	}
	return nil
}

// clientAuth is how a request authenticates its application: HTTP Basic for
// confidential applications (client_secret_basic), client_id in the form for public ones.
type clientAuth struct {
	id, secret string
}

func (c clientAuth) apply(form url.Values, header http.Header) {
	if c.secret != "" {
		header.Set("Authorization", basicAuth(c.id, c.secret))
		return
	}
	if c.id != "" {
		form.Set("client_id", c.id)
	}
}

// basicAuth encodes client credentials as RFC 6749 §2.3.1 says: form-encoded, then Base64.
func basicAuth(id, secret string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(encodeURIComponent(id)+":"+encodeURIComponent(secret)))
}

// postForm sends a form (token, revocation, introspection, device endpoints) and decodes
// a JSON answer into out (when out is not nil).
func postForm(ctx context.Context, client *http.Client, target string, form url.Values, auth clientAuth, failCode string, out any) error {
	header := http.Header{
		"Content-Type": {"application/x-www-form-urlencoded"},
		"Accept":       {"application/json"},
	}
	auth.apply(form, header)
	res, err := send(ctx, client, http.MethodPost, target, header, []byte(form.Encode()), failCode)
	if err != nil {
		return err
	}
	if !res.ok() {
		return oauthError(res, failCode)
	}
	if out == nil || len(bytes.TrimSpace(res.body)) == 0 {
		return nil
	}
	if err := json.Unmarshal(res.body, out); err != nil {
		return &Error{Code: failCode, Description: "the response is not JSON", Status: res.status, cause: err}
	}
	return nil
}

// encodeURIComponent escapes like JavaScript's encodeURIComponent (what 9in decodes).
func encodeURIComponent(s string) string {
	const unreserved = "-_.!~*'()"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.IndexByte(unreserved, c) >= 0 {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// randomString returns n random bytes, base64url-encoded.
func randomString(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand never fails on supported platforms; refuse to continue without randomness.
		panic("nine: crypto/rand failed: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// flight shares one call among concurrent callers with the same key. The call runs
// without the callers' cancellation (each caller still stops waiting when its own
// context ends), so one caller giving up doesn't fail the others.
type flight[T any] struct {
	mu    sync.Mutex
	calls map[string]*flightCall[T]
}

type flightCall[T any] struct {
	done chan struct{}
	val  T
	err  error
}

func (f *flight[T]) do(ctx context.Context, key string, fn func(context.Context) (T, error)) (T, error) {
	f.mu.Lock()
	if f.calls == nil {
		f.calls = make(map[string]*flightCall[T])
	}
	c, ok := f.calls[key]
	if !ok {
		c = &flightCall[T]{done: make(chan struct{})}
		f.calls[key] = c
		go func() {
			defer func() {
				if r := recover(); r != nil {
					c.err = fmt.Errorf("nine: panic: %v", r)
				}
				f.mu.Lock()
				delete(f.calls, key)
				f.mu.Unlock()
				close(c.done)
			}()
			c.val, c.err = fn(context.WithoutCancel(ctx))
		}()
	}
	f.mu.Unlock()
	select {
	case <-c.done:
		return c.val, c.err
	case <-ctx.Done():
		var zero T
		return zero, ctx.Err()
	}
}
