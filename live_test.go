package nine_test

// Live end-to-end tests against 9in's production test tenants (the sdk-e2e tenant, its
// sandbox and the adapter tenant), modelled on the monorepo's e2e suites. They sign real
// users in through the real hosted pages, verify real tokens, and replay real signed
// webhooks and adapter requests that 9in sent to the test receiver.
//
// Opt-in: NINE_E2E=1, with the settings in the file NINE_E2E_ENV points to (KEY=value
// lines) and/or E2E_<KEY> environment variables. Settings are never printed.
//
//	NINE_E2E=1 NINE_E2E_ENV=/path/to/.env.e2e go test -run Live -v -count=1 ./...
//
// The tests that need the confidential "E2E Server" client are skipped without
// SERVER_CLIENT_SECRET. Every user a run creates is deleted at the end.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	nine "github.com/9in-io/go-sdk"
)

// ---------------------------------------------------------------------------
// Settings

var (
	liveOnce sync.Once
	liveEnv  map[string]string
	liveRun  string
)

func live(t *testing.T) {
	t.Helper()
	if os.Getenv("NINE_E2E") != "1" {
		t.Skip("live e2e tests: set NINE_E2E=1 and NINE_E2E_ENV")
	}
	liveOnce.Do(func() {
		liveEnv = map[string]string{}
		if file := os.Getenv("NINE_E2E_ENV"); file != "" {
			f, err := os.Open(file)
			if err == nil {
				line := regexp.MustCompile(`^([A-Z0-9_]+)=(.*)$`)
				scanner := bufio.NewScanner(f)
				for scanner.Scan() {
					if m := line.FindStringSubmatch(strings.TrimSpace(scanner.Text())); m != nil {
						liveEnv[m[1]] = m[2]
					}
				}
				f.Close()
			}
		}
		for _, kv := range os.Environ() {
			if k, v, ok := strings.Cut(kv, "="); ok && strings.HasPrefix(k, "E2E_") {
				liveEnv[strings.TrimPrefix(k, "E2E_")] = v
			}
		}
		b := make([]byte, 2)
		_, _ = rand.Read(b)
		liveRun = "go" + strconv.FormatInt(time.Now().Unix(), 36) + hex.EncodeToString(b)
	})
}

func setting(t *testing.T, name string) string {
	t.Helper()
	v := liveEnv[name]
	if v == "" {
		t.Fatalf("E2E setting %s is missing", name)
	}
	return v
}

func hasSetting(name string) bool { return liveEnv[name] != "" }

func sandboxEmail() string { return "go-" + liveRun + "@sandbox.e2e.test" }

func managedEmail() string { return "managed-go-" + liveRun + "@e2e.9in.test" }

// ---------------------------------------------------------------------------
// A minimal browser for the hosted pages: a cookie jar, manual redirects, form posts.

type liveBrowser struct {
	client *http.Client
}

func newLiveBrowser() *liveBrowser {
	jar, _ := cookiejar.New(nil)
	return &liveBrowser{client: &http.Client{
		Jar:           jar,
		Timeout:       30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

type livePage struct {
	url    string
	status int
	html   string
}

func (b *liveBrowser) request(method, target string, form url.Values, referer string) (*http.Response, string, error) {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequest(method, target, body)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("User-Agent", "9in-e2e-go/1.0")
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		u, _ := url.Parse(target)
		req.Header.Set("Origin", u.Scheme+"://"+u.Host)
		req.Header.Set("Referer", referer)
	}
	res, err := b.client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer res.Body.Close()
	data, _ := io.ReadAll(res.Body)
	return res, string(data), nil
}

// follow follows redirects from target until one points at stopAt (returned as the
// callback) or a page is reached.
func (b *liveBrowser) follow(target, stopAt string) (string, *livePage, error) {
	current := target
	for hops := 0; hops < 20; hops++ {
		if stopAt != "" && strings.HasPrefix(current, stopAt) {
			return current, nil, nil
		}
		res, body, err := b.request(http.MethodGet, current, nil, "")
		if err != nil {
			return "", nil, err
		}
		if loc := res.Header.Get("Location"); res.StatusCode >= 300 && res.StatusCode < 400 && loc != "" {
			next, _ := url.Parse(current)
			current = next.ResolveReference(mustParse(loc)).String()
			continue
		}
		return "", &livePage{url: current, status: res.StatusCode, html: body}, nil
	}
	return "", nil, fmt.Errorf("too many redirects")
}

func mustParse(raw string) *url.URL {
	u, _ := url.Parse(raw)
	return u
}

var (
	formStart   = regexp.MustCompile(`<form\b`)
	inputTag    = regexp.MustCompile(`<input\b[^>]*>`)
	nameAttr    = regexp.MustCompile(`name="([^"]+)"`)
	valueAttr   = regexp.MustCompile(`value="([^"]*)"`)
	actionAttr  = regexp.MustCompile(`action="([^"]*)"`)
	scriptsTags = regexp.MustCompile(`(?s)<script.*?</script>|<style.*?</style>`)
	anyTag      = regexp.MustCompile(`<[^>]+>`)
	spaces      = regexp.MustCompile(`\s+`)
)

// firstForm returns the first form's action (resolved) and hidden fields.
func firstForm(page *livePage) (string, url.Values) {
	loc := formStart.FindStringIndex(page.html)
	if loc == nil {
		return page.url, url.Values{}
	}
	form := page.html[loc[0]:]
	if end := strings.Index(form, "</form>"); end >= 0 {
		form = form[:end]
	}
	fields := url.Values{}
	for _, input := range inputTag.FindAllString(form, -1) {
		if !strings.Contains(input, `type="hidden"`) {
			continue
		}
		name := nameAttr.FindStringSubmatch(input)
		if name == nil {
			continue
		}
		value := ""
		if m := valueAttr.FindStringSubmatch(input); m != nil {
			value = html.UnescapeString(m[1])
		}
		fields.Set(name[1], value)
	}
	action := page.url
	if m := actionAttr.FindStringSubmatch(form); m != nil && m[1] != "" {
		action = mustParse(page.url).ResolveReference(mustParse(html.UnescapeString(m[1]))).String()
	}
	return action, fields
}

func pageText(h string) string {
	return strings.TrimSpace(spaces.ReplaceAllString(html.UnescapeString(anyTag.ReplaceAllString(scriptsTags.ReplaceAllString(h, " "), " ")), " "))
}

func (p *livePage) String() string {
	if p == nil {
		return "<no page>"
	}
	text := pageText(p.html)
	if len(text) > 300 {
		text = text[:300]
	}
	return fmt.Sprintf("%d %s", p.status, text)
}

// signIn signs in on the hosted page from an authorization URL with an identifier and
// password, and returns the callback URL 9in redirected to (or the page it stopped at).
func (b *liveBrowser) signIn(authorizeURL, redirectURI, identifier, password string) (string, *livePage, error) {
	callback, page, err := b.follow(authorizeURL, redirectURI)
	if err != nil || page == nil {
		return callback, nil, err
	}
	if !strings.Contains(page.html, `name="identifier"`) {
		return "", page, nil
	}
	action, fields := firstForm(page)
	fields.Set("identifier", identifier)
	fields.Set("password", password)
	fields.Set("action", "password")
	res, body, err := b.request(http.MethodPost, action, fields, page.url)
	if err != nil {
		return "", nil, err
	}
	loc := res.Header.Get("Location")
	if loc == "" {
		return "", &livePage{url: action, status: res.StatusCode, html: body}, nil
	}
	return b.follow(mustParse(page.url).ResolveReference(mustParse(loc)).String(), redirectURI)
}

// openLoginLink opens a login link like a browser: the GET shows a page whose script
// posts the token back; this posts that form and follows the redirects.
func (b *liveBrowser) openLoginLink(link, redirectURI string) (string, *livePage, error) {
	res, body, err := b.request(http.MethodGet, link, nil, "")
	if err != nil {
		return "", nil, err
	}
	page := &livePage{url: link, status: res.StatusCode, html: body}
	if res.StatusCode != 200 || !strings.Contains(body, "data-autosubmit") {
		return "", page, nil
	}
	action, fields := firstForm(page)
	res, body, err = b.request(http.MethodPost, action, fields, link)
	if err != nil {
		return "", nil, err
	}
	loc := res.Header.Get("Location")
	if loc == "" {
		return "", &livePage{url: action, status: res.StatusCode, html: body}, nil
	}
	return b.follow(mustParse(link).ResolveReference(mustParse(loc)).String(), redirectURI)
}

func callbackQuery(t *testing.T) func(callback string, page *livePage, err error) url.Values {
	return func(callback string, page *livePage, err error) url.Values {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		if callback == "" {
			t.Fatalf("sign-in did not reach the callback: %s", page)
		}
		return mustParse(callback).Query()
	}
}

// ---------------------------------------------------------------------------
// The receiver's records

type webhookRecord struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	Environment string `json:"environment"`
	UserID      string `json:"userId"`
	Raw         string `json:"raw"`
	Signature   string `json:"signature"`
	Path        string `json:"path"`
	At          int64  `json:"at"`
}

type adapterRecord struct {
	Path      string `json:"path"`
	Body      string `json:"body"`
	Signature string `json:"signature"`
	RequestID string `json:"requestId"`
	At        int64  `json:"at"`
}

func records[T any](t *testing.T, kind string) []T {
	t.Helper()
	target := setting(t, "RECEIVER_URL") + "/records?kind=" + url.QueryEscape(kind) + "&t=" + url.QueryEscape(setting(t, "RECEIVER_TOKEN"))
	res, err := http.Get(target)
	if err != nil {
		t.Fatalf("receiver: %v", errors.Unwrap(err))
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("receiver: %d", res.StatusCode)
	}
	var out []T
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

func waitFor[T any](t *testing.T, kind string, match func(T) bool) T {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		for _, r := range records[T](t, kind) {
			if match(r) {
				return r
			}
		}
		time.Sleep(1500 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for a %s record", kind)
	var zero T
	return zero
}

// ---------------------------------------------------------------------------
// Cleanup: users this run created are deleted through the Management API.

type cleanup struct {
	mu    sync.Mutex
	users map[string][]string // issuer → user ids
}

var created = &cleanup{users: map[string][]string{}}

func (c *cleanup) add(issuer, id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, existing := range c.users[issuer] {
		if existing == id {
			return
		}
	}
	c.users[issuer] = append(c.users[issuer], id)
}

func (c *cleanup) run(t *testing.T) {
	if !hasSetting("SERVER_CLIENT_SECRET") {
		t.Log("SERVER_CLIENT_SECRET missing: test users are not deleted")
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for issuer, ids := range c.users {
		m, err := nine.NewManagementClient(nine.ManagementConfig{Issuer: issuer, ClientID: setting(t, "SERVER_CLIENT_ID"), ClientSecret: setting(t, "SERVER_CLIENT_SECRET")})
		if err != nil {
			t.Error(err)
			continue
		}
		for _, id := range ids {
			if err := m.DeleteUser(context.Background(), id); err != nil && !errors.Is(err, nine.ErrNotFound) {
				t.Errorf("deleting test user: %v", err)
			}
		}
		t.Logf("deleted %d test user(s)", len(ids))
	}
}

// ---------------------------------------------------------------------------
// The tests

func TestLive(t *testing.T) {
	live(t)
	t.Cleanup(func() { created.run(t) })
	ctx := context.Background()
	start := time.Now().UnixMilli()

	sandbox := setting(t, "SANDBOX_ISSUER")
	spa := func(t *testing.T) *nine.WebAppAuth {
		return mustLive[*nine.WebAppAuth](t)(nine.NewWebAppAuth(nine.WebAppAuthConfig{
			Issuer:      sandbox,
			ClientID:    setting(t, "SPA_CLIENT_ID"),
			RedirectURI: setting(t, "SPA_REDIRECT_URI"),
			Audience:    setting(t, "API_AUDIENCE"),
			Scopes:      []string{"openid", "profile", "email", "offline_access", "read:things"},
		}))
	}
	signInSandbox := func(t *testing.T, auth *nine.WebAppAuth, opts nine.LoginOptions) (*nine.Login, url.Values) {
		t.Helper()
		login := mustLive[*nine.Login](t)(auth.CreateLogin(ctx, opts))
		return login, callbackQuery(t)(newLiveBrowser().signIn(login.URL, setting(t, "SPA_REDIRECT_URI"), sandboxEmail(), "any-password"))
	}

	var session *nine.TokenSet
	auth := spa(t)

	t.Run("discovery", func(t *testing.T) {
		doc := mustLive[*nine.Discovery](t)(auth.Discovery(ctx))
		if doc.Issuer != sandbox || !strings.HasPrefix(doc.TokenEndpoint, sandbox) || doc.IntrospectionEndpoint == "" || doc.DeviceAuthorizationEndpoint == "" || !doc.AuthorizationResponseIssParameterSupported {
			t.Fatalf("discovery %+v", doc)
		}
	})

	t.Run("sign-in with PKCE through the hosted page", func(t *testing.T) {
		login, query := signInSandbox(t, auth, nine.LoginOptions{ReturnTo: "/go-after"})
		if query.Get("iss") != sandbox {
			t.Fatalf("iss %q", query.Get("iss"))
		}
		tokens, err := auth.HandleCallback(ctx, query, login.Pending)
		if err != nil {
			t.Fatal(err)
		}
		created.add(sandbox, tokens.Claims.Subject())
		if tokens.ReturnTo != "/go-after" || tokens.RefreshToken == "" || tokens.Expired(0) {
			t.Fatalf("tokens %+v", tokens)
		}
		if tokens.Claims.String("email") != sandboxEmail() || len(tokens.Claims.Audience()) != 1 || tokens.Claims.Audience()[0] != setting(t, "SPA_CLIENT_ID") {
			t.Fatalf("claims %v", tokens.Claims)
		}
		info := mustLive[nine.Claims](t)(auth.UserInfo(ctx, tokens.AccessToken))
		if info.Subject() != tokens.Claims.Subject() || info.String("email") != sandboxEmail() {
			t.Fatalf("userinfo %v", info)
		}
		// The token set survives a session round trip.
		data, _ := json.Marshal(tokens)
		var back nine.TokenSet
		if err := json.Unmarshal(data, &back); err != nil || back.RefreshToken != tokens.RefreshToken || back.Claims.Subject() != tokens.Claims.Subject() {
			t.Fatal("round trip")
		}
		session = tokens
	})
	if session == nil {
		t.FailNow()
	}

	t.Run("access tokens verify locally", func(t *testing.T) {
		v := mustLive[*nine.Verifier](t)(nine.NewVerifier(nine.VerifierConfig{Issuer: sandbox, Audience: setting(t, "API_AUDIENCE")}))
		claims, err := v.Verify(ctx, "Bearer "+session.AccessToken, "read:things")
		if err != nil {
			t.Fatal(err)
		}
		if claims.Subject() != session.Claims.Subject() || claims.ClientID() != setting(t, "SPA_CLIENT_ID") || claims.SessionID() == "" {
			t.Fatalf("claims %v", claims)
		}
		_, err = v.Verify(ctx, session.AccessToken, "write:things")
		if !errors.Is(err, nine.ErrInsufficientScope) {
			t.Fatalf("want insufficient_scope, got %v", err)
		}
		other := mustLive[*nine.Verifier](t)(nine.NewVerifier(nine.VerifierConfig{Issuer: sandbox, Audience: "https://other.e2e.9in.test"}))
		for _, bad := range []struct {
			v     *nine.Verifier
			token string
		}{{other, session.AccessToken}, {v, session.AccessToken[:len(session.AccessToken)-4] + "AAAA"}, {v, session.IDToken}} {
			_, err := bad.v.Verify(ctx, bad.token)
			var e *nine.Error
			if !errors.As(err, &e) || e.Code != "invalid_token" || e.Status != 401 {
				t.Fatalf("want invalid_token, got %v", err)
			}
		}
		// The ID token verifies as an ID token for the SPA client, not for another one.
		if _, err := v.VerifyIDToken(ctx, session.IDToken, setting(t, "SPA_CLIENT_ID"), ""); err != nil {
			t.Fatal(err)
		}
		if _, err := v.VerifyIDToken(ctx, session.IDToken, "app_someoneelse", ""); !errors.Is(err, nine.ErrInvalidIDToken) {
			t.Fatalf("want invalid_id_token, got %v", err)
		}
	})

	t.Run("refresh rotates, revocation sticks, logout URL", func(t *testing.T) {
		rotated := mustLive[*nine.TokenSet](t)(auth.Refresh(ctx, session.RefreshToken))
		if rotated.RefreshToken == session.RefreshToken || rotated.AccessToken == session.AccessToken {
			t.Fatal("not rotated")
		}
		if rotated.Claims.Subject() != session.Claims.Subject() {
			t.Fatal("the refreshed ID token is verified")
		}
		if same := mustLive[*nine.TokenSet](t)(auth.EnsureFresh(ctx, rotated, time.Minute)); same != rotated {
			t.Fatal("a fresh set is returned as is")
		}
		// Within 30 seconds a repeat is a race, not reuse: the same new refresh token comes back.
		if again := mustLive[*nine.TokenSet](t)(auth.Refresh(ctx, session.RefreshToken)); again.RefreshToken != rotated.RefreshToken {
			t.Fatal("grace window")
		}
		other := spa(t)
		login, query := signInSandbox(t, other, nine.LoginOptions{})
		tokens := mustLive[*nine.TokenSet](t)(other.HandleCallback(ctx, query, login.Pending))
		if err := other.Revoke(ctx, tokens.RefreshToken, ""); err != nil {
			t.Fatal(err)
		}
		if _, err := other.Refresh(ctx, tokens.RefreshToken); !errors.Is(err, nine.ErrInvalidGrant) {
			t.Fatalf("a revoked refresh token must be refused: %v", err)
		}
		logout := mustLive[string](t)(other.LogoutURL(ctx, nine.LogoutOptions{IDTokenHint: tokens.IDToken, PostLogoutRedirectURI: "http://127.0.0.1:8931/"}))
		u := mustParse(logout)
		if u.Scheme+"://"+u.Host+u.Path != sandbox+"/oauth/logout" || u.Query().Get("id_token_hint") != tokens.IDToken || u.Query().Get("client_id") != setting(t, "SPA_CLIENT_ID") {
			t.Fatalf("logout %s", u.Path)
		}
		session = rotated
	})

	t.Run("bad callbacks are refused without spending the code", func(t *testing.T) {
		a := spa(t)
		login, query := signInSandbox(t, a, nine.LoginOptions{})
		with := func(k, v string) url.Values {
			out := url.Values{}
			for key, vals := range query {
				out[key] = vals
			}
			out.Set(k, v)
			return out
		}
		for code, q := range map[string]url.Values{
			"invalid_state":  with("state", "forged"),
			"invalid_issuer": with("iss", "https://evil.example"),
			"access_denied":  {"error": {"access_denied"}, "state": {login.Pending.State}},
		} {
			_, err := a.HandleCallback(ctx, q, login.Pending)
			var e *nine.Error
			if !errors.As(err, &e) || e.Code != code {
				t.Fatalf("want %s, got %v", code, err)
			}
		}
		if _, err := a.HandleCallback(ctx, query, &nine.PendingLogin{State: login.Pending.State, Nonce: "wrong", Verifier: login.Pending.Verifier, RedirectURI: login.Pending.RedirectURI, CreatedAt: login.Pending.CreatedAt}); !errors.Is(err, nine.ErrInvalidIDToken) {
			// The nonce is checked after the code exchange, so this spends the code…
			t.Fatalf("wrong nonce: %v", err)
		}
		// …and a fresh sign-in shows the real callback works once, then not again.
		login, query = signInSandbox(t, a, nine.LoginOptions{})
		if _, err := a.HandleCallback(ctx, query, login.Pending); err != nil {
			t.Fatal(err)
		}
		if _, err := a.HandleCallback(ctx, query, login.Pending); !errors.Is(err, nine.ErrInvalidState) {
			t.Fatalf("replay: %v", err)
		}
	})

	t.Run("real webhook deliveries verify", func(t *testing.T) {
		if !hasSetting("RECEIVER_URL") {
			t.Skip("no receiver")
		}
		sub := session.Claims.Subject()
		secret := setting(t, "WEBHOOK_SECRET")
		createdHook := waitFor(t, "webhooks", func(r webhookRecord) bool { return r.Type == "user.created" && r.UserID == sub })
		loginHook := waitFor(t, "webhooks", func(r webhookRecord) bool { return r.Type == "user.login" && r.UserID == sub })

		event, err := nine.VerifyWebhook([]string{secret}, []byte(createdHook.Raw), createdHook.Signature, createdHook.Path)
		if err != nil {
			t.Fatal(err)
		}
		u, err := event.User()
		if err != nil || event.EventType != "user.created" || event.UserID() != sub || u.Email != sandboxEmail() || event.Tenant != setting(t, "TENANT_ID") || event.Environment != "sandbox" || event.CreatedAt.IsZero() {
			t.Fatalf("event %+v %v", event, err)
		}
		if _, has := event.Data["userId"]; has {
			t.Fatal("camelCase key in the event")
		}
		if e2, err := nine.VerifyWebhook([]string{"whsec_old", secret}, []byte(loginHook.Raw), loginHook.Signature, loginHook.Path); err != nil || e2.ID != loginHook.ID {
			t.Fatalf("rotation: %v", err)
		}
		for name, verify := range map[string]func() error{
			"wrong secret": func() error {
				_, err := nine.VerifyWebhook([]string{"whsec_wrong"}, []byte(loginHook.Raw), loginHook.Signature, loginHook.Path)
				return err
			},
			"altered body": func() error {
				_, err := nine.VerifyWebhook([]string{secret}, []byte(strings.Replace(loginHook.Raw, "user.login", "user.deleted", 1)), loginHook.Signature, loginHook.Path)
				return err
			},
			"other path": func() error {
				_, err := nine.VerifyWebhook([]string{secret}, []byte(loginHook.Raw), loginHook.Signature, "/elsewhere")
				return err
			},
			"no signature": func() error {
				_, err := nine.VerifyWebhook([]string{secret}, []byte(loginHook.Raw), "", loginHook.Path)
				return err
			},
		} {
			if err := verify(); !errors.Is(err, nine.ErrInvalidSignature) {
				t.Fatalf("%s: %v", name, err)
			}
		}
		// The real delivery through WebhookHandler, twice: handled once.
		var handled int
		var mu sync.Mutex
		h := nine.WebhookHandler(nine.WebhookConfig{Secret: secret, Handle: func(ctx context.Context, e *nine.WebhookEvent) error {
			mu.Lock()
			handled++
			mu.Unlock()
			return nil
		}})
		for i := 0; i < 2; i++ {
			r := httptest.NewRequest(http.MethodPost, loginHook.Path, strings.NewReader(loginHook.Raw))
			r.Header.Set(nine.SignatureHeader, loginHook.Signature)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != http.StatusNoContent {
				t.Fatalf("delivery %d: %d %s", i, w.Code, w.Body)
			}
		}
		if handled != 1 {
			t.Fatalf("handled %d times", handled)
		}
	})

	t.Run("adapter: sign-in and real adapter requests", func(t *testing.T) {
		if !hasSetting("ADAPTER_ISSUER") {
			t.Skip("no adapter tenant")
		}
		since := time.Now().UnixMilli()
		adapterAuth := mustLive[*nine.WebAppAuth](t)(nine.NewWebAppAuth(nine.WebAppAuthConfig{Issuer: setting(t, "ADAPTER_ISSUER"), ClientID: setting(t, "ADAPTER_SPA_CLIENT_ID"), RedirectURI: setting(t, "ADAPTER_SPA_REDIRECT_URI")}))
		login := mustLive[*nine.Login](t)(adapterAuth.CreateLogin(ctx, nine.LoginOptions{}))
		query := callbackQuery(t)(newLiveBrowser().signIn(login.URL, setting(t, "ADAPTER_SPA_REDIRECT_URI"), "alice@adapter.e2e.test", "Alice-Password-1"))
		tokens := mustLive[*nine.TokenSet](t)(adapterAuth.HandleCallback(ctx, query, login.Pending))
		if tokens.Claims.String("email") != "alice@adapter.e2e.test" || tokens.Claims.String("name") != "Alice Adapter" {
			t.Fatalf("claims %v", tokens.Claims)
		}
		wrong := mustLive[*nine.Login](t)(adapterAuth.CreateLogin(ctx, nine.LoginOptions{}))
		callback, page, err := newLiveBrowser().signIn(wrong.URL, setting(t, "ADAPTER_SPA_REDIRECT_URI"), "alice@adapter.e2e.test", "go-wrong-password")
		if err != nil || callback != "" || page == nil || page.status != 401 {
			t.Fatalf("wrong password: %v %q %s", err, callback, page)
		}
		blocked := mustLive[*nine.Login](t)(adapterAuth.CreateLogin(ctx, nine.LoginOptions{}))
		callback, page, err = newLiveBrowser().signIn(blocked.URL, setting(t, "ADAPTER_SPA_REDIRECT_URI"), "bob@adapter.e2e.test", "Bob-Password-1")
		if err != nil || callback != "" || page == nil || !strings.Contains(strings.ToLower(pageText(page.html)), "blocked") {
			t.Fatalf("blocked user: %v %q %s", err, callback, page)
		}

		raw := func(needle string) adapterRecord {
			return waitFor(t, "adapter-raw", func(r adapterRecord) bool {
				return r.At >= since && strings.HasSuffix(r.Path, "/authenticate") && strings.Contains(r.Body, needle)
			})
		}
		ok := raw("Alice-Password-1")
		refused := raw("go-wrong-password")
		bob := raw("bob@adapter.e2e.test")

		secret := setting(t, "ADAPTER_SECRET")
		h := nine.AdapterHandler(nine.AdapterConfig{Secret: secret, Adapter: liveAdapter{}})
		replay := func(method, path, body string, r adapterRecord) *httptest.ResponseRecorder {
			req := httptest.NewRequest(method, path, strings.NewReader(body))
			req.Header.Set("9in-Signature", r.Signature)
			req.Header.Set("9in-Request-Id", r.RequestID)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			return w
		}
		w := replay(http.MethodPost, ok.Path, ok.Body, ok)
		var reply struct {
			User nine.AdapterUser `json:"user"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &reply)
		if w.Code != 200 || reply.User.ID != "ext_alice" {
			t.Fatalf("authenticate: %d %s", w.Code, w.Body)
		}
		if err := nine.VerifySignature([]string{secret}, w.Header().Get("9in-signature"), "POST", ok.Path+"#"+ok.RequestID, w.Body.Bytes(), 0); err != nil {
			t.Fatalf("the response must be signed over the request id: %v", err)
		}
		if w := replay(http.MethodPost, refused.Path, refused.Body, refused); w.Code != 401 || !strings.Contains(w.Body.String(), "invalid_credentials") {
			t.Fatalf("wrong password: %d %s", w.Code, w.Body)
		}
		if w := replay(http.MethodPost, bob.Path, bob.Body, bob); w.Code != 403 || !strings.Contains(w.Body.String(), "blocked") {
			t.Fatalf("blocked: %d %s", w.Code, w.Body)
		}
		if w := replay(http.MethodPost, ok.Path, strings.Replace(ok.Body, "alice@", "bob@", 1), ok); w.Code != 401 || !strings.Contains(w.Body.String(), "invalid_signature") {
			t.Fatalf("altered body: %d", w.Code)
		}
		if w := replay(http.MethodPost, "/elsewhere/authenticate", ok.Body, ok); w.Code != 401 {
			t.Fatalf("other path: %d", w.Code)
		}
		if w := replay(http.MethodGet, ok.Path, ok.Body, ok); w.Code != 405 {
			t.Fatalf("GET: %d", w.Code)
		}
	})

	t.Run("device flow errors pass through", func(t *testing.T) {
		d := mustLive[*nine.DeviceAuth](t)(nine.NewDeviceAuth(nine.DeviceAuthConfig{Issuer: sandbox, ClientID: setting(t, "SPA_CLIENT_ID")}))
		_, err := d.Start(ctx)
		var e *nine.Error
		if !errors.As(err, &e) || e.Code != "unauthorized_client" || e.Status != 400 {
			t.Fatalf("the SPA client has no device grant: want unauthorized_client, got %v", err)
		}
	})

	if !hasSetting("SERVER_CLIENT_SECRET") {
		t.Log("SERVER_CLIENT_SECRET missing: the confidential-client tests are skipped")
		return
	}
	liveConfidential(t, ctx, start)
}

// liveAdapter answers like the receiver's user database for alice and bob.
type liveAdapter struct{}

func (liveAdapter) Authenticate(_ context.Context, id nine.Identifier, password string) (*nine.AdapterUser, error) {
	switch strings.ToLower(id.Value) {
	case "alice@adapter.e2e.test":
		if password == "Alice-Password-1" {
			return &nine.AdapterUser{ID: "ext_alice", Email: "alice@adapter.e2e.test", Name: "Alice Adapter"}, nil
		}
	case "bob@adapter.e2e.test":
		return nil, nine.ErrUserBlocked
	}
	return nil, nine.ErrInvalidCredentials
}

func (liveAdapter) FindUser(context.Context, nine.UserQuery) (*nine.AdapterUser, error) {
	return nil, nil
}

func (liveAdapter) OnEvent(context.Context, *nine.AdapterEvent) error { return nil }

func mustLive[T any](t *testing.T) func(T, error) T {
	return func(v T, err error) T {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
}

// ---------------------------------------------------------------------------
// The confidential "E2E Server" client, on the production environment

func liveConfidential(t *testing.T, ctx context.Context, start int64) {
	issuer := setting(t, "ISSUER")
	clientID := setting(t, "SERVER_CLIENT_ID")
	secret := setting(t, "SERVER_CLIENT_SECRET")
	redirect := setting(t, "SERVER_REDIRECT_URI")
	audience := setting(t, "API_AUDIENCE")
	email := managedEmail()
	password := "E2e-" + liveRun + "-Password!"

	m := mustLive[*nine.ManagementClient](t)(nine.NewManagementClient(nine.ManagementConfig{Issuer: issuer, ClientID: clientID, ClientSecret: secret}))
	user, err := m.CreateUser(ctx, nine.NewUser{Email: email, Password: password, Name: "Managed Go E2E", EmailVerified: true, Metadata: map[string]any{"run": liveRun}})
	if err != nil {
		t.Fatal(err)
	}
	created.add(issuer, user.ID)

	server := func(t *testing.T, audience string, scopes ...string) *nine.WebAppAuth {
		return mustLive[*nine.WebAppAuth](t)(nine.NewWebAppAuth(nine.WebAppAuthConfig{Issuer: issuer, ClientID: clientID, ClientSecret: secret, RedirectURI: redirect, Audience: audience, Scopes: scopes}))
	}
	serverSignIn := func(t *testing.T, a *nine.WebAppAuth, b *liveBrowser) *nine.TokenSet {
		t.Helper()
		login := mustLive[*nine.Login](t)(a.CreateLogin(ctx, nine.LoginOptions{ReturnTo: "/account"}))
		query := callbackQuery(t)(b.signIn(login.URL, redirect, email, password))
		return mustLive[*nine.TokenSet](t)(a.HandleCallback(ctx, query, login.Pending))
	}

	t.Run("management API round trip", func(t *testing.T) {
		if user.Email != email || !user.EmailVerified || user.Name != "Managed Go E2E" || user.Blocked || user.Metadata["run"] != liveRun || user.CreatedAt.IsZero() {
			t.Fatalf("created %+v", user)
		}
		if d := mustLive[*nine.UserDetail](t)(m.GetUser(ctx, user.ID)); d.User.Email != email || !d.HasPassword {
			t.Fatalf("get %+v", d)
		}
		if u := mustLive[*nine.ManagedUser](t)(m.FindUserByEmail(ctx, strings.ToUpper(email))); u.ID != user.ID {
			t.Fatal("find by email is case-insensitive")
		}
		list := mustLive[*nine.UserList](t)(m.ListUsers(ctx, nine.ListUsersOptions{Query: liveRun, Limit: 5}))
		found := false
		for _, u := range list.Users {
			found = found || u.ID == user.ID
		}
		if !found {
			t.Fatal("list")
		}
		if u := mustLive[*nine.ManagedUser](t)(m.UpdateUser(ctx, user.ID, nine.UserChanges{"name": "Renamed Go E2E"})); u.Name != "Renamed Go E2E" {
			t.Fatal("update")
		}
		_, err := m.CreateUser(ctx, nine.NewUser{Email: email, Password: password})
		var e *nine.Error
		if !errors.As(err, &e) || e.Status != 409 || e.Code != "identifier_taken" {
			t.Fatalf("duplicate: %v", err)
		}
		if _, err := m.GetUser(ctx, "usr_doesnotexist000000"); !errors.Is(err, nine.ErrNotFound) && errorStatus(err) != 404 {
			t.Fatalf("unknown id: %v", err)
		}
		if _, err := m.FindUserByEmail(ctx, "nobody-"+liveRun+"@e2e.9in.test"); errorStatus(err) != 404 {
			t.Fatalf("unknown email: %v", err)
		}
		_, err = m.UpdateUser(ctx, user.ID, nine.UserChanges{"nmae": "typo"})
		if !errors.As(err, &e) || e.Code != "invalid_user" || e.Details == nil {
			t.Fatalf("unknown field: %v", err)
		}
	})

	t.Run("block and unblock", func(t *testing.T) {
		if u := mustLive[*nine.ManagedUser](t)(m.BlockUser(ctx, user.ID)); !u.Blocked {
			t.Fatal("block")
		}
		a := server(t, "")
		login := mustLive[*nine.Login](t)(a.CreateLogin(ctx, nine.LoginOptions{}))
		callback, page, err := newLiveBrowser().signIn(login.URL, redirect, email, password)
		if err != nil || callback != "" || page == nil || !strings.Contains(strings.ToLower(pageText(page.html)), "blocked") {
			t.Fatalf("blocked sign-in: %v %q %s", err, callback, page)
		}
		if u := mustLive[*nine.ManagedUser](t)(m.UnblockUser(ctx, user.ID)); u.Blocked {
			t.Fatal("unblock")
		}
	})

	t.Run("server-side sign-in with a client secret", func(t *testing.T) {
		a := server(t, audience, "openid", "profile", "email", "offline_access", "read:things")
		tokens := serverSignIn(t, a, newLiveBrowser())
		if tokens.ReturnTo != "/account" || tokens.Claims.Subject() != user.ID || tokens.Claims.String("email") != email || tokens.Claims.Audience()[0] != clientID {
			t.Fatalf("tokens %+v", tokens)
		}
		if _, err := a.VerifyIDToken(ctx, tokens.IDToken, ""); err != nil {
			t.Fatal(err)
		}
		if info := mustLive[nine.Claims](t)(a.UserInfo(ctx, tokens.AccessToken)); info.String("email") != email {
			t.Fatal("userinfo")
		}
		v := mustLive[*nine.Verifier](t)(nine.NewVerifier(nine.VerifierConfig{Issuer: issuer, Audience: audience}))
		if c := mustLive[nine.Claims](t)(v.Verify(ctx, tokens.AccessToken, "read:things")); c.Subject() != user.ID {
			t.Fatal("verify")
		}
		if same := mustLive[*nine.TokenSet](t)(a.EnsureFresh(ctx, tokens, time.Minute)); same != tokens {
			t.Fatal("fresh")
		}
		stale := *tokens
		stale.ExpiresAt = time.Now()
		refreshed := mustLive[*nine.TokenSet](t)(a.EnsureFresh(ctx, &stale, time.Minute))
		if refreshed.RefreshToken == tokens.RefreshToken || refreshed.Claims.Subject() != user.ID || refreshed.ReturnTo != "/account" {
			t.Fatal("refreshed")
		}
		if again := mustLive[*nine.TokenSet](t)(a.Refresh(ctx, tokens.RefreshToken)); again.RefreshToken != refreshed.RefreshToken {
			t.Fatal("grace")
		}
		if err := a.Revoke(ctx, refreshed.RefreshToken, "refresh_token"); err != nil {
			t.Fatal(err)
		}
		if _, err := a.Refresh(ctx, refreshed.RefreshToken); !errors.Is(err, nine.ErrInvalidGrant) {
			t.Fatalf("revoked: %v", err)
		}
		if _, err := a.Refresh(ctx, tokens.RefreshToken); !errors.Is(err, nine.ErrInvalidGrant) {
			t.Fatalf("revoking the family ends the grace: %v", err)
		}
		logout := mustParse(mustLive[string](t)(a.LogoutURL(ctx, nine.LogoutOptions{IDTokenHint: refreshed.IDToken})))
		if logout.Scheme+"://"+logout.Host+logout.Path != issuer+"/oauth/logout" {
			t.Fatal("logout URL")
		}
	})

	t.Run("client credentials", func(t *testing.T) {
		cc := mustLive[*nine.ClientCredentials](t)(nine.NewClientCredentials(nine.ClientCredentialsConfig{Issuer: issuer, ClientID: clientID, ClientSecret: secret, Audience: audience, Scopes: []string{"read:things"}}))
		token := mustLive[string](t)(cc.Token(ctx))
		if again := mustLive[string](t)(cc.Token(ctx)); again != token {
			t.Fatal("cached")
		}
		v := mustLive[*nine.Verifier](t)(nine.NewVerifier(nine.VerifierConfig{Issuer: issuer, Audience: audience}))
		claims := mustLive[nine.Claims](t)(v.Verify(ctx, token, "read:things"))
		if claims.ClientID() != clientID || !claims.IsMachine() {
			t.Fatalf("claims %v", claims)
		}
		a := server(t, "")
		set := mustLive[*nine.TokenSet](t)(a.ClientCredentials(ctx, nine.ClientCredentialsOptions{Audience: audience, Scope: "read:things"}))
		if set.RefreshToken != "" || set.AccessToken == "" {
			t.Fatal("client credentials token set")
		}
	})

	t.Run("login links, prompt=none and ending every session", func(t *testing.T) {
		link := mustLive[*nine.LoginLink](t)(m.CreateLoginLink(ctx, user.ID, nine.LoginLinkOptions{ReturnTo: redirect, TTL: 5 * time.Minute}))
		if !strings.HasPrefix(link.URL, issuer+"/") || !link.ExpiresAt.After(time.Now()) {
			t.Fatalf("link %+v", link)
		}
		// A GET alone (a mail scanner) does not use the link up.
		if res, _, err := newLiveBrowser().request(http.MethodGet, link.URL, nil, ""); err != nil || res.StatusCode != 200 {
			t.Fatal("GET")
		}
		b := newLiveBrowser()
		landed, page, err := b.openLoginLink(link.URL, redirect)
		if err != nil || !strings.HasPrefix(landed, redirect) {
			t.Fatalf("link: %v %s", err, page)
		}
		if again, page, _ := newLiveBrowser().openLoginLink(link.URL, redirect); again != "" || page == nil || page.status != 400 {
			t.Fatalf("a login link is single use: %q %s", again, page)
		}
		a := server(t, "")
		login := mustLive[*nine.Login](t)(a.CreateLogin(ctx, nine.LoginOptions{Prompt: "none"}))
		silent, page, err := b.follow(login.URL, redirect)
		query := callbackQuery(t)(silent, page, err)
		if query.Get("code") == "" {
			t.Fatal("prompt=none without a code")
		}
		if tokens := mustLive[*nine.TokenSet](t)(a.HandleCallback(ctx, query, login.Pending)); tokens.Claims.Subject() != user.ID {
			t.Fatal("silent sign-in")
		}
		if n := mustLive[int](t)(m.RevokeUserSessions(ctx, user.ID)); n < 1 {
			t.Fatalf("revoked %d", n)
		}
		after := mustLive[*nine.Login](t)(a.CreateLogin(ctx, nine.LoginOptions{Prompt: "none"}))
		denied, page, err := b.follow(after.URL, redirect)
		q := callbackQuery(t)(denied, page, err)
		if q.Get("error") != "login_required" {
			t.Fatalf("after ending sessions: %v", q)
		}
		if _, err := a.HandleCallback(ctx, q, after.Pending); !errors.Is(err, nine.ErrLoginRequired) {
			t.Fatalf("login_required: %v", err)
		}
	})

	t.Run("sessions: list, end one, introspection sees it", func(t *testing.T) {
		a := server(t, audience, "openid", "email", "offline_access", "read:things")
		tokens := serverSignIn(t, a, newLiveBrowser())
		sid := tokens.Claims.SessionID()
		sessions := mustLive[[]nine.ManagedSession](t)(m.ListUserSessions(ctx, user.ID))
		var mine *nine.ManagedSession
		for i := range sessions {
			if sessions[i].SID == sid {
				mine = &sessions[i]
			}
		}
		if mine == nil || mine.UserID != user.ID || len(mine.AMR) != 1 || mine.AMR[0] != "pwd" || !mine.ExpiresAt.After(time.Now()) || mine.AuthTime.IsZero() {
			t.Fatalf("session %+v", mine)
		}
		introspect := mustLive[*nine.Verifier](t)(nine.NewVerifier(nine.VerifierConfig{Issuer: issuer, Audience: audience, ClientID: clientID, ClientSecret: secret, Mode: nine.ModeIntrospect}))
		if c := mustLive[nine.Claims](t)(introspect.Verify(ctx, tokens.AccessToken)); c.SessionID() != sid {
			t.Fatal("introspect")
		}
		if err := m.RevokeSession(ctx, sid); err != nil {
			t.Fatal(err)
		}
		for _, s := range mustLive[[]nine.ManagedSession](t)(m.ListUserSessions(ctx, user.ID)) {
			if s.SID == sid {
				t.Fatal("still listed")
			}
		}
		if _, err := introspect.Verify(ctx, tokens.AccessToken); !errors.Is(err, nine.ErrInvalidToken) {
			t.Fatalf("introspection after revocation: %v", err)
		}
		if _, err := a.Refresh(ctx, tokens.RefreshToken); !errors.Is(err, nine.ErrInvalidGrant) {
			t.Fatalf("refresh after revocation: %v", err)
		}
		if err := m.RevokeSession(ctx, sid); errorStatus(err) != 404 {
			t.Fatalf("revoking again: %v", err)
		}
		if u := mustLive[*nine.ManagedUser](t)(m.FindUser(ctx, "email", strings.ToUpper(email))); u.ID != user.ID {
			t.Fatal("find by email")
		}
		if _, err := m.FindUser(ctx, "username", "nobody_"+liveRun); errorStatus(err) != 404 {
			t.Fatalf("unknown username: %v", err)
		}
	})

	t.Run("import users", func(t *testing.T) {
		id := "e2e|" + liveRun
		imported := "imported-" + liveRun + "@e2e.9in.test"
		importedPassword := "Imp-" + liveRun + "-Password!"
		created.add(issuer, id)
		createdAt := time.Date(2020, 1, 2, 4, 4, 5, 0, time.FixedZone("", 3600))
		results := mustLive[[]nine.ImportResult](t)(m.ImportUsers(ctx, []nine.ImportUser{
			{ID: id, NewUser: nine.NewUser{Email: imported, EmailVerified: true, Name: "Imported Go E2E", Password: importedPassword}, CreatedAt: &createdAt},
			{NewUser: nine.NewUser{Email: "broken-" + liveRun + "@e2e.9in.test", PasswordHash: "md5:not-supported"}},
		}, nine.ImportOptions{Source: "e2e"}))
		if len(results) != 2 || results[0].Status != "created" || results[0].ID != id || !results[0].OK || results[1].OK || results[1].Error != "unsupported_password_hash" {
			t.Fatalf("results %+v", results)
		}
		if r := mustLive[[]nine.ImportResult](t)(m.ImportUsers(ctx, []nine.ImportUser{{ID: id, NewUser: nine.NewUser{Email: imported, Name: "Changed"}}}, nine.ImportOptions{})); r[0].Status != "skipped" {
			t.Fatalf("skip %+v", r)
		}
		if r := mustLive[[]nine.ImportResult](t)(m.ImportUsers(ctx, []nine.ImportUser{{ID: id, NewUser: nine.NewUser{Email: imported, Name: "Changed"}}}, nine.ImportOptions{OnConflict: "update"})); r[0].Status != "updated" {
			t.Fatalf("update %+v", r)
		}
		got := mustLive[*nine.UserDetail](t)(m.GetUser(ctx, id)).User
		if got.Name != "Changed" || !got.CreatedAt.Equal(time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)) {
			t.Fatalf("imported %+v", got)
		}
		a := server(t, "")
		login := mustLive[*nine.Login](t)(a.CreateLogin(ctx, nine.LoginOptions{}))
		query := callbackQuery(t)(newLiveBrowser().signIn(login.URL, redirect, imported, importedPassword))
		if tokens := mustLive[*nine.TokenSet](t)(a.HandleCallback(ctx, query, login.Pending)); tokens.Claims.Subject() != id {
			t.Fatal("the imported user signs in")
		}
	})

	t.Run("hybrid verification drops a revoked token when the webhook arrives", func(t *testing.T) {
		a := server(t, audience, "openid", "email", "offline_access", "read:things")
		tokens := serverSignIn(t, a, newLiveBrowser())
		hybrid := mustLive[*nine.Verifier](t)(nine.NewVerifier(nine.VerifierConfig{Issuer: issuer, Audience: audience, ClientID: clientID, ClientSecret: secret}))
		introspect := mustLive[*nine.Verifier](t)(nine.NewVerifier(nine.VerifierConfig{Issuer: issuer, Audience: audience, ClientID: clientID, ClientSecret: secret, Mode: nine.ModeIntrospect}))
		local := mustLive[*nine.Verifier](t)(nine.NewVerifier(nine.VerifierConfig{Issuer: issuer, Audience: audience}))
		if hybrid.Mode() != nine.ModeHybrid {
			t.Fatal("hybrid is the default with client credentials")
		}
		claims := mustLive[nine.Claims](t)(hybrid.Verify(ctx, tokens.AccessToken, "read:things"))
		if _, err := hybrid.Verify(ctx, tokens.AccessToken, "write:things"); !errors.Is(err, nine.ErrInsufficientScope) {
			t.Fatal(err)
		}
		if err := a.Revoke(ctx, tokens.AccessToken, "access_token"); err != nil {
			t.Fatal(err)
		}
		if _, err := introspect.Verify(ctx, tokens.AccessToken); !errors.Is(err, nine.ErrInvalidToken) {
			t.Fatalf("introspect: %v", err)
		}
		if _, err := local.Verify(ctx, tokens.AccessToken); err != nil {
			t.Fatalf("local mode: valid until it expires: %v", err)
		}
		if _, err := hybrid.Verify(ctx, tokens.AccessToken); err != nil {
			t.Fatalf("hybrid: the cached answer until 9in tells us: %v", err)
		}
		if !hasSetting("RECEIVER_URL") {
			t.Skip("no receiver")
		}
		hook := waitFor(t, "webhooks", func(r webhookRecord) bool {
			if r.Type != "token.revoked" || r.Environment != "production" || r.At < start {
				return false
			}
			var e struct {
				Data map[string]any `json:"data"`
			}
			_ = json.Unmarshal([]byte(r.Raw), &e)
			return e.Data["jti"] == claims.TokenID()
		})
		// The real delivery, through WebhookHandler wired to the verifier.
		h := nine.WebhookHandler(nine.WebhookConfig{Secret: setting(t, "WEBHOOK_SECRET"), Verifier: hybrid})
		r := httptest.NewRequest(http.MethodPost, hook.Path, bytes.NewReader([]byte(hook.Raw)))
		r.Header.Set(nine.SignatureHeader, hook.Signature)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusNoContent {
			t.Fatalf("webhook: %d %s", w.Code, w.Body)
		}
		if _, err := hybrid.Verify(ctx, tokens.AccessToken); !errors.Is(err, nine.ErrInvalidToken) {
			t.Fatalf("hybrid after the webhook: %v", err)
		}
	})

	t.Run("opaque access tokens are introspected", func(t *testing.T) {
		opaque := setting(t, "OPAQUE_API_AUDIENCE")
		a := server(t, opaque, "openid", "offline_access")
		tokens := serverSignIn(t, a, newLiveBrowser())
		if !strings.HasPrefix(tokens.AccessToken, nine.OpaquePrefix) {
			t.Fatal("not opaque")
		}
		hybrid := mustLive[*nine.Verifier](t)(nine.NewVerifier(nine.VerifierConfig{Issuer: issuer, Audience: opaque, ClientID: clientID, ClientSecret: secret}))
		if c := mustLive[nine.Claims](t)(hybrid.Verify(ctx, tokens.AccessToken)); c.Subject() != user.ID {
			t.Fatal("opaque")
		}
		local := mustLive[*nine.Verifier](t)(nine.NewVerifier(nine.VerifierConfig{Issuer: issuer, Audience: opaque}))
		if _, err := local.Verify(ctx, tokens.AccessToken); !errors.Is(err, nine.ErrInvalidToken) {
			t.Fatal("local mode refuses opaque tokens")
		}
		otherAPI := mustLive[*nine.Verifier](t)(nine.NewVerifier(nine.VerifierConfig{Issuer: issuer, Audience: audience, ClientID: clientID, ClientSecret: secret}))
		if _, err := otherAPI.Verify(ctx, tokens.AccessToken); !errors.Is(err, nine.ErrInvalidToken) {
			t.Fatal("an opaque token for another API")
		}
	})

	t.Run("WebApp: sign in, protected page, API token, refresh, sign out", func(t *testing.T) {
		base := strings.TrimSuffix(redirect, "/callback")
		app := mustLive[*nine.WebApp](t)(nine.NewWebApp(nine.WebAppConfig{
			Issuer: issuer, ClientID: clientID, ClientSecret: secret, Audience: audience,
			Scopes: []string{"openid", "profile", "email", "offline_access", "read:things"},
			Secret: "go-e2e-cookie-secret-" + liveRun + "-0123456789", BaseURL: base, BasePath: "/",
			// Longer than the token's lifetime: every request refreshes (rotating the refresh token).
			RefreshLeeway: 25 * time.Hour,
		}))
		mux := http.NewServeMux()
		mux.Handle("/login", app)
		mux.Handle("/callback", app)
		mux.Handle("/logout", app)
		mux.Handle("/me", app.RequireUser(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, err := app.AccessToken(w, r)
			if err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"sub": nine.UserFrom(r.Context()).Subject, "email": nine.UserFrom(r.Context()).Email, "token": token})
		})))
		jar, _ := cookiejar.New(nil)
		do := func(method, target string) *httptest.ResponseRecorder {
			r := httptest.NewRequest(method, target, nil)
			for _, c := range jar.Cookies(r.URL) {
				r.AddCookie(c)
			}
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, r)
			jar.SetCookies(r.URL, w.Result().Cookies())
			return w
		}
		if w := do("GET", base+"/me"); w.Code != http.StatusUnauthorized {
			t.Fatalf("signed out: %d", w.Code)
		}
		login := do("GET", base+"/login?return_to=%2Fme")
		callback, page, err := newLiveBrowser().signIn(login.Header().Get("Location"), redirect, email, password)
		if err != nil || callback == "" {
			t.Fatalf("hosted sign-in: %v %s", err, page)
		}
		w := do("GET", callback)
		if w.Code != http.StatusFound || w.Header().Get("Location") != base+"/me" {
			t.Fatalf("callback: %d %s %s", w.Code, w.Header().Get("Location"), w.Body)
		}
		w = do("GET", base+"/me")
		var me map[string]string
		_ = json.Unmarshal(w.Body.Bytes(), &me)
		if w.Code != 200 || me["sub"] != user.ID || me["email"] != email {
			t.Fatalf("me: %d %s", w.Code, w.Body)
		}
		v := mustLive[*nine.Verifier](t)(nine.NewVerifier(nine.VerifierConfig{Issuer: issuer, Audience: audience}))
		if c := mustLive[nine.Claims](t)(v.Verify(ctx, me["token"], "read:things")); c.Subject() != user.ID {
			t.Fatal("API token")
		}
		// Each request refreshed and saved the rotated refresh token: the next one works too.
		first := me["token"]
		w = do("GET", base+"/me")
		_ = json.Unmarshal(w.Body.Bytes(), &me)
		if w.Code != 200 || me["token"] == first || setCookieNamed(w, "nine_session") == nil {
			t.Fatalf("refresh: %d", w.Code)
		}
		if c := mustLive[nine.Claims](t)(v.Verify(ctx, me["token"], "read:things")); c.Subject() != user.ID {
			t.Fatal("refreshed API token")
		}
		out := do("GET", base+"/logout")
		end := mustParse(out.Header().Get("Location"))
		if out.Code != http.StatusFound || end.Scheme+"://"+end.Host+end.Path != issuer+"/oauth/logout" || end.Query().Get("post_logout_redirect_uri") != base+"/" {
			t.Fatalf("logout: %d %s", out.Code, out.Header().Get("Location"))
		}
		if w := do("GET", base+"/me"); w.Code != http.StatusUnauthorized {
			t.Fatalf("after logout: %d", w.Code)
		}
	})

	t.Run("a wrong client secret is refused", func(t *testing.T) {
		wrong := mustLive[*nine.ManagementClient](t)(nine.NewManagementClient(nine.ManagementConfig{Issuer: issuer, ClientID: clientID, ClientSecret: "not-the-secret"}))
		_, err := wrong.ListUsers(ctx, nine.ListUsersOptions{})
		var e *nine.Error
		if !errors.As(err, &e) || e.Code != "invalid_client" {
			t.Fatalf("management: %v", err)
		}
		cc := mustLive[*nine.ClientCredentials](t)(nine.NewClientCredentials(nine.ClientCredentialsConfig{Issuer: issuer, ClientID: clientID, ClientSecret: "not-the-secret"}))
		if _, err := cc.Token(ctx); !errors.As(err, &e) || e.Code != "invalid_client" {
			t.Fatalf("client credentials: %v", err)
		}
	})
}

func setCookieNamed(w *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range w.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func errorStatus(err error) int {
	var e *nine.Error
	if errors.As(err, &e) {
		return e.Status
	}
	return 0
}
