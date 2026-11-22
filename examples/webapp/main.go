// Command webapp is a server-rendered web app that signs users in with 9in.
//
//	NINE_ISSUER=https://acme.9in.io NINE_CLIENT_ID=app_… NINE_CLIENT_SECRET=… \
//	NINE_SECRET="$(openssl rand -base64 32)" NINE_BASE_URL=http://localhost:3000 \
//	go run ./examples/webapp
//
// Register NINE_BASE_URL + "/nine/callback" as a callback URL of the application and
// NINE_BASE_URL + "/" as a logout URL. Optional: NINE_AUDIENCE (an API to get access
// tokens for), NINE_BASE_PATH (default /nine), ADDR (default 127.0.0.1:3000).
package main

import (
	"errors"
	"html/template"
	"log"
	"net/http"
	"os"
	"strconv"

	nine "github.com/9in-io/go-sdk"
)

var page = template.Must(template.New("page").Parse(`<!doctype html>
<meta charset="utf-8"><title>9in Go example</title>
<style>body{font-family:system-ui;max-width:40rem;margin:3rem auto;padding:0 1rem}</style>
<h1>9in Go example</h1>
{{if .User}}
  <p>Signed in as <strong>{{.User.Name}}</strong> ({{.User.Email}}).</p>
  <p><a href="/dashboard">Dashboard</a> · <a href="{{.Base}}/logout">Sign out</a></p>
{{else}}
  <p>You are signed out.</p>
  <p><a href="{{.Base}}/login?return_to=/dashboard">Sign in</a> · <a href="{{.Base}}/signup">Create an account</a></p>
{{end}}
{{if .Claims}}<h2>Your claims</h2><pre>{{range $k, $v := .Claims}}{{$k}}: {{$v}}
{{end}}</pre>{{end}}
{{if .TokenNote}}<p>{{.TokenNote}}</p>{{end}}`))

func main() {
	cfg := nine.WebAppConfigFromEnv()
	if p := os.Getenv("NINE_BASE_PATH"); p != "" {
		cfg.BasePath = p
	}
	app, err := nine.NewWebApp(cfg)
	if err != nil {
		log.Fatal(err)
	}
	base := cfg.BasePath
	if base == "" {
		base = "/nine"
	}
	if base == "/" {
		base = ""
	}

	mux := http.NewServeMux()
	// The sign-in routes: <base>/login, /signup, /callback and /logout.
	for _, route := range []string{"/login", "/signup", "/callback", "/logout"} {
		mux.Handle(base+route, app)
	}

	// A page anyone can see; it knows who is signed in.
	mux.Handle("/{$}", app.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		render(w, map[string]any{"User": nine.UserFrom(r.Context()), "Base": base})
	})))

	// A page for signed-in users only: others are sent to sign in and brought back.
	mux.Handle("/dashboard", app.RequireUser(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := nine.UserFrom(r.Context())
		note := ""
		// A valid access token for your API (refreshed and rotated when needed).
		if token, err := app.AccessToken(w, r); err != nil {
			note = "No access token: " + err.Error()
		} else {
			note = "Access token ready for your API (" + strconv.Itoa(len(token)) + " characters)."
		}
		render(w, map[string]any{"User": user, "Base": base, "Claims": user.Claims, "TokenNote": note})
	})))

	addr := os.Getenv("ADDR")
	if addr == "" {
		addr = "127.0.0.1:3000"
	}
	log.Printf("listening on http://%s", addr)
	server := &http.Server{Addr: addr, Handler: mux}
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

func render(w http.ResponseWriter, data map[string]any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := page.Execute(w, data); err != nil {
		log.Print(err)
	}
}
