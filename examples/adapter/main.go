// Command adapter keeps users in your own database: it serves the adapter protocol
// endpoints 9in calls (…/authenticate, …/user, …/event) over an in-memory user list.
//
//	NINE_ADAPTER_SECRET=… go run ./examples/adapter
//
// In the console, add a user database connection pointing at https://<this host>/nine
// with the same secret. The demo users are jane@example.com and the blocked
// bob@example.com, both with the password "correct horse battery staple".
package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"

	nine "github.com/9in-io/go-sdk"
)

type user struct {
	id, email, name string
	passwordHash    [32]byte // a real app stores bcrypt or argon2 hashes
	blocked         bool
}

// users is the database: replace it with yours.
type users struct {
	mu   sync.Mutex
	list []user
}

func (u *users) byIdentifier(id nine.Identifier) *user {
	u.mu.Lock()
	defer u.mu.Unlock()
	for i := range u.list {
		if id.Type == "email" && strings.EqualFold(u.list[i].email, id.Value) {
			return &u.list[i]
		}
	}
	return nil
}

func (u *users) byID(id string) *user {
	u.mu.Lock()
	defer u.mu.Unlock()
	for i := range u.list {
		if u.list[i].id == id {
			return &u.list[i]
		}
	}
	return nil
}

func toAdapterUser(x *user) *nine.AdapterUser {
	return &nine.AdapterUser{ID: x.id, Email: x.email, EmailVerified: true, Name: x.name, Blocked: x.blocked}
}

// Authenticate checks a password: the user, ErrInvalidCredentials or ErrUserBlocked.
func (u *users) Authenticate(_ context.Context, id nine.Identifier, password string) (*nine.AdapterUser, error) {
	found := u.byIdentifier(id)
	hash := sha256.Sum256([]byte(password))
	if found == nil || subtle.ConstantTimeCompare(hash[:], found.passwordHash[:]) != 1 {
		return nil, nine.ErrInvalidCredentials
	}
	if found.blocked {
		return nil, nine.ErrUserBlocked
	}
	return toAdapterUser(found), nil
}

// FindUser looks a user up by id or identifier; nil when there is none.
func (u *users) FindUser(_ context.Context, q nine.UserQuery) (*nine.AdapterUser, error) {
	var found *user
	if q.ID != "" {
		found = u.byID(q.ID)
	} else if q.Identifier != nil {
		found = u.byIdentifier(*q.Identifier)
	}
	if found == nil {
		return nil, nil
	}
	return toAdapterUser(found), nil
}

// OnEvent receives notifications; otp.requested means: deliver this one-time code.
func (u *users) OnEvent(_ context.Context, e *nine.AdapterEvent) error {
	switch e.EventType {
	case "otp.requested":
		log.Printf("one-time code for user %s by %v (deliver it with your mailer or SMS provider)", e.UserID(), e.Data["channel"])
	default:
		log.Printf("event %s for user %s", e.EventType, e.UserID())
	}
	return nil
}

func main() {
	secret := nine.Env("ADAPTER_SECRET")
	if secret == "" {
		log.Fatal("set NINE_ADAPTER_SECRET")
	}
	demo := sha256.Sum256([]byte("correct horse battery staple"))
	db := &users{list: []user{
		{id: "1", email: "jane@example.com", name: "Jane Doe", passwordHash: demo},
		{id: "2", email: "bob@example.com", name: "Bob Blocked", passwordHash: demo, blocked: true},
	}}

	mux := http.NewServeMux()
	mux.Handle("/nine/", nine.AdapterHandler(nine.AdapterConfig{
		Secret:  secret,
		Adapter: db,
		OnError: func(r *http.Request, err error) { log.Printf("adapter error: %v", err) },
	}))

	addr := os.Getenv("ADDR")
	if addr == "" {
		addr = "127.0.0.1:5000"
	}
	log.Printf("adapter listening on http://%s/nine", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}
