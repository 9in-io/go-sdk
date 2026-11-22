// Command device signs in from a terminal with the device flow (RFC 8628).
//
//	NINE_ISSUER=https://acme.9in.io NINE_CLIENT_ID=app_tv… go run ./examples/device
//
// The application must be a "TV & Device" application (Applications → Create
// application → TV & Device). Optional: NINE_AUDIENCE, to get an access token for an API.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"

	nine "github.com/9in-io/go-sdk"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	device, err := nine.NewDeviceAuth(nine.DeviceAuthConfig{
		Issuer:   nine.Env("ISSUER"),
		ClientID: nine.Env("CLIENT_ID"),
		Audience: nine.Env("AUDIENCE"),
	})
	if err != nil {
		log.Fatal(err)
	}
	code, err := device.Start(ctx)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("To sign in, open %s and enter the code %s\n", code.VerificationURI, code.UserCode)
	if code.VerificationURIComplete != "" {
		fmt.Printf("(or open %s)\n", code.VerificationURIComplete)
	}

	tokens, err := device.Wait(ctx, code)
	switch {
	case errors.Is(err, nine.ErrAccessDenied):
		log.Fatal("you declined the sign-in")
	case errors.Is(err, nine.ErrExpiredToken):
		log.Fatal("the code expired; run the command again")
	case err != nil:
		log.Fatal(err)
	}
	fmt.Printf("Signed in as %s (%s)\n", tokens.Claims.String("name"), tokens.Claims.Subject())

	// Keep tokens.RefreshToken somewhere safe; later:
	//   tokens, err = device.EnsureFresh(ctx, tokens, time.Minute)
	info, err := device.UserInfo(ctx, tokens.AccessToken)
	if err == nil {
		fmt.Printf("userinfo: %v\n", map[string]any(info))
	}
}
