package cmd

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/oauth2"

	"github.com/chet-wynn-cookieai/oauth2client/internal/termcolor"
)

const (
	authorizeUrl = "/oauth/authorize"
	tokenUrl     = "/oauth/token"
	userInfoUrl  = "/oauth/userinfo"
	testUrl      = "/api/private/system"

	defaultTenantUrl = "https://tenant1.cookieai.test:8081"
)

func init() {
	RootCmd.AddCommand(startCmd)

	// Tenant configuration
	startCmd.Flags().String("tenant", defaultTenantUrl, "Tenant URL for cp-api; defaults to https://tenant1.cookieai.test:8081")

	// OAuth2 client credentials
	startCmd.Flags().String("client-id", "", "OAuth2 client ID (required)")
	startCmd.Flags().String("client-secret", "", "OAuth2 client secret (required)")

	// OAuth2 parameters
	startCmd.Flags().String("redirect_uri", "http://localhost:18181/callback", "OAuth2 redirect URI")
	startCmd.Flags().String("scope", "demo:write", "OAuth2 scope")
}

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Test OAuth2 authorization code flow with tenant",
	Example: `
GENERAL PURPOSE:

oauth2client start \
    --client-id "your-client-id" \
    --client-secret "your-client-secret" \
    --tenant "https://tenant1.cookieai.test:8081" \
    --scope "demo:write"

TENANT1:

oauth2client start \
    --client-id "your-client-id" \
    --client-secret "your-client-secret" \
    --scope "demo:write"
`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()

		// Get parameters from command line
		tenant := mustGetString(cmd, "tenant")
		clientID := mustGetString(cmd, "client-id")
		if clientID == "" {
			return errors.New("missing client-id")
		}
		clientSecret := mustGetString(cmd, "client-secret")
		if clientSecret == "" {
			return errors.New("missing client-secret")
		}
		redirectURI := mustGetString(cmd, "redirect_uri")
		scope := mustGetString(cmd, "scope")

		log.Printf("%s", termcolor.Cyan("🚀 Starting OAuth2 client test"))
		log.Printf("📍 Tenant: %s", termcolor.Blue(tenant))
		log.Printf("🔑 Client ID: %s", termcolor.Blue(clientID))
		log.Printf("🔗 Redirect URI: %s", termcolor.Blue(redirectURI))
		log.Printf("🎯 Scope: %s", termcolor.Blue(scope))

		// Create and authenticate client
		client, err := New(ctx, tenant, clientID, clientSecret, redirectURI, scope)
		if err != nil {
			return errors.Wrap(err, "failed to create and authenticate OAuth2 client")
		}

		log.Println(termcolor.Magenta("=== Testing UserInfo endpoint ==="))
		if err := client.UserInfo(); err != nil {
			log.Printf("%s UserInfo test failed: %v", termcolor.Red("❌"), err)
		} else {
			log.Printf("%s UserInfo test passed", termcolor.Green("✅"))
		}

		log.Println(termcolor.Magenta("=== Testing Users:Me endpoint ==="))
		if err := client.System(); err != nil {
			log.Printf("%s Users:Me test failed: %v", termcolor.Red("❌"), err)
		} else {
			log.Printf("%s Users:Me test passed", termcolor.Green("✅"))
		}

		log.Println(termcolor.Green("🎉 OAuth2 client test completed successfully"))
		return nil
	},
}

func mustGetString(cmd *cobra.Command, name string) string {
	value, err := cmd.Flags().GetString(name)
	if err != nil {
		panic(err)
	}
	return value
}

func New(ctx context.Context, tenant string, id string, secret string, redirectURI string, scope string) (*MyClient, error) {
	client := &MyClient{
		tenant:       tenant,
		clientID:     id,
		clientSecret: secret,
		config: &oauth2.Config{
			ClientID:     id,
			ClientSecret: secret,
			Endpoint: oauth2.Endpoint{
				AuthURL:   tenant + authorizeUrl,
				TokenURL:  tenant + tokenUrl,
				AuthStyle: oauth2.AuthStyleInParams,
			},
			RedirectURL: redirectURI,
			Scopes:      []string{scope},
		},
		refreshToken: "",
		token:        nil,
	}

	err := client.Authenticate(ctx)
	if err != nil {
		return nil, err
	}

	return client, nil
}

type MyClient struct {
	hc *http.Client

	tenant       string
	clientID     string
	clientSecret string
	config       *oauth2.Config

	refreshToken string
	token        *oauth2.Token
}

func (r *MyClient) Authenticate(ctx context.Context) error {
	state := uuid.NewString()

	// use PKCE to protect against CSRF attacks
	// https://www.ietf.org/archive/id/draft-ietf-oauth-security-topics-22.html#name-countermeasures-6
	verifier := oauth2.GenerateVerifier()

	// Redirect user to consent page to ask for permission
	// for the scopes specified above.
	authURL := r.config.AuthCodeURL(state, oauth2.AccessTypeOffline, oauth2.S256ChallengeOption(verifier))

	log.Println(termcolor.Yellow("🔐 Please open the following URL in your browser to authorize:"))
	fmt.Println()
	fmt.Println(termcolor.Cyan(authURL)) // no logger decorations
	fmt.Println()
	log.Printf("%s", termcolor.Yellow("⏳ Waiting for authorization callback..."))

	code, err := r.startCallbackServer(ctx)
	if err != nil {
		return errors.Wrap(err, "failed to get authorization code")
	}

	log.Printf("%s Authorization code received", termcolor.Green("✅"))

	token, err := r.config.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return errors.Wrap(err, "failed to exchange code for token")
	}

	r.token = token
	r.hc = r.config.Client(ctx, token)

	log.Println(termcolor.Green("🔑 Token Details:"))
	log.Printf("  Access Token: %s", termcolor.Blue(token.AccessToken))
	if token.RefreshToken != "" {
		log.Printf("  Refresh Token: %s", termcolor.Blue(token.RefreshToken))
	}
	log.Printf("  Expiry: %s", termcolor.Blue(token.Expiry))
	if scope := token.Extra("scope"); scope != nil {
		log.Printf("  Scopes: %s", termcolor.Blue(scope))
	}
	if idToken := token.Extra("id_token"); idToken != nil {
		log.Printf("  ID Token: %s", termcolor.Blue("present"))
	}
	log.Printf("  Token Type: %s", termcolor.Blue(token.TokenType))

	log.Println(termcolor.Green("🎯 Authentication successful!"))
	return nil
}

func (r *MyClient) startCallbackServer(ctx context.Context) (string, error) {
	codeCh := make(chan string, 1)
	errCh := make(chan error, 1)

	server := &http.Server{Addr: ":18181"}

	http.HandleFunc("/callback", func(w http.ResponseWriter, req *http.Request) {
		code := req.URL.Query().Get("code")
		if code == "" {
			errMsg := req.URL.Query().Get("error")
			if errMsg == "" {
				errMsg = "no authorization code received"
			}
			errCh <- errors.New("authorization failed: " + errMsg)
			if _, err := fmt.Fprintf(w, "Authorization failed: %s", errMsg); err != nil {
				log.Errorf("Failed to write error message to browser: %v", err)
			}
			return
		}

		codeCh <- code
		if _, err := fmt.Fprintf(w, "✅ Authorization successful! You can close this window."); err != nil {
			log.Errorf("Failed to write error message to browser: %v", err)
		}
	})

	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- errors.Wrap(err, "callback server failed")
		}
	}()

	select {
	case code := <-codeCh:
		if err := server.Shutdown(ctx); err != nil {
			return "", errors.Wrap(err, "failed to shutdown callback server")
		}
		wg.Wait()
		return code, nil
	case err := <-errCh:
		if err := server.Shutdown(ctx); err != nil {
			return "", errors.Wrap(err, "failed to shutdown callback server")
		}
		wg.Wait()
		return "", err
	case <-ctx.Done():
		if err := server.Shutdown(ctx); err != nil {
			return "", errors.Wrap(err, "failed to shutdown callback server")
		}
		wg.Wait()
		return "", ctx.Err()
	}
}

func (r *MyClient) UserInfo() error {
	if r.hc == nil {
		return errors.New("client not authenticated")
	}

	resp, err := r.hc.Get(r.tenant + userInfoUrl)
	if err != nil {
		return errors.Wrap(err, "failed to get user info")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return errors.New(fmt.Sprintf("user info request failed with status %d: %s", resp.StatusCode, string(body)))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return errors.Wrap(err, "failed to read user info response")
	}

	log.Printf("%s %s", termcolor.Green("📋 User Info Response:"), termcolor.Cyan(strings.TrimSpace(string(body))))
	return nil
}

func (r *MyClient) System() error {
	if r.hc == nil {
		return errors.New("client not authenticated")
	}

	resp, err := r.hc.Get(r.tenant + testUrl)
	if err != nil {
		return errors.Wrap(err, "failed to get system")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return errors.New(fmt.Sprintf("system request failed with status %d: %s", resp.StatusCode, string(body)))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return errors.Wrap(err, "failed to read system response")
	}

	log.Printf("%s %s", termcolor.Green("👤 System Response:"), termcolor.Cyan(string(body)))
	return nil
}
