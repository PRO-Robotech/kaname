// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/corelib/tokenpolicy"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/client_token"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/signingkeys"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/PRO-Robotech/kaname/internal/clientassertion"
	"github.com/PRO-Robotech/kaname/internal/clienttokenwire"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/presentedcred"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/tokensigner"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type installationCredential struct {
	ClientID      string `json:"clientId"`
	KeyID         string `json:"keyId"`
	PrivateKeyPEM string `json:"privateKeyPem"`
}

type installationAuthentication struct {
	gateOnce          sync.Once
	gate              chan struct{}
	accessToken       string
	accessOwner       string
	accessExpires     time.Time
	credential        installationCredential
	key               *ecdsa.PrivateKey
	resolver          clientassertion.ClientResolver
	verifier          *clientassertion.Verifier
	issuer            *client_token.UseCase
	reader            *presentedcred.Reader
	audience          string
	assertionAudience string
}

func preparePresentedReader(pool *pgxpool.Pool, cfg config.Config, keys *signingkeys.Keystore, logger *slog.Logger) (*presentedcred.Reader, error) {
	if !cfg.AuthN.PresentedCredential.Enabled {
		return nil, nil
	}
	basic, err := newBasicCredentialAuthority(pool)
	if err != nil {
		return nil, err
	}
	if keys == nil {
		return nil, fmt.Errorf("presented credentials require signing keys")
	}
	return presentedcred.New(presentedcred.Config{
		BasicCredentials: basic, Issuer: cfg.AuthN.TokenSigning.Issuer,
		Audience:          cfg.AuthN.PresentedCredential.Audience,
		AllowedAlgorithms: cfg.AuthN.TokenSigning.AllowedAlgorithmList(), Keys: keys,
		Revocations:        kanamepg.NewMintedTokenRevocationRepo(pool),
		RevocationCacheTTL: cfg.AuthN.PresentedCredential.RevocationCacheTTL,
		Logger:             logger.With(slog.String("component", "presented_credential")), TrustDomain: cfg.AuthN.TrustDomain(),
	})
}

func loadInstallationCredential(path string) (installationCredential, *ecdsa.PrivateKey, error) {
	f, err := os.Open(path)
	if err != nil {
		return installationCredential{}, nil, fmt.Errorf("installation credential file cannot be opened")
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || st.Size() > 65536 {
		return installationCredential{}, nil, fmt.Errorf("installation credential requires a private regular file of at most 65536 bytes")
	}
	var c installationCredential
	dec := json.NewDecoder(io.LimitReader(f, 65537))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return installationCredential{}, nil, fmt.Errorf("installation credential has invalid shape")
	}
	if dec.Decode(new(any)) != io.EOF || c.ClientID == "" || c.KeyID == "" || c.PrivateKeyPEM == "" {
		return installationCredential{}, nil, fmt.Errorf("installation credential is incomplete")
	}
	key, err := jwt.ParseECPrivateKeyFromPEM([]byte(c.PrivateKeyPEM))
	if err != nil || key.Curve.Params().BitSize != 256 {
		return installationCredential{}, nil, fmt.Errorf("installation credential requires an ES256 private key")
	}

	return c, key, nil
}

func prepareInstallationAuthentication(pool *pgxpool.Pool, cfg config.Config, signer *tokensigner.Signer, reader *presentedcred.Reader, logger *slog.Logger) (*installationAuthentication, error) {
	if signer == nil || reader == nil || !cfg.AuthN.ClientToken.Enabled {
		return nil, fmt.Errorf("installation credential requires shared token issuance and presented credential verification")
	}
	c, key, err := loadInstallationCredential(cfg.ModuleSeedInstaller.CredentialFile)
	if err != nil {
		return nil, err
	}
	bc := clientTokenBuildConfig(cfg, signer.Issuer(), logger, nil, func(*http.Request) string { return "installation" })
	resolver := clienttokenwire.WithDeadlineResolver(kanamepg.NewAssertionClientRepo(pool), credentialLanePeerTimeout)
	verifier, issuer, err := clienttokenwire.Prepare(bc, kanamepg.NewAssertionClientRepo(pool), kanamepg.NewTrustedIssuerRepo(pool), kanamepg.NewClientAssertionReplayRepo(pool), signer, newAssertionClaimsComposer(pool, cfg), kanamepg.NewSessionRevocationsAdapter(pool))
	if err != nil {
		return nil, err
	}
	return &installationAuthentication{credential: c, key: key, resolver: resolver, verifier: verifier, issuer: issuer, reader: reader, audience: cfg.AuthN.PresentedCredential.Audience, assertionAudience: signer.Issuer()}, nil
}

// Authenticate reuses an actual issued access token, checking it through the
// normal presented reader every time. Authority is independently checked per pair.
func (a *installationAuthentication) Authenticate(parent context.Context) (context.Context, error) {
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	a.gateOnce.Do(func() { a.gate = make(chan struct{}, 1) })
	select {
	case a.gate <- struct{}{}:
	case <-ctx.Done():
		return nil, status.FromContextError(ctx.Err()).Err()
	}
	defer func() { <-a.gate }()
	if a.accessToken == "" || !time.Now().Before(a.accessExpires) {
		token, owner, err := a.exchange(ctx)
		if err != nil {
			return nil, err
		}
		a.accessToken = token.AccessToken
		a.accessOwner = owner
		// Renew conservatively before the numeric-date rounding boundary; acceptance
		// and revocation of each presentation still belong to the ordinary reader.
		a.accessExpires = time.Now().Add(time.Duration(max(0, token.ExpiresIn-1)) * time.Second)
	}
	var authenticated context.Context
	incoming := metadata.NewIncomingContext(ctx, metadata.Pairs(presentedcred.MetadataKey, "Bearer "+a.accessToken))
	_, err := a.reader.UnaryOver(nil)(incoming, nil, &grpc.UnaryServerInfo{FullMethod: "/kaname.cloud.iam.v1.GrantDelegationService/Create"}, func(c context.Context, _ any) (any, error) {
		p, ok := operations.PrincipalFromContextOK(c)
		if !ok || p.Type != "service_account" || p.ID != a.accessOwner {
			return nil, status.Error(codes.Unauthenticated, "unauthenticated")
		}
		authenticated = installationVerifiedContext{Context: parent, values: c}
		return nil, nil
	})
	if err != nil {
		return nil, err
	}
	return authenticated, nil
}

func (a *installationAuthentication) exchange(ctx context.Context) (client_token.Output, string, error) {
	for {
		client, outcome, err := clientassertion.ResolveRegisteredClient(ctx, a.resolver, a.credential.ClientID)
		if err != nil {
			return client_token.Output{}, "", installationProofFailure(outcome)
		}
		if client.Kind != domain.AssertionClientServiceAccount {
			return client_token.Output{}, "", installationProofFailure(clientassertion.OutcomeClientUnknown)
		}
		raw, err := a.freshAssertion(client)
		if err != nil {
			return client_token.Output{}, "", err
		}
		verified, err := a.verifier.Verify(ctx, tokenpolicy.ClientAssertionType, raw)
		if err != nil {
			if verified.Outcome == clientassertion.OutcomeClientPaceExceeded {
				if err := waitInstallationExchange(ctx, verified.RetryAfter); err != nil {
					return client_token.Output{}, "", err
				}
				continue // Fresh lookup, assertion and jti; never retry a consumed proof.
			}
			return client_token.Output{}, "", installationProofFailure(verified.Outcome)
		}
		token, outcome, err := a.issuer.Issue(ctx, client_token.Input{Client: verified.Client, RequestedAudience: []string{a.audience}})
		if err != nil {
			return client_token.Output{}, "", installationProofFailure(outcome)
		}
		return token, verified.Client.OwnerID, nil
	}
}

func waitInstallationExchange(ctx context.Context, retryAfter time.Duration) error {
	if retryAfter <= 0 {
		return status.Error(codes.ResourceExhausted, "client exchange pace exceeded")
	}
	timer := time.NewTimer(retryAfter)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return status.FromContextError(ctx.Err()).Err()
	case <-timer.C:
		return nil
	}
}

func (a *installationAuthentication) freshAssertion(client domain.AssertionClient) (string, error) {
	now := time.Now().UTC()
	end := now.Add(min(60*time.Second, tokenpolicy.MaxAssertionLifetime))
	if client.ExpiresAt > 0 && time.Unix(client.ExpiresAt, 0).Before(end) {
		end = time.Unix(client.ExpiresAt, 0)
	}
	if !end.After(now) {
		return "", status.Error(codes.Unauthenticated, "unauthenticated")
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}
	assertion := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.RegisteredClaims{
		Issuer: a.credential.ClientID, Subject: a.credential.ClientID, Audience: jwt.ClaimStrings{a.assertionAudience},
		IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(end), ID: hex.EncodeToString(nonce[:]),
	})
	assertion.Header["typ"] = tokenpolicy.TokenTypeClientAssertion
	assertion.Header["kid"] = a.credential.KeyID
	raw, err := assertion.SignedString(a.key)
	if err != nil {
		return "", status.Error(codes.Unauthenticated, "unauthenticated")
	}
	return raw, nil
}

type installationVerifiedContext struct {
	context.Context
	values context.Context
}

func (c installationVerifiedContext) Value(key any) any { return c.values.Value(key) }

func installationProofFailure(outcome clientassertion.Outcome) error {
	if clientassertion.OurSide(outcome) {
		return status.Error(codes.Unavailable, "authentication backend unavailable")
	}
	return status.Error(codes.Unauthenticated, "unauthenticated")
}
