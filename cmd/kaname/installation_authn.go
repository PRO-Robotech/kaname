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
	c, key, err := loadInstallationCredential(cfg.Installation.CredentialFile)
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

// Authenticate renews from the same standing key on every pair. Only the normal
// presented-credential reader can put the verified token's principal in context.
func (a *installationAuthentication) Authenticate(ctx context.Context) (context.Context, error) {
	parent := ctx
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	client, err := a.resolver.ResolveAssertionClient(ctx, a.credential.ClientID)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "unauthenticated")
	}
	if client.Kind != domain.AssertionClientServiceAccount {
		return nil, status.Error(codes.Unauthenticated, "unauthenticated")
	}
	now := time.Now().UTC()
	end := now.Add(min(60*time.Second, tokenpolicy.MaxAssertionLifetime))
	if client.ExpiresAt > 0 && time.Unix(client.ExpiresAt, 0).Before(end) {
		end = time.Unix(client.ExpiresAt, 0)
	}
	if !end.After(now) {
		return nil, status.Error(codes.Unauthenticated, "unauthenticated")
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	assertion := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.RegisteredClaims{
		Issuer: a.credential.ClientID, Subject: a.credential.ClientID, Audience: jwt.ClaimStrings{a.assertionAudience},
		IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(end), ID: hex.EncodeToString(nonce[:]),
	})
	assertion.Header["typ"] = tokenpolicy.TokenTypeClientAssertion
	assertion.Header["kid"] = a.credential.KeyID
	raw, err := assertion.SignedString(a.key)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "unauthenticated")
	}
	verified, err := a.verifier.Verify(ctx, tokenpolicy.ClientAssertionType, raw)
	if err != nil {
		return nil, installationProofFailure(verified.Outcome)
	}
	token, outcome, err := a.issuer.Issue(ctx, client_token.Input{Client: verified.Client, RequestedAudience: []string{a.audience}})
	if err != nil {
		return nil, installationProofFailure(outcome)
	}
	// Preserve the caller's cancellation lifetime after the bounded authn call.
	var authenticated context.Context
	incoming := metadata.NewIncomingContext(ctx, metadata.Pairs(presentedcred.MetadataKey, "Bearer "+token.AccessToken))
	_, err = a.reader.UnaryOver(nil)(incoming, nil, &grpc.UnaryServerInfo{FullMethod: "/kaname.cloud.iam.v1.GrantDelegationService/Create"}, func(c context.Context, _ any) (any, error) {
		p, ok := operations.PrincipalFromContextOK(c)
		if !ok || p.Type != "service_account" || p.ID != verified.Client.OwnerID {
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
