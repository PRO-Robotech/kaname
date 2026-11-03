// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package installruntime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/PRO-Robotech/corelib/tokenpolicy"
	"github.com/golang-jwt/jwt/v5"
)

// StandingToken is observed only after the exact issued credential succeeds at
// the ordinary presented-credential /me endpoint. Claims are not an authenticator.
type StandingToken struct {
	Bearer              string
	Assertion           string
	AssertionJTI        string
	JTI                 string
	IssuedAt, ExpiresAt time.Time
}

func (w *Wire) ExchangeStandingCreator(ctx context.Context, c *StandingCreator, issuer, audience string) (StandingToken, error) {
	var observed StandingToken
	key, err := jwt.ParseECPrivateKeyFromPEM([]byte(c.privateKey))
	if err != nil {
		return observed, errors.New("standing assertion key is not ES256")
	}
	jti, err := randomURLToken()
	if err != nil {
		return observed, err
	}
	now := time.Now().UTC().Truncate(time.Second)
	lifetime := 60 * time.Second
	if tokenpolicy.MaxAssertionLifetime < lifetime {
		lifetime = tokenpolicy.MaxAssertionLifetime
	}
	end := now.Add(lifetime)
	if c.ExpiresAt.IsZero() {
		return observed, errors.New("observed real key expiry is required")
	}
	if c.ExpiresAt.Before(end) {
		end = c.ExpiresAt
	}
	if !end.After(now) {
		return observed, errors.New("standing key already expired")
	}
	assertion := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.RegisteredClaims{
		Issuer: c.ClientID, Subject: c.ClientID, Audience: jwt.ClaimStrings{issuer}, ID: jti,
		IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(end),
	})
	assertion.Header["typ"] = tokenpolicy.TokenTypeClientAssertion
	assertion.Header["kid"] = c.KeyID
	proof, err := assertion.SignedString(key)
	if err != nil {
		return observed, errors.New("cannot sign standing assertion")
	}
	form := url.Values{"grant_type": {"client_credentials"}, "client_assertion_type": {tokenpolicy.ClientAssertionType}, "client_assertion": {proof}, "audience": {audience}}
	code, _, raw, err := w.request(ctx, http.MethodPost, w.IssuanceURL+"/iam/v1/token", http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}, []byte(form.Encode()))
	if err != nil {
		return observed, err
	}
	var token struct {
		AccessToken string `json:"access_token"`
	}
	if code != http.StatusOK || json.Unmarshal(raw, &token) != nil || token.AccessToken == "" {
		return observed, fmt.Errorf("standing exchange returned HTTP %d or no token", code)
	}
	var me struct{ Subject string }
	code, err = w.JSON(ctx, http.MethodGet, "/iam/v1/me", token.AccessToken, nil, &me)
	if err != nil {
		return observed, err
	}
	if code != http.StatusOK || me.Subject != "service_account:"+c.ID {
		return observed, errors.New("ordinary presented reader rejected standing creator identity")
	}
	claims := jwt.MapClaims{}
	_, _, err = new(jwt.Parser).ParseUnverified(token.AccessToken, claims)
	if err != nil {
		return observed, errors.New("accepted standing token has unreadable claims")
	}
	issued, err := claims.GetIssuedAt()
	if err != nil || issued == nil {
		return observed, errors.New("accepted token lacks issuedAt")
	}
	expires, err := claims.GetExpirationTime()
	if err != nil || expires == nil {
		return observed, errors.New("accepted token lacks expiresAt")
	}
	tokenID, ok := claims["jti"].(string)
	if !ok || tokenID == "" {
		return observed, errors.New("accepted token lacks JTI")
	}
	return StandingToken{Assertion: proof, AssertionJTI: jti, Bearer: token.AccessToken, JTI: tokenID, IssuedAt: issued.Time, ExpiresAt: expires.Time}, nil
}
