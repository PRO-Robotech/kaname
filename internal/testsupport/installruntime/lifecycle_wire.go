// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package installruntime

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/PRO-Robotech/corelib/tokenpolicy"
	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"gopkg.in/yaml.v3"
)

// Существующий конечный сертификат стенда записи модуля; без передаваемых идентичности или метаданных пользователя.
// Настоящий состав модулей сервера и политика RegisterResource определяют полномочия.
func (w *Wire) ModuleWriter(pki string) (*grpc.ClientConn, error) {
	leaf, err := tls.LoadX509KeyPair(filepath.Join(pki, "registry.crt"), filepath.Join(pki, "registry.key"))
	if err != nil {
		return nil, errors.New("existing module writer leaf unavailable")
	}
	cfg := w.publicTLS.Clone()
	cfg.Certificates = []tls.Certificate{leaf}
	return grpc.NewClient(w.InternalGatewayAddress(), grpc.WithTransportCredentials(credentials.NewTLS(cfg)))
}

// Выдаём штатный ключ для уже созданной SA. Неявного GrantAdmin нет.
func (w *Wire) IssueStandingKey(ctx context.Context, o *VerifiedOperator, id, account, path string, observe func(string)) (*StandingCreator, error) {
	if observe == nil {
		return nil, errors.New("private secret observer required")
	}
	op, err := w.createOperation(ctx, o, "/iam/v1/serviceAccounts/"+url.PathEscape(id)+"/keys", map[string]any{"credentialKind": "CREDENTIAL_KIND_KEYPAIR", "ttlSeconds": 7200, "description": "Generic RID lifecycle key"})
	if err != nil {
		return nil, err
	}
	var issued struct {
		ClientID      string `json:"clientId"`
		KeyID         string `json:"keyId"`
		PrivateKeyPEM string `json:"privateKeyPem"`
		Algorithm     string `json:"algorithm"`
	}
	decodeErr := json.Unmarshal(op.Response, &issued)
	observe(issued.PrivateKeyPEM)
	if decodeErr != nil || issued.ClientID == "" || issued.KeyID == "" || issued.PrivateKeyPEM == "" || issued.Algorithm != "ES256" {
		return nil, errors.New("ordinary Issue returned incomplete key")
	}
	c := &StandingCreator{ID: id, AccountID: account, ClientID: issued.ClientID, KeyID: issued.KeyID, privateKey: issued.PrivateKeyPEM, CredentialFile: path, KeyOperation: op}
	// Обходим страницы штатного API ключей; запрошенный постоянный срок никогда
	// не используется вымышленной датой истечения.
	seen := map[string]bool{}
	token := ""
	for {
		if seen[token] {
			return nil, errors.New("key page token repeated")
		}
		seen[token] = true
		var page struct {
			Keys []struct {
				ID        string    `json:"id"`
				ExpiresAt time.Time `json:"expiresAt"`
			}
			Next string `json:"nextPageToken"`
		}
		code, err := w.JSON(ctx, http.MethodGet, "/iam/v1/serviceAccounts/"+id+"/keys?"+url.Values{"pageSize": {"2"}, "pageToken": {token}}.Encode(), o.Bearer(), nil, &page)
		if err != nil {
			return nil, err
		}
		if code != 200 {
			return nil, errors.New("normal key List refused")
		}
		for _, k := range page.Keys {
			if k.ID == c.KeyID {
				c.ExpiresAt = k.ExpiresAt
			}
		}
		token = page.Next
		if token == "" {
			break
		}
	}
	if c.ExpiresAt.IsZero() {
		return nil, errors.New("issued key absent from complete public census")
	}
	material, err := json.Marshal(map[string]string{"clientId": c.ClientID, "keyId": c.KeyID, "privateKeyPem": c.privateKey})
	if err != nil {
		return nil, err
	}
	observe(string(material))
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	_, writeErr := file.Write(material)
	closeErr := file.Close()
	if writeErr != nil {
		return nil, writeErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	return c, nil
}

// Проверяем штатную конечную точку токенов со СТАРЫМ точным постоянным ключом после
// штатного отзыва/удаления. Возвращаем безопасную классификацию OAuth, не текст ответа.
func (w *Wire) StandingKeyRefusal(ctx context.Context, c *StandingCreator, issuer, audience string) (int, string, string, error) {
	key, err := jwt.ParseECPrivateKeyFromPEM([]byte(c.privateKey))
	if err != nil {
		return 0, "", "", errors.New("standing key parse failed")
	}
	jti, err := randomURLToken()
	if err != nil {
		return 0, "", "", err
	}
	now := time.Now().UTC().Truncate(time.Second)
	assertion := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.RegisteredClaims{Issuer: c.ClientID, Subject: c.ClientID, Audience: jwt.ClaimStrings{issuer}, ID: jti, IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(now.Add(60 * time.Second))})
	assertion.Header["typ"] = tokenpolicy.TokenTypeClientAssertion
	assertion.Header["kid"] = c.KeyID
	proof, err := assertion.SignedString(key)
	if err != nil {
		return 0, "", "", errors.New("standing assertion signing failed")
	}
	form := url.Values{"grant_type": {"client_credentials"}, "client_assertion_type": {tokenpolicy.ClientAssertionType}, "client_assertion": {proof}, "audience": {audience}}
	code, _, raw, err := w.request(ctx, http.MethodPost, w.IssuanceURL+"/iam/v1/token", http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}, []byte(form.Encode()))
	if err != nil {
		return code, "", proof, err
	}
	var out struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(raw, &out) != nil {
		return code, "", proof, errors.New("token refusal body is not JSON")
	}
	return code, out.Error, proof, nil
}

// StartCatalogOnly открывает существующий путь запуска без объявлений, чтобы O мог
// восстановить состояние через живые штатные API, пока старый C остаётся выведенным из обращения.
// Он отклоняет любое объявление делегирования, не обходя его проверку аутентификации.
func (s *Session) StartCatalogOnly(ctx context.Context, in RIDDeliveryFixture) (*Process, error) {
	if err := s.checkEnvironment(); err != nil {
		return nil, err
	}
	for _, raw := range [][]byte{in.First, in.Second} {
		if len(raw) == 0 {
			continue
		}
		var doc struct {
			Seed struct {
				Delegations []any `yaml:"grantDelegations"`
			} `yaml:"seed"`
		}
		if err := yaml.Unmarshal(raw, &doc); err != nil {
			return nil, err
		}
		if len(doc.Seed.Delegations) != 0 {
			return nil, errors.New("catalog-only profile cannot carry delegation declarations")
		}
	}
	dir := filepath.Join(s.Root, fmt.Sprintf("delivery-%03d", s.sequence+1))
	if _, err := in.Write(dir, false); err != nil {
		return nil, err
	}
	config, err := yaml.Marshal(map[string]any{"manifests": map[string]any{"dir": dir, "required": true}})
	if err != nil {
		return nil, err
	}
	p, err := s.start(ctx, config)
	if err != nil {
		return p, err
	}
	ready, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	return p, p.AwaitReady(ready, s.Probe)
}

// Штатное ограничение частоты читается из настоящего HTTP Retry-After, со свежим подписанным JTI
// для каждого повтора. Настройки частоты, часы и поведение проверяющего не подменяются.
func (w *Wire) ExchangeLifecycleKey(ctx context.Context, c *StandingCreator, issuer, audience string, observe func(string)) (StandingToken, error) {
	if observe == nil {
		return StandingToken{}, errors.New("private secret observer required")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	key, err := jwt.ParseECPrivateKeyFromPEM([]byte(c.privateKey))
	if err != nil {
		return StandingToken{}, errors.New("standing assertion key is not ES256")
	}
	for {
		jti, err := randomURLToken()
		if err != nil {
			return StandingToken{}, err
		}
		now := time.Now().UTC().Truncate(time.Second)
		end := now.Add(60 * time.Second)
		if tokenpolicy.MaxAssertionLifetime < 60*time.Second {
			end = now.Add(tokenpolicy.MaxAssertionLifetime)
		}
		if c.ExpiresAt.Before(end) {
			end = c.ExpiresAt
		}
		if !end.After(now) {
			return StandingToken{}, errors.New("standing key already expired")
		}
		assertion := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.RegisteredClaims{Issuer: c.ClientID, Subject: c.ClientID, Audience: jwt.ClaimStrings{issuer}, ID: jti, IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(end)})
		assertion.Header["typ"] = tokenpolicy.TokenTypeClientAssertion
		assertion.Header["kid"] = c.KeyID
		proof, err := assertion.SignedString(key)
		if err != nil {
			return StandingToken{}, errors.New("standing assertion signing failed")
		}
		observe(proof)
		form := url.Values{"grant_type": {"client_credentials"}, "client_assertion_type": {tokenpolicy.ClientAssertionType}, "client_assertion": {proof}, "audience": {audience}}
		code, headers, raw, err := w.request(ctx, http.MethodPost, w.IssuanceURL+"/iam/v1/token", http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}, []byte(form.Encode()))
		if err != nil {
			return StandingToken{}, err
		}
		if code == http.StatusTooManyRequests {
			seconds, e := strconv.Atoi(headers.Get("Retry-After"))
			if e != nil || seconds < 1 {
				return StandingToken{}, errors.New("issuance pace refusal lacks positive Retry-After")
			}
			timer := time.NewTimer(time.Duration(seconds) * time.Second)
			select {
			case <-ctx.Done():
				timer.Stop()
				return StandingToken{}, ctx.Err()
			case <-timer.C:
			}
			continue
		}
		var token struct {
			AccessToken string `json:"access_token"`
		}
		if json.Unmarshal(raw, &token) != nil {
			return StandingToken{}, errors.New("issuance body is not JSON")
		}
		observe(token.AccessToken)
		if code != 200 || token.AccessToken == "" {
			return StandingToken{}, fmt.Errorf("normal standing issuance returned HTTP %d", code)
		}
		var me struct{ Subject string }
		code, err = w.JSON(ctx, http.MethodGet, "/iam/v1/me", token.AccessToken, nil, &me)
		if err != nil {
			return StandingToken{}, err
		}
		if code != 200 || me.Subject != "service_account:"+c.ID {
			return StandingToken{}, errors.New("normal presented reader rejected issued identity")
		}
		claims := jwt.MapClaims{}
		_, _, err = new(jwt.Parser).ParseUnverified(token.AccessToken, claims)
		if err != nil {
			return StandingToken{}, errors.New("verified token claims unreadable")
		}
		issued, err := claims.GetIssuedAt()
		if err != nil || issued == nil {
			return StandingToken{}, errors.New("verified token issuedAt missing")
		}
		expires, err := claims.GetExpirationTime()
		if err != nil || expires == nil {
			return StandingToken{}, errors.New("verified token expiresAt missing")
		}
		return StandingToken{Bearer: token.AccessToken, Assertion: proof, AssertionJTI: jti, IssuedAt: issued.Time, ExpiresAt: expires.Time}, nil
	}
}
