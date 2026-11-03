// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package installruntime

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/PRO-Robotech/corelib/grpcsrv"
	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
)

// Wire обращается к настоящим производственным слушателям с существующим CA стенда и
// двумя разными конечными идентичностями. Небезопасного режима TLS или синтетического
// субъекта контекста нет. Тела ответов (которые могут содержать удостоверения) никогда
// не включаются в ошибки. Их байты получает только закрытый вызывающий фикстуры.
type Wire struct {
	ports                           NativePorts
	PublicURL, IssuanceURL, JWKSURL string
	http                            *http.Client
	publicTLS, gatewayTLS           *tls.Config
}

func NewWire(pki, publicURL, issuanceURL, jwksURL string) (*Wire, error) {
	for _, endpoint := range []string{publicURL, issuanceURL, jwksURL} {
		u, err := url.Parse(endpoint)
		if err != nil || u.Scheme != "https" || u.Hostname() != "localhost" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return nil, errors.New("native acceptance requires explicit HTTPS localhost endpoints")
		}
	}
	root, err := os.ReadFile(filepath.Join(pki, "ca.crt"))
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(root) {
		return nil, errors.New("fixture CA has no certificates")
	}
	load := func(leaf string) (*tls.Config, error) {
		cert, err := tls.LoadX509KeyPair(filepath.Join(pki, leaf+".crt"), filepath.Join(pki, leaf+".key"))
		if err != nil {
			return nil, err
		}
		return &tls.Config{RootCAs: pool, Certificates: []tls.Certificate{cert}, ServerName: "localhost", MinVersion: tls.VersionTLS12}, nil
	}
	public, err := load("srv")
	if err != nil {
		return nil, err
	}
	gateway, err := load("edge")
	if err != nil {
		return nil, err
	}
	return &Wire{ports: DefaultNativePorts(), PublicURL: publicURL, IssuanceURL: issuanceURL, JWKSURL: jwksURL,
		publicTLS: public, gatewayTLS: gateway,
		http: &http.Client{Transport: &http.Transport{TLSClientConfig: public}, Timeout: 20 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

func (w *Wire) Close() { w.http.CloseIdleConnections() }

func (w *Wire) ListenersReady(ctx context.Context) error {
	for _, port := range w.ports.All() {
		dialer := tls.Dialer{Config: w.publicTLS.Clone()}
		conn, err := dialer.DialContext(ctx, "tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			return fmt.Errorf("owned TLS listener %d not ready", port)
		}
		conn.Close()
	}
	return w.JWKSReady(ctx)
}

func (w *Wire) request(ctx context.Context, method, endpoint string, headers http.Header, body []byte) (int, http.Header, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(body))
	if err != nil {
		return 0, nil, nil, errors.New("invalid fixture request")
	}
	req.Header = headers.Clone()
	res, err := w.http.Do(req)
	if err != nil {
		// Ошибки net/url включают полный URL авторизации и его чувствительный запрос.
		return 0, nil, nil, fmt.Errorf("native HTTP transport failed: %T", err)
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 4*1024*1024+1))
	if err != nil || len(raw) > 4*1024*1024 {
		return res.StatusCode, nil, nil, errors.New("native HTTP response unreadable or exceeds fixture ceiling")
	}
	return res.StatusCode, res.Header, raw, nil
}

func (w *Wire) JWKSReady(ctx context.Context) error {
	code, _, raw, err := w.request(ctx, http.MethodGet, w.JWKSURL+"/.well-known/kaname/jwks.json", nil, nil)
	if err != nil {
		return err
	}
	var doc struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if code != http.StatusOK || json.Unmarshal(raw, &doc) != nil || len(doc.Keys) == 0 {
		return errors.New("native JWKS application is not ready")
	}
	return nil
}

// OperatorGiven — принятый начальный Given пользователя/сессии/интерактивного клиента.
// Он не несёт административной выдачи. Только штатная начальная настройка запуска даёт O
// эти полномочия; штатный запрос /me должен принять полученный токен церемонии.
type OperatorGiven struct {
	UserID, SessionBearer, ClientID, ClientSecret, RedirectURI string
}

// VerifiedOperator не может создаваться вне этого пакета. Его шлюзовые
// идентичность/ACR выводятся из того же токена, принятого настоящим считывателем /me.
type VerifiedOperator struct{ token, userID, acr string }

func (o *VerifiedOperator) Bearer() string { return o.token }
func (o *VerifiedOperator) UserID() string { return o.userID }
func (o *VerifiedOperator) GatewayContext(ctx context.Context) context.Context {
	return metadata.NewOutgoingContext(ctx, metadata.Pairs(grpcsrv.MDKeyPrincipalType, "user",
		grpcsrv.MDKeyPrincipalID, o.userID, grpcsrv.MDKeyTokenACR, o.acr))
}

func randomURLToken() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

// ExchangeOperator выполняет настоящий обмен кода авторизации + PKCE через
// слушатель TLS, затем аутентифицирует ровно этот токен в публичном API /me.
// Чтение ACR после этого не аутентифицирует токен: это уже сделал /me.
func (w *Wire) ExchangeOperator(ctx context.Context, given OperatorGiven) (*VerifiedOperator, error) {
	verifier, err := randomURLToken()
	if err != nil {
		return nil, err
	}
	state, err := randomURLToken()
	if err != nil {
		return nil, err
	}
	challenge := sha256.Sum256([]byte(verifier))
	query := url.Values{"response_type": {"code"}, "client_id": {given.ClientID}, "redirect_uri": {given.RedirectURI},
		"scope": {"openid"}, "state": {state}, "code_challenge_method": {"S256"},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(challenge[:])}}
	code, headers, _, err := w.request(ctx, http.MethodGet, w.IssuanceURL+"/iam/v1/authorize?"+query.Encode(),
		http.Header{"Cookie": {"kaname_session=" + given.SessionBearer}}, nil)
	if err != nil {
		return nil, err
	}
	redirect, err := url.Parse(headers.Get("Location"))
	if code != http.StatusFound || err != nil || redirect == nil {
		return nil, fmt.Errorf("native authorization-code request returned HTTP %d", code)
	}
	params := redirect.Query()
	redirect.RawQuery = ""
	if redirect.String() != given.RedirectURI || len(params["code"]) != 1 || params.Get("code") == "" || len(params["state"]) != 1 || params.Get("state") != state || params.Get("error") != "" {
		return nil, errors.New("native authorize redirect/state/code differs from the registered ceremony")
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {params.Get("code")}, "redirect_uri": {given.RedirectURI}, "code_verifier": {verifier}}
	basic := base64.StdEncoding.EncodeToString([]byte(url.QueryEscape(given.ClientID) + ":" + url.QueryEscape(given.ClientSecret)))
	code, _, raw, err := w.request(ctx, http.MethodPost, w.IssuanceURL+"/iam/v1/token",
		http.Header{"Authorization": {"Basic " + basic}, "Content-Type": {"application/x-www-form-urlencoded"}}, []byte(form.Encode()))
	if err != nil {
		return nil, err
	}
	var token struct {
		AccessToken string `json:"access_token"`
	}
	if code != http.StatusOK || json.Unmarshal(raw, &token) != nil || token.AccessToken == "" {
		return nil, fmt.Errorf("native authorization-code exchange returned HTTP %d or no token", code)
	}
	code, _, raw, err = w.request(ctx, http.MethodGet, w.PublicURL+"/iam/v1/me", http.Header{"Authorization": {"Bearer " + token.AccessToken}}, nil)
	if err != nil {
		return nil, err
	}
	var me struct{ Subject, UserID string }
	if code != http.StatusOK || json.Unmarshal(raw, &me) != nil || me.Subject != "user:"+given.UserID || me.UserID != given.UserID {
		return nil, fmt.Errorf("real presented-credential /me rejected O or changed identity: HTTP %d", code)
	}
	claims := jwt.MapClaims{}
	if _, _, err := new(jwt.Parser).ParseUnverified(token.AccessToken, claims); err != nil || claims["sub"] != given.UserID || claims["kaname_principal_type"] != "user" || claims["acr"] != "2" {
		return nil, errors.New("accepted operator credential does not carry the expected user/ACR2")
	}
	return &VerifiedOperator{token: token.AccessToken, userID: given.UserID, acr: "2"}, nil
}

// JSON использует штатный предъявленный токен. Отрицательные случаи получают настоящий
// статус HTTP и могут проверять безопасный структурный код без печати тел.
func (w *Wire) JSON(ctx context.Context, method, path, bearer string, in, out any) (int, error) {
	if !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") {
		return 0, errors.New("public fixture path must be relative to the selected listener")
	}
	body, err := json.Marshal(in)
	if err != nil {
		return 0, err
	}
	if in == nil {
		body = nil
	}
	header := http.Header{"Content-Type": {"application/json"}}
	if bearer != "" {
		header.Set("Authorization", "Bearer "+bearer)
	}
	code, _, raw, err := w.request(ctx, method, w.PublicURL+path, header, body)
	if err != nil {
		return code, err
	}
	if out != nil && json.Unmarshal(raw, out) != nil {
		return code, errors.New("native API response is not the expected JSON document")
	}
	return code, nil
}

func (w *Wire) Gateway(address string) (*grpc.ClientConn, error) {
	if address != w.InternalGatewayAddress() {
		return nil, errors.New("gateway fixture must target the selected native loopback listener")
	}
	return grpc.NewClient(address, grpc.WithTransportCredentials(credentials.NewTLS(w.gatewayTLS.Clone())))
}

// Operation опрашивает тот же производственный публичный интерфейс видимости, что использует
// независимый набор Newman. Он сохраняет отказы API отказами и требует
// настоящий завершённый ответ, а не только допуск запроса.
type Operation struct {
	ID    string `json:"id"`
	Done  bool   `json:"done"`
	Error *struct {
		Code int `json:"code"`
	} `json:"error"`
	Response json.RawMessage `json:"response"`
	Metadata json.RawMessage `json:"metadata"`
}

func (w *Wire) AwaitOperation(ctx context.Context, bearer string, op Operation) (Operation, error) {
	if op.ID == "" {
		return op, errors.New("normal API did not return an Operation ID")
	}
	for {
		if op.Done {
			if op.Error != nil {
				return op, fmt.Errorf("normal Operation completed with code %d", op.Error.Code)
			}
			if len(op.Response) == 0 {
				return op, errors.New("normal Operation completed without a response")
			}
			return op, nil
		}
		timer := time.NewTimer(25 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return op, ctx.Err()
		case <-timer.C:
		}
		var next Operation
		code, err := w.JSON(ctx, http.MethodGet, "/operations/"+url.PathEscape(op.ID), bearer, nil, &next)
		if err != nil {
			return op, err
		}
		if code != http.StatusOK || next.ID != op.ID {
			return op, errors.New("normal Operation poll rejected or changed identity")
		}
		op = next
	}
}

// AwaitOperatorAdmin наблюдает штатный API текущих полномочий. Начальная настройка запуска
// асинхронна; готовность TLS/JWKS не заменяет этот барьер.
// Повторяется только ожидаемый отказ разрешения до начальной настройки. Отказы аутентификации,
// серверной части и формы ответа остаются отказами нативного запуска.
func (w *Wire) AwaitOperatorAdmin(ctx context.Context, operator *VerifiedOperator) error {
	if operator == nil || operator.userID == "" {
		return errors.New("verified operator required")
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		var out struct {
			Admins []struct {
				GrantID     string `json:"clusterAdminGrantId"`
				SubjectType string `json:"subjectType"`
				SubjectID   string `json:"subjectId"`
			} `json:"admins"`
		}
		code, err := w.JSON(ctx, http.MethodGet, "/iam/v1/cluster/admins", operator.Bearer(), nil, &out)
		if err != nil {
			return err
		}
		if code == http.StatusOK {
			matches := 0
			for _, admin := range out.Admins {
				if admin.SubjectType == "USER" && admin.SubjectID == operator.userID && admin.GrantID != "" {
					matches++
				}
			}
			if matches != 1 {
				return errors.New("current-authority API did not return exactly one active O grant")
			}
			return nil
		}
		if code != http.StatusForbidden {
			return fmt.Errorf("bootstrap authority observation returned HTTP %d", code)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
