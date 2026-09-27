// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// revocation_reaches_presentation_test.go — K1 одним прогоном СКВОЗЬ обе
// половины (задача PRO-Robotech/kaname#396, предикат снятия п. 1).
//
// # Что здесь настоящее
//
// Церемония фундамента (`oauthceremony.New`) — настоящая, со своим движком.
// Адаптеры службы — настоящие: выпуск и опознание (`AccessTokens` над
// подписантом службы), отзыв (`Grants`), чеканка идентификатора гранта
// (`NewGrantID`). Место, принимающее токен, — настоящий авторитет отзыва на пути
// запроса (`tokenintrospecthttp`), а правило отзыва в нём — настоящее
// (`tokenrevocation`).
//
// Подставлены только хранилища: записи кода, токенов, семейств и выпусков, а
// также справочник проверочных значений секрета клиента живут в памяти пробы;
// сверку секрета исполняет настоящий адаптер (`ClientSecrets`) над настоящим
// проверяющим (`passwordverify`). Подставка держит СЕМАНТИКУ порта (погашение
// одной операцией под замком, повтор отдаёт запись вместе с отказом,
// отозванное семейство не отдаётся) и семантику схемы службы: семейство
// заводится вместе с кодом, запись выпуска ложится только в живое семейство,
// отметка отзыва доезжает до каждой записи выпуска семейства (решение К10,
// вариант А: семейство выпуска служба знает по записи jti → семейство,
// kaname#319). То, что схема службы держит это на самом деле, держат
// интеграционные пробы слоя доступа
// (`family_revocation_through_three_surfaces_integration_test.go`) и схемы
// (`access_token_family_schema_integration_test.go`).
//
// # Почему одним прогоном
//
// Две пробы по половине — «отзыв ставит отметку» и «правило читает запись
// выпуска» — зелены каждая и при несведённой середине: выпуск, не пишущий
// запись, даёт токен, о семействе которого правилу спросить не по чему.
// Сходимость видна только сквозь обе половины.
package ceremonyport_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/oauthceremony"
	"github.com/PRO-Robotech/corelib/tokenpolicy"

	"github.com/PRO-Robotech/kaname/internal/ceremonyport"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/handler/tokenintrospecthttp"
	"github.com/PRO-Robotech/kaname/internal/passwordverify"
)

const (
	flowSecret   = "correct-horse-battery-staple"
	flowRedirect = "https://console.kacho.local/oauth2/callback"
	flowState    = "s6BhdRkqt3s6BhdRkqt3s6BhdRkqt3xx"
	flowVerifier = "dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXkQ"
)

// ── Семейства: отметка отзыва и записи выпуска ─────────────────────────────

type memFamilies struct {
	mu      sync.Mutex
	known   map[string]bool
	revoked map[string]domain.FamilyRevocationReason
	// issued — записи выпуска: jti → семейство.
	issued map[string]string
}

func newMemFamilies() *memFamilies {
	return &memFamilies{
		known:   map[string]bool{},
		revoked: map[string]domain.FamilyRevocationReason{},
		issued:  map[string]string{},
	}
}

// open заводит семейство — у службы его заводит выдача кода.
func (m *memFamilies) open(familyID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.known[familyID] = true
}

// RevokeFamily — как у хранилища службы: причина судится словарём, отметка
// ставится один раз (первая причина остаётся). Отметка и есть отзыв каждой
// записи выпуска семейства: ответ о выпуске читается от неё.
func (m *memFamilies) RevokeFamily(_ context.Context, familyID string, reason domain.FamilyRevocationReason) (int64, error) {
	if familyID == "" {
		return 0, errEmptyFamily
	}
	if err := reason.Validate(); err != nil {
		return 0, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, done := m.revoked[familyID]; done {
		return 0, nil
	}
	m.revoked[familyID] = reason
	return 1, nil
}

// RecordAccessToken — писатель записи выпуска, как у хранилища службы: запись
// ложится только в известное и живое семейство (у службы это держит внешний
// ключ записи), иначе — ErrAccessTokenFamilyNotLive.
func (m *memFamilies) RecordAccessToken(_ context.Context, jti, familyID string, issuedAt, expiresAt time.Time) error {
	if jti == "" || familyID == "" || issuedAt.IsZero() || !expiresAt.After(issuedAt) {
		return errString("issuance record: jti, family and a lifetime are required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, revoked := m.revoked[familyID]; revoked || !m.known[familyID] {
		return domain.ErrAccessTokenFamilyNotLive
	}
	m.issued[jti] = familyID
	return nil
}

// RevokedBefore — читатель отсечек субъекта и клиента. Отсечек эта проба не
// ставит: отзыв семейства их не пишет.
func (m *memFamilies) RevokedBefore(context.Context, string) (time.Time, bool, error) {
	return time.Time{}, false, nil
}

// FamilyRevoked — ответ записи выпуска о семействе: записи нет — выпуск
// семейству не принадлежит; есть — отозвано ли её семейство.
func (m *memFamilies) FamilyRevoked(_ context.Context, jti string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	family, recorded := m.issued[jti]
	if !recorded {
		return false, nil
	}
	_, revoked := m.revoked[family]
	return revoked, nil
}

func (m *memFamilies) isRevoked(familyID string) (domain.FamilyRevocationReason, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.revoked[familyID]
	return r, ok
}

type errString string

func (e errString) Error() string { return string(e) }

const errEmptyFamily = errString("family id is required")

// ── Хранилища церемонии ────────────────────────────────────────────────────

type codeRow struct {
	rec      oauthceremony.AuthorizationCodeRecord
	consumed bool
}

type refreshRow struct {
	grant   oauthceremony.GrantRecord
	rotated bool
}

type memVaults struct {
	mu       sync.Mutex
	families *memFamilies
	clients  map[string]oauthceremony.ClientRegistration
	// secrets — справочник проверочных значений секрета клиента, над которым
	// стоит адаптер ClientSecrets; контракт — хранилища службы.
	secrets *secretStore
	codes   map[string]*codeRow
	access  map[string]oauthceremony.GrantRecord
	refresh map[string]*refreshRow
}

func newMemVaults(families *memFamilies) *memVaults {
	return &memVaults{
		families: families,
		clients:  map[string]oauthceremony.ClientRegistration{},
		secrets:  &secretStore{verifiers: map[string]domain.LoginVerifier{}},
		codes:    map[string]*codeRow{},
		access:   map[string]oauthceremony.GrantRecord{},
		refresh:  map[string]*refreshRow{},
	}
}

func (v *memVaults) revoked(grantID string) bool {
	_, r := v.families.isRevoked(grantID)
	return r
}

func (v *memVaults) LookupClient(_ context.Context, clientID string) (oauthceremony.ClientRegistration, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	reg, ok := v.clients[clientID]
	if !ok {
		return oauthceremony.ClientRegistration{}, oauthceremony.ErrGrantNotFound
	}
	return reg, nil
}

func (v *memVaults) StoreAuthorizationCode(_ context.Context, sig string, rec oauthceremony.AuthorizationCodeRecord) (oauthceremony.StoreOutcome, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if _, taken := v.codes[sig]; taken {
		return oauthceremony.StoreOutcome{}, oauthceremony.ErrStorageConflict
	}
	v.codes[sig] = &codeRow{rec: rec}
	// Код и его семейство заводятся вместе — как у выдачи кода службы.
	v.families.open(rec.Grant.GrantID)
	return oauthceremony.RowsTouched(1), nil
}

func (v *memVaults) FetchAuthorizationCode(_ context.Context, sig string) (oauthceremony.AuthorizationCodeRecord, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	row, ok := v.codes[sig]
	if !ok {
		return oauthceremony.AuthorizationCodeRecord{}, oauthceremony.ErrGrantNotFound
	}
	if row.consumed {
		return row.rec, oauthceremony.ErrAuthorizationCodeConsumed
	}
	return row.rec, nil
}

func (v *memVaults) ConsumeAuthorizationCode(_ context.Context, sig string) (oauthceremony.StoreOutcome, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	row, ok := v.codes[sig]
	if !ok || row.consumed {
		return oauthceremony.RowsTouched(0), nil
	}
	row.consumed = true
	return oauthceremony.RowsTouched(1), nil
}

func (v *memVaults) StoreAccessToken(_ context.Context, sig string, grant oauthceremony.GrantRecord) (oauthceremony.StoreOutcome, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if _, taken := v.access[sig]; taken {
		return oauthceremony.StoreOutcome{}, oauthceremony.ErrStorageConflict
	}
	v.access[sig] = grant
	return oauthceremony.RowsTouched(1), nil
}

func (v *memVaults) FetchAccessToken(_ context.Context, sig string) (oauthceremony.GrantRecord, error) {
	v.mu.Lock()
	grant, ok := v.access[sig]
	v.mu.Unlock()
	if !ok || v.revoked(grant.GrantID) {
		return oauthceremony.GrantRecord{}, oauthceremony.ErrGrantNotFound
	}
	return grant, nil
}

func (v *memVaults) DropAccessToken(_ context.Context, sig string) (oauthceremony.StoreOutcome, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if _, ok := v.access[sig]; !ok {
		return oauthceremony.RowsTouched(0), nil
	}
	delete(v.access, sig)
	return oauthceremony.RowsTouched(1), nil
}

func (v *memVaults) StoreRefreshToken(_ context.Context, sig, _ string, grant oauthceremony.GrantRecord) (oauthceremony.StoreOutcome, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if _, taken := v.refresh[sig]; taken {
		return oauthceremony.StoreOutcome{}, oauthceremony.ErrStorageConflict
	}
	v.refresh[sig] = &refreshRow{grant: grant}
	return oauthceremony.RowsTouched(1), nil
}

func (v *memVaults) FetchRefreshToken(_ context.Context, sig string) (oauthceremony.GrantRecord, error) {
	v.mu.Lock()
	row, ok := v.refresh[sig]
	v.mu.Unlock()
	switch {
	case !ok, v.revoked(row.grant.GrantID):
		return oauthceremony.GrantRecord{}, oauthceremony.ErrGrantNotFound
	case row.rotated:
		return row.grant, oauthceremony.ErrRefreshTokenRotated
	default:
		return row.grant, nil
	}
}

func (v *memVaults) DropRefreshToken(_ context.Context, sig string) (oauthceremony.StoreOutcome, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if _, ok := v.refresh[sig]; !ok {
		return oauthceremony.RowsTouched(0), nil
	}
	delete(v.refresh, sig)
	return oauthceremony.RowsTouched(1), nil
}

func (v *memVaults) RotateRefreshToken(_ context.Context, grantID, sig string) (oauthceremony.StoreOutcome, error) {
	v.mu.Lock()
	row, ok := v.refresh[sig]
	v.mu.Unlock()
	if !ok || v.revoked(grantID) {
		return oauthceremony.RowsTouched(0), nil
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if row.rotated || row.grant.GrantID != grantID {
		return oauthceremony.RowsTouched(0), nil
	}
	row.rotated = true
	return oauthceremony.RowsTouched(1), nil
}

// ── Сборка ─────────────────────────────────────────────────────────────────

type flowRig struct {
	ceremony *oauthceremony.Ceremony
	tokens   *ceremonyport.AccessTokens
	vaults   *memVaults
	families *memFamilies
	surface  http.Handler
}

func newFlowRig(t *testing.T) *flowRig {
	t.Helper()
	rig := &flowRig{}
	ring := newKeyRing(t, testKID)
	families := newMemFamilies()
	// Выпуск пишет запись в ТО ЖЕ хранилище семейств, от отметки которого
	// читается ответ о выпуске, — как у службы.
	tokens := newRecordingAccessTokens(t, ring, time.Now, families)
	grants, err := ceremonyport.NewGrants(families)
	require.NoError(t, err)
	vaults := newMemVaults(families)

	hasher := floorHasher(t)
	stored, err := hasher.Hash(flowSecret)
	require.NoError(t, err)
	vaults.secrets.verifiers[testClientID] = stored
	secrets, err := ceremonyport.NewClientSecrets(vaults.secrets,
		alignedVerifier(t, hasher, &outcomeCounter{cells: map[passwordverify.Outcome]int{}}))
	require.NoError(t, err)
	vaults.clients[testClientID] = oauthceremony.ClientRegistration{
		ClientID:      testClientID,
		RedirectURIs:  []string{flowRedirect},
		GrantKinds:    []oauthceremony.GrantKind{oauthceremony.GrantAuthorizationCode, oauthceremony.GrantRefreshToken},
		ResponseKinds: []string{"code"},
		Scopes:        []string{"openid", "offline"},
		Audiences:     []string{testAudience},
	}

	ceremony, err := oauthceremony.New(oauthceremony.Config{
		AuthorizationEndpoint:     "https://iam.kacho.local/iam/v1/authorize",
		TokenEndpoint:             "https://iam.kacho.local/iam/v1/token",
		AccessTokenLifespan:       10 * time.Minute,
		RefreshTokenLifespan:      time.Hour,
		AuthorizationCodeLifespan: tokenpolicy.MaxAuthorizationCodeTTL,
		ScopeMatching:             oauthceremony.ScopeMatchingExact,
		RefreshTokenIssuance:      oauthceremony.RefreshTokenIssuanceOnScope,
		RefreshTokenScopes:        []string{"offline"},
		MinParameterEntropy:       8,
		PortTimeout:               2 * time.Second,
		OperationTimeout:          5 * time.Second,
		NewGrantID:                ceremonyport.NewGrantID,
	}, oauthceremony.Ports{
		Clients:            vaults,
		AuthorizationCodes: vaults,
		AccessTokens:       vaults,
		RefreshTokens:      vaults,
		Grants:             grants,
		AccessTokenIssuer:  tokens,
		ClientSecrets:      secrets,
	})
	require.NoError(t, err, "церемония не собрана на адаптерах службы")

	surface := tokenintrospecthttp.NewHandler(tokenintrospecthttp.Config{
		Issuer: testIssuer, Keys: ring, Revocations: families, Clock: time.Now,
	})
	rig.ceremony, rig.tokens, rig.vaults, rig.families, rig.surface = ceremony, tokens, vaults, families, surface
	return rig
}

// loginGrant — решение службы о выдаче: контекст входа — полями, а не ключами
// карты утверждений.
func loginGrant() oauthceremony.AuthorizationGrant {
	return oauthceremony.AuthorizationGrant{
		Subject:          testSubject,
		SessionID:        testSessionID,
		ACR:              testACR,
		AuthTime:         testAuthTime,
		GrantedScopes:    []string{"openid", "offline"},
		GrantedAudiences: []string{testAudience},
	}
}

func (r *flowRig) issueCode(t *testing.T) string {
	t.Helper()
	code, err := r.issueCodeFor(loginGrant())
	require.NoError(t, err, "CompleteAuthorization отказал")
	return code
}

// issueCodeFor проходит точку авторизации и выдаёт код по решению grant.
func (r *flowRig) issueCodeFor(grant oauthceremony.AuthorizationGrant) (string, error) {
	sum := sha256.Sum256([]byte(flowVerifier))
	intent, err := r.ceremony.Authorize(context.Background(), oauthceremony.AuthorizationRequest{
		ClientID:      testClientID,
		RedirectURI:   flowRedirect,
		ResponseKinds: []oauthceremony.ResponseKind{oauthceremony.ResponseKindCode},
		Scopes:        []string{"openid", "offline"},
		Audiences:     []string{testAudience},
		State:         flowState,
		Additional: map[string][]string{
			"code_challenge":        {base64.RawURLEncoding.EncodeToString(sum[:])},
			"code_challenge_method": {"S256"},
		},
	})
	if err != nil {
		return "", fmt.Errorf("Authorize: %w", err)
	}
	result, err := r.ceremony.CompleteAuthorization(context.Background(), intent, grant)
	if err != nil {
		return "", err
	}
	codes := result.Parameters["code"]
	if len(codes) != 1 {
		return "", fmt.Errorf("точка авторизации выдала %d кодов, а не один", len(codes))
	}
	return codes[0], nil
}

func (r *flowRig) exchangeCode(code string) (oauthceremony.TokenResult, error) {
	return r.exchangeCodeAs(testClientID, flowSecret, code)
}

// exchangeCodeAs — обмен кода клиентом clientID, доказывающим себя секретом.
func (r *flowRig) exchangeCodeAs(clientID, secret, code string) (oauthceremony.TokenResult, error) {
	return r.ceremony.Exchange(context.Background(), oauthceremony.TokenRequest{
		Grant: oauthceremony.GrantAuthorizationCode, ClientID: clientID, ClientSecret: secret,
		AuthMethod: oauthceremony.ClientAuthBasic, Code: code, RedirectURI: flowRedirect, CodeVerifier: flowVerifier,
	})
}

func (r *flowRig) refresh(token string) (oauthceremony.TokenResult, error) {
	return r.ceremony.Exchange(context.Background(), oauthceremony.TokenRequest{
		Grant: oauthceremony.GrantRefreshToken, ClientID: testClientID, ClientSecret: flowSecret,
		AuthMethod: oauthceremony.ClientAuthBasic, RefreshToken: token,
	})
}

// freshFamily проходит церемонию до пары токенов нового семейства.
func (r *flowRig) freshFamily(t *testing.T) oauthceremony.TokenResult {
	t.Helper()
	tokens, err := r.exchangeCode(r.issueCode(t))
	require.NoError(t, err, "обмен кода отказал")
	require.NotEmpty(t, tokens.AccessToken)
	require.NotEmpty(t, tokens.RefreshToken, "обмен не выдал токена обновления при выданной offline")
	return tokens
}

// familyOf — ключ семейства предъявленного токена так, как его видит служба:
// опознание адаптером и запись гранта под jti.
func (r *flowRig) familyOf(t *testing.T, access string) string {
	t.Helper()
	jti, err := r.tokens.IdentifyAccessToken(context.Background(), access)
	require.NoError(t, err)
	r.vaults.mu.Lock()
	defer r.vaults.mu.Unlock()
	grant, ok := r.vaults.access[jti]
	require.True(t, ok, "НЕ ВЫПОЛНИЛОСЬ: грант под jti выпуска не положен")
	return grant.GrantID
}

// accepted — принимает ли место предъявления этот токен доступа.
func (r *flowRig) accepted(t *testing.T, access string) bool {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, tokenintrospecthttp.IntrospectPath,
		strings.NewReader(url.Values{"token": {access}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	r.surface.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, "место предъявления не ответило суждением: %s", rec.Body.String())
	var body struct {
		Active bool `json:"active"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	return body.Active
}

// ── K1 ─────────────────────────────────────────────────────────────────────

func TestK1_RevokedFamilyIsRefusedWhereTheAccessTokenIsPresented(t *testing.T) {
	rig := newFlowRig(t)

	// Близнец на весь прогон: семейство, которое никто не отзывает.
	twin := rig.freshFamily(t)
	require.True(t, rig.accepted(t, twin.AccessToken),
		"НЕ ВЫПОЛНИЛОСЬ: токен свежего семейства не принят местом предъявления до всякого отзыва")

	t.Run("повтор кода", func(t *testing.T) {
		code := rig.issueCode(t)
		first, err := rig.exchangeCode(code)
		require.NoError(t, err)
		family := rig.familyOf(t, first.AccessToken)

		_, err = rig.exchangeCode(code)
		require.Error(t, err, "НЕ ВЫПОЛНИЛОСЬ: повтор кода обменялся")
		reason, revoked := rig.families.isRevoked(family)
		require.True(t, revoked, "повтор кода не отозвал семейство")
		require.Equal(t, domain.FamilyRevocationReason(oauthceremony.RevocationCodeReplay), reason)

		require.False(t, rig.accepted(t, first.AccessToken),
			"токен доступа семейства повторённого кода принят при предъявлении")
		require.True(t, rig.accepted(t, twin.AccessToken), "близнец: неотозванное семейство перестало приниматься")
	})

	t.Run("повтор токена обновления", func(t *testing.T) {
		pair := rig.freshFamily(t)
		family := rig.familyOf(t, pair.AccessToken)
		rotated, err := rig.refresh(pair.RefreshToken)
		require.NoError(t, err, "оборот токена обновления отказал")
		require.True(t, rig.accepted(t, rotated.AccessToken), "НЕ ВЫПОЛНИЛОСЬ: токен оборота не принят до повтора")

		_, err = rig.refresh(pair.RefreshToken)
		require.Error(t, err, "НЕ ВЫПОЛНИЛОСЬ: повтор токена обновления обернулся")
		reason, revoked := rig.families.isRevoked(family)
		require.True(t, revoked, "повтор токена обновления не отозвал семейство")
		require.Equal(t, domain.FamilyRevocationReason(oauthceremony.RevocationRefreshReplay), reason)

		require.False(t, rig.accepted(t, pair.AccessToken), "прежний токен доступа семейства принят")
		require.False(t, rig.accepted(t, rotated.AccessToken), "токен доступа, выданный оборотом, принят")
		require.True(t, rig.accepted(t, twin.AccessToken), "близнец: неотозванное семейство перестало приниматься")
	})

	t.Run("выпуск после отметки отзыва не состоится", func(t *testing.T) {
		// Так выглядит одновременный повтор кода: опередивший прочитал
		// семейство живым и выпускает ПОСЛЕ отметки, которую ставит отзыв
		// отставшего. Запись выпуска в отозванное семейство не ложится, и
		// выпуск, не записанный в семейство, клиенту не уезжает: иначе это был
		// бы токен, о семействе которого правилу спросить не по чему.
		code := rig.issueCode(t)
		first, err := rig.exchangeCode(code)
		require.NoError(t, err)
		family := rig.familyOf(t, first.AccessToken)
		_, err = rig.exchangeCode(code)
		require.Error(t, err, "НЕ ВЫПОЛНИЛОСЬ: повтор кода обменялся")
		_, revoked := rig.families.isRevoked(family)
		require.True(t, revoked, "НЕ ВЫПОЛНИЛОСЬ: семейство не отозвано")
		issueLate := func(grantID string) (oauthceremony.IssuedAccessToken, error) {
			return rig.tokens.IssueAccessToken(context.Background(), oauthceremony.GrantRecord{
				GrantID: grantID, ClientID: testClientID,
				GrantedScopes: []string{"openid"}, GrantedAudiences: []string{testAudience},
				Session: oauthceremony.SessionRecord{
					Subject: testSubject, SessionID: testSessionID, ACR: testACR, AuthTime: testAuthTime,
					ExpiresAt: map[oauthceremony.TokenKind]time.Time{oauthceremony.TokenKindAccess: time.Now().Add(5 * time.Minute)},
				},
			})
		}
		late, err := issueLate(family)
		require.ErrorIsf(t, err, domain.ErrAccessTokenFamilyNotLive,
			"выпуск в отозванное семейство состоялся (токен выдан: %v)", late.Token != "")
		require.Empty(t, late.Token, "при отказе записи выпуска уехал токен")

		// Близнец отличается ОДНИМ фактом — семейство не отозвано.
		live, err := issueLate(rig.familyOf(t, twin.AccessToken))
		require.NoError(t, err, "близнец: выпуск того же вида для неотозванного семейства отказал")
		require.True(t, rig.accepted(t, live.Token),
			"близнец: выпуск того же вида для неотозванного семейства не принят")
	})
}

// Отзыв клиентом (RFC 7009) — причина фундамента `client-revoke`, у которой в
// закрытом словаре службы и в ограничении схемы слова НЕТ; слово заводит
// задача PRO-Robotech/kaname#406. Пока его нет, отзыв обязан отказать
// ОПЕРАЦИЕЙ — громко, не назвав успехом отзыв, которого не было, и не записав
// семейству чужую причину.
//
// Проба истекает сама: слово появилось — первое утверждение краснеет, и подслучай
// переводится на полное утверждение K1 (отозвано → отвергнуто при предъявлении,
// близнец принят), как у двух соседних путей.
func TestK1_ClientRevokeRefusesLoudlyWhileTheWordIsMissing(t *testing.T) {
	_, hasWord := ceremonyport.FamilyReasonOf(oauthceremony.RevocationClientRevoke)
	require.False(t, hasWord, "у причины client-revoke появилось слово службы — переведите этот "+
		"подслучай на полное утверждение K1 и снимите запись ожидания в grants_test.go")

	rig := newFlowRig(t)
	pair := rig.freshFamily(t)
	family := rig.familyOf(t, pair.AccessToken)

	err := rig.ceremony.Revoke(context.Background(), oauthceremony.RevocationRequest{
		Token: pair.RefreshToken, KindHint: oauthceremony.TokenKindRefresh,
		ClientID: testClientID, ClientSecret: flowSecret, AuthMethod: oauthceremony.ClientAuthBasic,
	})
	require.Error(t, err, "отзыв клиентом ответил успехом, хотя причину записать нечем")
	_, revoked := rig.families.isRevoked(family)
	require.False(t, revoked, "семейству записана причина, которой нет в словаре службы")
}

// ── Контекст входа: поля записи, а не ключи карты ──────────────────────────

// recordOf — запись гранта, под которой хранилище держит выпуск jti.
func (r *flowRig) recordOf(t *testing.T, access string) oauthceremony.GrantRecord {
	t.Helper()
	jti, err := r.tokens.IdentifyAccessToken(context.Background(), access)
	require.NoError(t, err)
	r.vaults.mu.Lock()
	defer r.vaults.mu.Unlock()
	rec, ok := r.vaults.access[jti]
	require.True(t, ok, "НЕ ВЫПОЛНИЛОСЬ: запись под jti выпуска не положена")
	return rec
}

// Сессия, уровень и момент аутентификации, названные решением службы о выдаче,
// доходят до записи ПОЛЯМИ — и после обмена кода, и после оборота токена
// обновления: это снимок на выдаче кода, и у семейства он один. Токен доступа
// несёт уровень и момент из этих полей.
func TestLoginContext_ReachesTheRecordsAsFields(t *testing.T) {
	rig := newFlowRig(t)
	pair := rig.freshFamily(t)
	rotated, err := rig.refresh(pair.RefreshToken)
	require.NoError(t, err, "оборот токена обновления отказал")

	for name, access := range map[string]string{"обмен кода": pair.AccessToken, "оборот": rotated.AccessToken} {
		rec := rig.recordOf(t, access)
		require.Equalf(t, testSessionID, rec.Session.SessionID, "%s: сессия не дошла до записи полем", name)
		require.Equalf(t, testACR, rec.Session.ACR, "%s: уровень не дошёл до записи полем", name)
		require.Truef(t, testAuthTime.Equal(rec.Session.AuthTime), "%s: момент аутентификации %s, а не %s",
			name, rec.Session.AuthTime, testAuthTime)
		for _, key := range []string{"sid", "acr", "auth_time"} {
			require.NotContainsf(t, rec.Session.Claims, key, "%s: ключ %q лёг в карту утверждений записи", name, key)
		}
		_, claims := unverifiedClaims(t, access)
		require.Equalf(t, testACR, claims["acr"], "%s: уровень токена не из поля записи", name)
		require.Equalf(t, float64(testAuthTime.Unix()), claims["auth_time"], "%s: момент токена не из поля записи", name)
	}
}

// Близнец: те же ключи — в карте утверждений решения, с ДРУГИМИ значениями, —
// в запись не идут: выдача отказывает до кода, и хранилище кода не пополняется.
// Ключ вне контекста входа в той же карте выдачи не мешает.
func TestLoginContext_KeysOfTheClaimsMapDoNotReachTheRecord(t *testing.T) {
	rig := newFlowRig(t)
	codesBefore := func() int {
		rig.vaults.mu.Lock()
		defer rig.vaults.mu.Unlock()
		return len(rig.vaults.codes)
	}

	for key, value := range map[string]any{
		"sid": "hss-claims-only-session", "acr": "3", "auth_time": testAuthTime.Add(-time.Hour).Unix(),
	} {
		t.Run(key, func(t *testing.T) {
			before := codesBefore()
			grant := loginGrant()
			grant.Claims = map[string]any{key: value}
			code, err := rig.issueCodeFor(grant)
			require.Error(t, err, "выдача приняла ключ %q в карте утверждений", key)
			require.Empty(t, code)
			require.Equal(t, before, codesBefore(), "запись кода легла при отвергнутой выдаче")
		})
	}

	t.Run("близнец: ключ вне контекста входа выдаётся", func(t *testing.T) {
		before := codesBefore()
		grant := loginGrant()
		grant.Claims = map[string]any{"tenant_hint": "acc-0123456789abcdefg"}
		code, err := rig.issueCodeFor(grant)
		require.NoError(t, err)
		require.NotEmpty(t, code)
		require.Equal(t, before+1, codesBefore())
	})
}

// ── Секрет клиента сквозь церемонию ────────────────────────────────────────

// Порт сверки провязан в церемонию: неверный секрет и неизвестный клиент — один
// и тот же отказ доказательства; отказ справочника — отказ операции, а не
// «клиент не доказан»; верный секрет обменивает тот же код.
func TestClientSecrets_ProveTheClientThroughTheCeremony(t *testing.T) {
	rig := newFlowRig(t)
	code := rig.issueCode(t)

	_, err := rig.exchangeCodeAs(testClientID, "not-the-secret-of-this-client", code)
	require.Equal(t, oauthceremony.CodeInvalidClient, oauthceremony.CodeOf(err), "неверный секрет: %v", err)

	_, err = rig.exchangeCodeAs(unknownClientID, flowSecret, code)
	require.Equal(t, oauthceremony.CodeInvalidClient, oauthceremony.CodeOf(err), "неизвестный клиент: %v", err)

	rig.vaults.secrets.mu.Lock()
	rig.vaults.secrets.fail = errors.New("connection refused")
	rig.vaults.secrets.mu.Unlock()
	_, err = rig.exchangeCode(code)
	require.Equal(t, oauthceremony.CodeServerError, oauthceremony.CodeOf(err),
		"отказ справочника стал ответом о клиенте: %v", err)

	rig.vaults.secrets.mu.Lock()
	rig.vaults.secrets.fail = nil
	rig.vaults.secrets.mu.Unlock()
	tokens, err := rig.exchangeCode(code)
	require.NoError(t, err, "близнец: верный секрет не обменял код")
	require.NotEmpty(t, tokens.AccessToken)
}
