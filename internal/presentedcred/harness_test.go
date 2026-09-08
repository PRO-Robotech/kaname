// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// harness_test.go — фикстура читателя предъявленного удостоверения.
//
// # Один факт на отрицание
//
// Каждое отрицание §4 приёмки KAN-AUTHN-1 отличается от годного предъявления
// РОВНО ОДНИМ названным фактом. Поэтому годный токен собирается ОДНОЙ функцией,
// а отрицание получается изменением одного поля её входа: два факта разом дали
// бы отказ, про который неизвестно, какая половина его произвела.
//
// # Часы — вход, а не окружение
//
// Обе половины окна отзыва (до истечения кеша и после) наблюдаются
// детерминированно, а не выжидаются: без управляемых часов KAN-REV-04 был бы
// пробой, чей исход зависит от загрузки машины.
package presentedcred_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"github.com/PRO-Robotech/kacho/pkg/operations"
	"github.com/PRO-Robotech/kacho/pkg/tokenpolicy"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/presentedcred"
	"github.com/PRO-Robotech/kaname/internal/signingkeygen"
)

const (
	// testIssuer — издатель, которым установка объявила СЕБЯ.
	testIssuer = "https://kaname.example.test"
	// testAudience — адресат ПУБЛИЧНОГО слушателя.
	testAudience = "kaname-public"
	// testSubject / testPrincipalID — за кого говорит годный токен.
	testSubject     = "usr-01hzzzzzzzzzzzzzzz"
	testPrincipalID = "usr-01hzzzzzzzzzzzzzzz"
	testDisplay     = "alice@example.test"
	testKID         = "kacho-2026-09-a"
)

// keyMaterial — пара ключей и её публикуемая половина.
type keyMaterial struct {
	kid        string
	alg        domain.SigningAlgorithm
	privatePEM []byte
	published  domain.PublishedKey
}

func newKey(t *testing.T, kid string, alg domain.SigningAlgorithm) keyMaterial {
	t.Helper()
	mat, err := signingkeygen.Generate(alg)
	if err != nil {
		t.Fatalf("порождение ключа %s: %v", alg, err)
	}
	return keyMaterial{
		kid:        kid,
		alg:        alg,
		privatePEM: mat.PrivateKeyPEM,
		published: domain.PublishedKey{
			KID: domain.KeyID(kid), Algorithm: alg, PublicKeyPEM: mat.PublicKeyPEM,
		},
	}
}

// signingMethod — метод подписи по алгоритму ключа. Своей таблицы алгоритмов
// фикстура не заводит: словарь платформы один (`tokenpolicy.Algorithms`).
func signingMethod(t *testing.T, alg domain.SigningAlgorithm) jwt.SigningMethod {
	t.Helper()
	switch string(alg) {
	case tokenpolicy.AlgRS256:
		return jwt.SigningMethodRS256
	case tokenpolicy.AlgES256:
		return jwt.SigningMethodES256
	case tokenpolicy.AlgEdDSA:
		return jwt.SigningMethodEdDSA
	default:
		t.Fatalf("фикстура не знает алгоритма %q — словарь платформы разошёлся с ней", alg)
		return nil
	}
}

func parsePrivate(t *testing.T, alg domain.SigningAlgorithm, pem []byte) any {
	t.Helper()
	var (
		key any
		err error
	)
	switch string(alg) {
	case tokenpolicy.AlgRS256:
		key, err = jwt.ParseRSAPrivateKeyFromPEM(pem)
	case tokenpolicy.AlgES256:
		key, err = jwt.ParseECPrivateKeyFromPEM(pem)
	case tokenpolicy.AlgEdDSA:
		key, err = jwt.ParseEdPrivateKeyFromPEM(pem)
	default:
		t.Fatalf("фикстура не знает алгоритма %q", alg)
	}
	if err != nil {
		t.Fatalf("разбор приватной половины %s: %v", alg, err)
	}
	return key
}

// mint — ВХОД чеканки. Каждое поле — ровно один факт, который отрицание меняет.
type mint struct {
	signer    keyMaterial
	kid       string
	headerAlg string
	typ       string
	crit      []string
	extraHdr  map[string]any

	issuer    string
	audience  []string
	subject   string
	issuedAt  time.Time
	notBefore time.Time
	expiry    time.Time
	claims    map[string]any
}

// goodMint — годное предъявление KAN-VER-01. ЕДИНСТВЕННЫЙ положительный
// контроль семейства: без него все отрицания зеленели бы на установке,
// отвергающей вообще всё.
func goodMint(k keyMaterial, now time.Time) mint {
	return mint{
		signer:    k,
		kid:       k.kid,
		typ:       tokenpolicy.TokenTypeAccess,
		issuer:    testIssuer,
		audience:  []string{testAudience},
		subject:   testSubject,
		issuedAt:  now,
		notBefore: now,
		expiry:    now.Add(10 * time.Minute),
		claims: map[string]any{
			domain.ClaimPrincipalType:    "user",
			domain.ClaimPrincipalID:      testPrincipalID,
			domain.ClaimPrincipalDisplay: testDisplay,
		},
	}
}

func (m mint) sign(t *testing.T) string {
	t.Helper()
	claims := jwt.MapClaims{}
	for k, v := range m.claims {
		claims[k] = v
	}
	claims["iss"] = m.issuer
	claims["sub"] = m.subject
	claims["aud"] = m.audience
	claims["iat"] = m.issuedAt.Unix()
	claims["nbf"] = m.notBefore.Unix()
	claims["exp"] = m.expiry.Unix()
	claims["jti"] = "tok-" + m.subject

	method := signingMethod(t, m.signer.alg)
	tok := jwt.NewWithClaims(method, claims)
	tok.Header["kid"] = m.kid
	if m.typ != "" {
		tok.Header["typ"] = m.typ
	} else {
		delete(tok.Header, "typ")
	}
	if len(m.crit) > 0 {
		tok.Header["crit"] = m.crit
	}
	for k, v := range m.extraHdr {
		tok.Header[k] = v
	}
	if m.headerAlg != "" {
		// Заголовок объявляет ОДИН алгоритм, подпись кладётся ДРУГИМ — это и
		// есть один факт сценария KAN-VER-09.
		tok.Header["alg"] = m.headerAlg
	}
	raw, err := tok.SignedString(parsePrivate(t, m.signer.alg, m.signer.privatePEM))
	if err != nil {
		t.Fatalf("подпись: %v", err)
	}
	return raw
}

// ── подставные зависимости ──────────────────────────────────────────────────

// stubKeys — публикуемый набор. Ошибка — ТРЕТИЙ исход, а не пустой набор:
// нечитаемый набор и пустой дают одно и то же число, если их смешать.
type stubKeys struct {
	mu   sync.Mutex
	keys []domain.PublishedKey
	err  error
	// asked — сколько раз у реестра спросили набор. Без счёта «снимок держит»
	// неотличимо от «снимка нет вовсе».
	asked int
}

func (s *stubKeys) PublishedSet(context.Context) ([]domain.PublishedKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.asked++
	if s.err != nil {
		return nil, s.err
	}
	return append([]domain.PublishedKey(nil), s.keys...), nil
}

func (s *stubKeys) askedTimes() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.asked
}

func (s *stubKeys) set(keys ...domain.PublishedKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys = keys
}

func (s *stubKeys) fail(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.err = err
}

// stubRevocations — авторитет отзыва с управляемым числом обращений: без счёта
// «кеш держит» неотличимо от «читателя отзыва нет вовсе».
type stubRevocations struct {
	mu     sync.Mutex
	before map[string]time.Time
	err    error
	asked  int
}

func (s *stubRevocations) RevokedBefore(_ context.Context, subject string) (time.Time, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.asked++
	if s.err != nil {
		return time.Time{}, false, s.err
	}
	t, ok := s.before[subject]
	return t, ok, nil
}

func (s *stubRevocations) revoke(subject string, at time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.before == nil {
		s.before = map[string]time.Time{}
	}
	s.before[subject] = at
}

func (s *stubRevocations) askedTimes() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.asked
}

// testClock — управляемые часы.
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// ── стенд ───────────────────────────────────────────────────────────────────

type stand struct {
	reader *presentedcred.Reader
	keys   *stubKeys
	revs   *stubRevocations
	clock  *testClock
	key    keyMaterial
	now    time.Time
}

type standOpt func(*presentedcred.Config, *stand)

func withAllowedAlgorithms(algs ...string) standOpt {
	return func(c *presentedcred.Config, _ *stand) { c.AllowedAlgorithms = algs }
}

func withCacheTTL(d time.Duration) standOpt {
	return func(c *presentedcred.Config, _ *stand) { c.RevocationCacheTTL = d }
}

func withExtraPublishedKeys(keys ...domain.PublishedKey) standOpt {
	return func(_ *presentedcred.Config, s *stand) {
		s.keys.keys = append(s.keys.keys, keys...)
	}
}

func newStand(t *testing.T, opts ...standOpt) *stand {
	t.Helper()
	now := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	key := newKey(t, testKID, domain.SigningAlgES256)
	s := &stand{
		keys:  &stubKeys{keys: []domain.PublishedKey{key.published}},
		revs:  &stubRevocations{},
		clock: &testClock{now: now},
		key:   key,
		now:   now,
	}
	cfg := presentedcred.Config{
		Issuer:             testIssuer,
		Audience:           testAudience,
		AllowedAlgorithms:  []string{tokenpolicy.AlgES256},
		Keys:               s.keys,
		Revocations:        s.revs,
		RevocationCacheTTL: 30 * time.Second,
		Clock:              s.clock.Now,
	}
	for _, o := range opts {
		o(&cfg, s)
	}
	r, err := presentedcred.New(cfg)
	if err != nil {
		t.Fatalf("построение читателя: %v", err)
	}
	s.reader = r
	return s
}

// present прогоняет запрос через перехватчик читателя и возвращает личность,
// которую увидел бы обработчик, и отказ.
func (s *stand) present(t *testing.T, raw string, ctxOpts ...func(context.Context) context.Context) (operations.Principal, bool, error) {
	t.Helper()
	ctx := context.Background()
	if raw != "" {
		ctx = metadata.NewIncomingContext(ctx, metadata.Pairs(presentedcred.MetadataKey, "Bearer "+raw))
	}
	for _, o := range ctxOpts {
		ctx = o(ctx)
	}
	var (
		seen    operations.Principal
		present bool
	)
	final := func(c context.Context, _ any) (any, error) {
		seen, present = operations.PrincipalFromContextOK(c)
		return nil, nil
	}
	// Пара извлечения личности здесь ПУСТА, и это верно для предмета: проба
	// утверждает, что читатель отвергает и кого называет, а не как он сложен с
	// парой. Размещение — предмет проб композиционного корня, и там цепочка
	// собирается боевым сборщиком.
	_, err := s.reader.UnaryOver(nil)(ctx, nil,
		&grpc.UnaryServerInfo{FullMethod: "/kaname.cloud.iam.v1.ProjectService/Get"}, final)
	return seen, present, err
}

// good чеканит годное предъявление стенда.
func (s *stand) good(t *testing.T) string {
	t.Helper()
	return goodMint(s.key, s.now).sign(t)
}
