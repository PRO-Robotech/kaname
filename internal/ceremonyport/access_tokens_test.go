// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// access_tokens_test.go — обязанности адаптера порта выпуска и опознания токена
// доступа (задача PRO-Robotech/kaname#396, пункты K2, K3, K4).
package ceremonyport_test

import (
	"bytes"
	"context"
	"errors"
	"log"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/oauthceremony"
	"github.com/PRO-Robotech/corelib/tokenpolicy"

	"github.com/PRO-Robotech/kaname/internal/tokenrevocation"
)

// unverifiedClaims разбирает выпущенный токен БЕЗ проверки подписи — пробе
// выпуска нужен состав, а не вердикт.
func unverifiedClaims(t *testing.T, raw string) (map[string]any, jwt.MapClaims) {
	t.Helper()
	claims := jwt.MapClaims{}
	tok, _, err := jwt.NewParser().ParseUnverified(raw, claims)
	require.NoError(t, err)
	return tok.Header, claims
}

// ── K2: выпуск ──────────────────────────────────────────────────────────────

// Утверждения о доступе берутся ТОЛЬКО из выданного: согласие уже просьбы —
// в токене выданное; протокольные поля запроса, запрошенное и утверждения
// сеанса в токен не идут. Состав ЗАКРЫТ: утверждение сверх перечня — находка.
func TestIssue_K2_ClaimsComeOnlyFromWhatWasGranted(t *testing.T) {
	ring := newKeyRing(t, testKID)
	a := newAccessTokens(t, ring, time.Now)
	grant := grantWithin(time.Now().Add(10 * time.Minute))

	issued, err := a.IssueAccessToken(context.Background(), grant)
	require.NoError(t, err)
	header, claims := unverifiedClaims(t, issued.Token)

	require.Equal(t, tokenpolicy.TokenTypeAccess, header["typ"])
	require.Equal(t, testSubject, claims["sub"], "субъект — не субъект сеанса гранта")
	require.Equal(t, testClientID, claims["client_id"], "клиент — не клиент гранта")
	require.Equal(t, testFamily, claims[tokenrevocation.FamilyKeyClaim],
		"токен не несёт ключа семейства — отзыв семейства он пережил бы до exp")
	require.Equal(t, "openid offline", claims["scope"], "область — не выданная")
	require.ElementsMatch(t, []any{testAudience}, claims["aud"], "получатели — не выданные")

	allowed := []string{"iss", "sub", "aud", "iat", "nbf", "exp", "jti", "client_id", "scope",
		tokenrevocation.FamilyKeyClaim}
	for name := range claims {
		require.Truef(t, slices.Contains(allowed, name),
			"утверждение %q вне закрытого состава выпуска %v", name, allowed)
	}
	raw := issued.Token
	_, payload := unverifiedClaims(t, raw)
	for _, leaked := range []string{"requested-only-scope", "requested-only.kacho.local",
		"form-only-marker", "form-only-challenge-value", "session-only-username",
		"session-only-value", "session_only_claim"} {
		for name, v := range payload {
			require.NotContainsf(t, strings.ToLower(asText(v)), leaked,
				"утверждение %q несёт %q — не выданное, а запрошенное или протокольное", name, leaked)
		}
	}
}

// Близнец K2: согласие РАВНО просьбе — в токене то же выданное. Отрицание выше
// зеленело бы на выпуске, не кладущем области вовсе.
func TestIssue_K2_TwinGrantEqualToRequestCarriesTheSame(t *testing.T) {
	ring := newKeyRing(t, testKID)
	a := newAccessTokens(t, ring, time.Now)
	grant := grantWithin(time.Now().Add(10 * time.Minute))
	grant.RequestedScopes = slices.Clone(grant.GrantedScopes)
	grant.RequestedAudiences = slices.Clone(grant.GrantedAudiences)

	issued, err := a.IssueAccessToken(context.Background(), grant)
	require.NoError(t, err)
	_, claims := unverifiedClaims(t, issued.Token)
	require.Equal(t, "openid offline", claims["scope"])
	require.ElementsMatch(t, []any{testAudience}, claims["aud"])
}

// Момент выпуска — не раньше начала секунды вызова, срок — не позже границы,
// и отданные величины — ровно те, что легли в токен.
func TestIssue_K2_IssuedAtIsNotBeforeTheCallAndExpiryWithinTheBound(t *testing.T) {
	ring := newKeyRing(t, testKID)
	a := newAccessTokens(t, ring, time.Now)
	bound := time.Now().Add(7*time.Minute + 300*time.Millisecond)

	callSecond := time.Now().Truncate(time.Second)
	issued, err := a.IssueAccessToken(context.Background(), grantWithin(bound))
	require.NoError(t, err)
	_, claims := unverifiedClaims(t, issued.Token)

	require.False(t, issued.IssuedAt.Before(callSecond),
		"iat %s раньше секунды вызова %s", issued.IssuedAt, callSecond)
	require.False(t, issued.ExpiresAt.After(bound), "exp %s позже границы %s", issued.ExpiresAt, bound)
	require.True(t, issued.ExpiresAt.After(issued.IssuedAt), "exp не позже iat")
	require.Equal(t, int64(claims["iat"].(float64)), issued.IssuedAt.Unix(), "отданный iat не равен лежащему в токене")
	require.Equal(t, int64(claims["exp"].(float64)), issued.ExpiresAt.Unix(), "отданный exp не равен лежащему в токене")
	require.Zero(t, issued.ExpiresAt.Nanosecond(), "отданный exp несёт долю секунды, которой в токене нет")
	require.Equal(t, claims["jti"], issued.ID, "отданный идентификатор не равен jti токена")
}

// Выпуск без предмета — отказ, а не токен: без границы срока, без ключа
// семейства, без субъекта, без выданного получателя (незаданный получатель
// означал бы «любой»).
func TestIssue_K2_RefusesAGrantItCannotHonour(t *testing.T) {
	ring := newKeyRing(t, testKID)
	a := newAccessTokens(t, ring, time.Now)
	bound := time.Now().Add(10 * time.Minute)

	for _, tc := range []struct {
		name  string
		shape func(*oauthceremony.GrantRecord)
	}{
		{"граница срока не названа", func(g *oauthceremony.GrantRecord) {
			g.Session.ExpiresAt = map[oauthceremony.TokenKind]time.Time{}
		}},
		{"граница срока уже прошла", func(g *oauthceremony.GrantRecord) {
			g.Session.ExpiresAt[oauthceremony.TokenKindAccess] = time.Now().Add(-time.Minute)
		}},
		{"ключа семейства нет", func(g *oauthceremony.GrantRecord) { g.GrantID = "" }},
		{"субъекта нет", func(g *oauthceremony.GrantRecord) { g.Session.Subject = "" }},
		{"клиента нет", func(g *oauthceremony.GrantRecord) { g.ClientID = "" }},
		{"получатель не выдан", func(g *oauthceremony.GrantRecord) { g.GrantedAudiences = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			grant := grantWithin(bound)
			tc.shape(&grant)
			issued, err := a.IssueAccessToken(context.Background(), grant)
			require.Error(t, err)
			require.Empty(t, issued.Token, "при отказе выпуска уехал токен")
		})
	}

	t.Run("близнец: полный грант выпускается", func(t *testing.T) {
		issued, err := a.IssueAccessToken(context.Background(), grantWithin(bound))
		require.NoError(t, err)
		require.NotEmpty(t, issued.Token)
	})
}

// ── K3: опознание ───────────────────────────────────────────────────────────

// genuineClaims — состав токена этого издателя; craft подписывает его так, как
// назовёт случай.
func genuineClaims(iat time.Time) jwt.MapClaims {
	return jwt.MapClaims{
		"iss": testIssuer, "sub": testSubject, "aud": []string{testAudience},
		"iat": iat.Unix(), "nbf": iat.Unix(), "exp": iat.Add(5 * time.Minute).Unix(),
		"jti": "tok0123456789abcdefg", "client_id": testClientID,
		tokenrevocation.FamilyKeyClaim: testFamily,
	}
}

func signES(t *testing.T, ring *keyRing, kid string, claims jwt.MapClaims, typ string) string {
	t.Helper()
	key, err := jwt.ParseECPrivateKeyFromPEM(ring.mat.PrivateKeyPEM)
	require.NoError(t, err)
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["kid"] = kid
	if typ != "" {
		tok.Header["typ"] = typ
	}
	raw, err := tok.SignedString(key)
	require.NoError(t, err)
	return raw
}

// Каждый случай перечня K3 рядом со своим близнецом: подлинный токен того же
// состава опознаётся своим jti. Без близнеца отрицание зеленело бы на
// адаптере, не опознающем ничего.
func TestIdentify_K3_EveryCaseBesideItsTwin(t *testing.T) {
	ring := newKeyRing(t, testKID)
	a := newAccessTokens(t, ring, time.Now)
	now := time.Now()

	genuine := signES(t, ring, testKID, genuineClaims(now), tokenpolicy.TokenTypeAccess)
	jti, err := a.IdentifyAccessToken(context.Background(), genuine)
	require.NoError(t, err, "близнец: подлинный токен не опознан")
	require.Equal(t, "tok0123456789abcdefg", jti)

	t.Run("подлинный ИСТЁКШИЙ опознаётся своим jti — срок судит церемония", func(t *testing.T) {
		past := now.Add(-3 * time.Hour)
		expired := signES(t, ring, testKID, genuineClaims(past), tokenpolicy.TokenTypeAccess)
		got, err := a.IdentifyAccessToken(context.Background(), expired)
		require.NoError(t, err, "истёкший подлинный токен не опознан — отзыв по нему стал бы успехом без действия")
		require.Equal(t, "tok0123456789abcdefg", got)
	})

	t.Run("подлинный, выпущенный самим адаптером, опознаётся", func(t *testing.T) {
		issued, err := a.IssueAccessToken(context.Background(), grantWithin(now.Add(10*time.Minute)))
		require.NoError(t, err)
		got, err := a.IdentifyAccessToken(context.Background(), issued.Token)
		require.NoError(t, err)
		require.Equal(t, issued.ID, got)
	})

	foreign := newKeyRing(t, testKID) // тот же kid, чужой ключ
	unknown := newKeyRing(t, "kaname-b")
	hsKey := []byte(ring.mat.PublicKeyPEM)

	refusals := []struct {
		name  string
		token func(t *testing.T) string
	}{
		{"чужая подпись под нашим kid", func(t *testing.T) string {
			return signES(t, foreign, testKID, genuineClaims(now), tokenpolicy.TokenTypeAccess)
		}},
		{"неизвестный kid", func(t *testing.T) string {
			return signES(t, unknown, "kaname-b", genuineClaims(now), tokenpolicy.TokenTypeAccess)
		}},
		{"alg none", func(t *testing.T) string {
			tok := jwt.NewWithClaims(jwt.SigningMethodNone, genuineClaims(now))
			tok.Header["kid"] = testKID
			tok.Header["typ"] = tokenpolicy.TokenTypeAccess
			raw, err := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
			require.NoError(t, err)
			return raw
		}},
		{"HS256 публичной половиной как секретом", func(t *testing.T) string {
			tok := jwt.NewWithClaims(jwt.SigningMethodHS256, genuineClaims(now))
			tok.Header["kid"] = testKID
			tok.Header["typ"] = tokenpolicy.TokenTypeAccess
			raw, err := tok.SignedString(hsKey)
			require.NoError(t, err)
			return raw
		}},
		{"битая форма", func(*testing.T) string { return "eyJhbGciOiJFUzI1NiJ9.не-json.подпись" }},
		{"три пустых сегмента", func(*testing.T) string { return ".." }},
		{"непрозрачное значение (вид токена обновления)", func(*testing.T) string {
			return "3f1c5e0a9b7d4c2e8f6a1b3c5d7e9f0a2b4c6d8e0f1a3b5c7d9e1f3a5b7c9d0e"
		}},
		{"подделанная полезная нагрузка при подлинной подписи", func(t *testing.T) string {
			parts := strings.Split(genuine, ".")
			other := strings.Split(signES(t, ring, testKID, jwt.MapClaims{
				"iss": testIssuer, "sub": "usr-zzzzzzzzzzzzzzzzz", "jti": "tokzzzzzzzzzzzzzzzzz",
				"iat": now.Unix(), "exp": now.Add(time.Minute).Unix(),
			}, tokenpolicy.TokenTypeAccess), ".")
			return parts[0] + "." + other[1] + "." + parts[2]
		}},
		{"наш ключ, чужой издатель", func(t *testing.T) string {
			c := genuineClaims(now)
			c["iss"] = "https://other.example"
			return signES(t, ring, testKID, c, tokenpolicy.TokenTypeAccess)
		}},
		{"наш ключ, не тот вид токена", func(t *testing.T) string {
			return signES(t, ring, testKID, genuineClaims(now), "JWT")
		}},
		{"наш ключ, без jti", func(t *testing.T) string {
			c := genuineClaims(now)
			delete(c, "jti")
			return signES(t, ring, testKID, c, tokenpolicy.TokenTypeAccess)
		}},
	}
	for _, tc := range refusals {
		t.Run(tc.name, func(t *testing.T) {
			got, err := a.IdentifyAccessToken(context.Background(), tc.token(t))
			require.ErrorIs(t, err, oauthceremony.ErrGrantNotFound,
				"случай K3 не назван «не наш»: %v", err)
			require.Empty(t, got)
			for _, verdict := range []error{oauthceremony.ErrTokenExpired, oauthceremony.ErrInactiveToken,
				oauthceremony.ErrTokenSignatureMismatch} {
				require.NotErrorIs(t, err, verdict, "порт вернул вердикт о токене вместо «не наш»")
			}
		})
	}
}

// Опознание, которое не состоялось, не вправе стать «не наш»: отзыв ответил бы
// успехом, не сняв живой токен. Близнец — тот же токен при исправном наборе.
func TestIdentify_K3_UnavailableKeySetIsAnOperationFailure(t *testing.T) {
	ring := newKeyRing(t, testKID)
	a := newAccessTokens(t, ring, time.Now)
	token := signES(t, ring, testKID, genuineClaims(time.Now()), tokenpolicy.TokenTypeAccess)

	_, err := a.IdentifyAccessToken(context.Background(), token)
	require.NoError(t, err, "близнец: при исправном наборе подлинный токен не опознан")

	ring.setErr = errors.New("набор ключей недоступен")
	_, err = a.IdentifyAccessToken(context.Background(), token)
	require.Error(t, err)
	require.NotErrorIs(t, err, oauthceremony.ErrGrantNotFound,
		"сбой набора прочитан как «не наш» — отзыв по живому токену стал бы успехом без действия")

	ring.setErr = nil
	ring.published[0].PublicKeyPEM = "-----BEGIN PUBLIC KEY-----\nне-ключ\n-----END PUBLIC KEY-----\n"
	_, err = a.IdentifyAccessToken(context.Background(), token)
	require.Error(t, err)
	require.NotErrorIs(t, err, oauthceremony.ErrGrantNotFound,
		"испорченный СВОЙ ключ набора прочитан как «не наш»: это наша поломка, а не чужой токен")
}

// ── K4: предъявленное значение не пишется ни в журнал, ни в текст отказа ──────

// captureLogs перенаправляет общий журнал процесса в буфер на время пробы.
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prevSlog := slog.Default()
	prevLog := log.Writer()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	log.SetOutput(&buf)
	t.Cleanup(func() {
		slog.SetDefault(prevSlog)
		log.SetOutput(prevLog)
	})
	return &buf
}

// fragments — предъявленное значение и его части: целиком, по сегментам и
// окнами. Часть секрета в тексте — такая же утечка, как весь секрет.
func fragments(token string) []string {
	out := []string{token}
	for _, seg := range strings.Split(token, ".") {
		if len(seg) >= 12 {
			out = append(out, seg)
		}
	}
	for i := 0; i+12 <= len(token); i += 6 {
		out = append(out, token[i:i+12])
	}
	return out
}

func TestIdentify_K4_PresentedValueReachesNeitherLogNorError(t *testing.T) {
	ring := newKeyRing(t, testKID)
	a := newAccessTokens(t, ring, time.Now)
	logs := captureLogs(t)

	genuine := signES(t, ring, testKID, genuineClaims(time.Now()), tokenpolicy.TokenTypeAccess)
	parts := strings.Split(genuine, ".")
	tampered := parts[0] + "." + parts[1] + "." + strings.Repeat("A", len(parts[2]))
	opaque := "3f1c5e0a9b7d4c2e8f6a1b3c5d7e9f0a2b4c6d8e0f1a3b5c7d9e1f3a5b7c9d0e"

	cases := []struct {
		name   string
		token  string
		broken bool
	}{
		{"JWT с чужой подписью", tampered, false},
		{"непрозрачное значение", opaque, false},
		{"JWT при недоступном наборе", genuine, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ring.setErr = nil
			if tc.broken {
				ring.setErr = errors.New("набор ключей недоступен")
			}
			logs.Reset()
			_, err := a.IdentifyAccessToken(context.Background(), tc.token)
			require.Error(t, err, "условие не создано: опознание не отказало")
			for _, frag := range fragments(tc.token) {
				require.NotContains(t, err.Error(), frag, "текст отказа несёт предъявленное значение")
				require.NotContains(t, logs.String(), frag, "журнал несёт предъявленное значение")
			}
		})
	}
}

func asText(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case []any:
		var b strings.Builder
		for _, e := range x {
			b.WriteString(asText(e))
			b.WriteByte(' ')
		}
		return b.String()
	default:
		return ""
	}
}
