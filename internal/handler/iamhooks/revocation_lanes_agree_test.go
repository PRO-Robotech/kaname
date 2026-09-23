// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// revocation_lanes_agree_test.go — отсечка отзыва-всех утверждается
// СРАВНЕНИЕМ полос выдачи, а не пробой каждой по отдельности (задача
// kaname#379).
//
// # Почему сравнением
//
// Токен человеку выдают три полосы: хук выпуска, хук обновления и наш
// собственный токен-эндпоинт. Проба каждой полосы по отдельности требует знать,
// каким свойство ДОЛЖНО быть, — и каждая полоса по отдельности выглядела бы
// исправной со своими зелёными пробами. Неверной была бы их РАЗНИЦА. Сравнение
// спрашивает другое: один принципал, одна отсечка — один вердикт на всех
// полосах, предъявляющих одно и то же полномочие.
//
// # Осей сравнения ДВЕ, и они охватывают разное
//
// Отсечка взвешивается против момента, от которого считается полномочие, а он
// у полномочий разный. У КЛЮЧА человека это момент его выдачи — ключ
// предъявляют хук выпуска и наш эндпоинт. У СЕССИИ человека — момент её входа,
// и сессию предъявляют хук выпуска и хук обновления; у эндпоинта сессии нет, у
// хука обновления нет ключа (выдача по ключу не выдаёт обновляемого токена).
// Свести оси в одну значило бы либо потребовать от полосы полномочия, которого
// она не предъявляет, либо оставить полосу вне сравнения. Хук выпуска стоит на
// обеих осях — это одна полоса с двумя видами полномочия.
//
// # Что здесь ОДНО на все полосы
//
// Служба состава, её порты, строка ключа, момент сессии, отсечка и её читатель
// — один экземпляр на все полосы входа. Два экземпляра сверяли бы два разных
// принципала и были бы зелены при любом расхождении полос.
//
// # Перепись печатает ОБЕ величины — и обе выводит из исполненного
//
// «Полос N · сверяют отсечку M»: N — полосы, которые действительно исполнились,
// M — те из них, чей вердикт отсечка СМЕНИЛА (выдача без отсечки, отказ при
// запрещающей). Числа не выписываются: полоса, которую забыли завести, или
// полоса, не читающая отсечку, меняют их, а литерал — нет. Ось, сличившая
// меньше двух полос, — не сравнение, а проба одной полосы, и падает с названной
// причиной; ни одной исполненной полосы — «не выполнилось», а не зелёное.
package iamhooks_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/client_token"
	"github.com/PRO-Robotech/kaname/internal/clientassertion"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/handler/iamhooks"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/PRO-Robotech/kaname/internal/tokensigner"
)

// Оба порта — одна форма: один и тот же читатель подаётся обеим полосам, и
// сборка это требует, а не предполагает.
var _ client_token.RevocationLookup = iamhooks.UserRevocationLookup(nil)
var _ iamhooks.UserRevocationLookup = client_token.RevocationLookup(nil)

const (
	laneUserMirror = "cap-machine"
	laneSAMirror   = "cap-machine-sa"
	laneOurUserKey = "uoc_01abcdefghjkmnpqx"
	laneOurSAKey   = "soc_01abcdefghjkmnpqx"
	laneSAID       = "sva_01abcdefghjkmnpqx"
)

// laneOwnClients — чтение строки реестра по НАШЕМУ идентификатору. Отдаёт ТЕ ЖЕ
// строки, что порты прежнего пути отдают по зеркальному значению.
type laneOwnClients struct {
	uoc domain.UserOAuthClient
	soc domain.ServiceAccountOAuthClient
}

func (l laneOwnClients) GetUserToken(_ context.Context, id domain.UserOAuthClientID) (domain.UserOAuthClient, error) {
	if id != l.uoc.ID {
		return domain.UserOAuthClient{}, errors.New("lane own clients: unknown user-token client")
	}
	return l.uoc, nil
}

func (l laneOwnClients) GetSAKey(_ context.Context, id domain.SAOAuthClientID) (domain.ServiceAccountOAuthClient, error) {
	if id != l.soc.ID {
		return domain.ServiceAccountOAuthClient{}, errors.New("lane own clients: unknown sa-key client")
	}
	return l.soc, nil
}

// laneSigner — подписант нашей полосы. Предмет пробы — вердикт выдачи, а не
// подпись; подпись закреплена своими пробами подписанта.
type laneSigner struct{}

func (laneSigner) Sign(_ context.Context, req tokensigner.Request) (tokensigner.Token, error) {
	return tokensigner.Token{Token: "signed-for-" + req.Subject}, nil
}
func (laneSigner) Issuer() string { return "https://kaname.kacho.local" }

// laneInput — один вход сравнения: одна отсечка и одно полномочие.
type laneInput struct {
	name string
	// kind — вид ключа (ось ключа); на оси сессии не читается.
	kind domain.AssertionClientKind
	// cutoff — отсечка отзыва-всех; nil — отсечки нет.
	cutoff *time.Time
	// lookupErr — отказ хранилища отсечек.
	lookupErr error
	// sessionWithoutInstant — сессия не называет момента входа (ось сессии).
	sessionWithoutInstant bool
	wantIssue             bool
}

// revocationLane — полоса выдачи глазами этой пробы: выдала ли она токен на
// этом входе.
type revocationLane struct {
	name  string
	issue func(t *testing.T, in laneInput, revs *fakeRevocations) bool
}

// laneObservation — что полоса показала на всех входах оси, вместе.
type laneObservation struct {
	ran             bool
	issuedOnControl bool // выдала без отсечки и при отвечающем хранилище
	refusedByCutoff bool // отказала при отсечке и отвечающем хранилище
}

// compareLanes гоняет каждый вход по всем полосам оси, требует ожидаемого
// вердикта и совпадения вердиктов полос, и отдаёт наблюдения по полосам —
// перепись выводится из них, а не выписывается.
func compareLanes(
	t *testing.T, axis string, lanes []revocationLane, cases []laneInput, seen map[string]*laneObservation,
) (compared int) {
	t.Helper()
	if len(lanes) == 0 {
		t.Fatalf("ось %q: не заведено ни одной полосы — сравнение не выполнилось, это не зелёное", axis)
	}
	for _, c := range cases {
		t.Run(axis+": "+c.name, func(t *testing.T) {
			// Одна отсечка, один читатель — всем полосам входа.
			revs := newFakeRevocations()
			revs.userBeforeErr = c.lookupErr
			if c.cutoff != nil {
				revs.MarkUserRevokedBefore(cutoffUserID, *c.cutoff)
			}
			verdicts := make(map[string]bool, len(lanes))
			for _, l := range lanes {
				issued := l.issue(t, c, revs)
				verdicts[l.name] = issued
				o := seen[l.name]
				if o == nil {
					o = &laneObservation{}
					seen[l.name] = o
				}
				o.ran = true
				if c.lookupErr == nil && c.cutoff == nil && issued {
					o.issuedOnControl = true
				}
				if c.lookupErr == nil && c.cutoff != nil && !issued {
					o.refusedByCutoff = true
				}
				require.Equalf(t, c.wantIssue, issued, "полоса %q: выдача=%v", l.name, issued)
			}
			first := verdicts[lanes[0].name]
			for _, l := range lanes[1:] {
				require.Equalf(t, first, verdicts[l.name],
					"полосы разошлись на входе %q: %q сказала %v, %q сказала %v — расхождение полос "+
						"одного механизма обязано быть решением, а не побочным эффектом",
					c.name, lanes[0].name, first, l.name, verdicts[l.name])
			}
		})
		compared++
	}
	return compared
}

// ranOn — сколько полос оси действительно исполнилось.
func ranOn(lanes []revocationLane, seen map[string]*laneObservation) int {
	n := 0
	for _, l := range lanes {
		if o := seen[l.name]; o != nil && o.ran {
			n++
		}
	}
	return n
}

// TestRevokeAllCutoff_BothIssuanceLanesAgree — один принципал, одна отсечка,
// один вердикт на каждой полосе, предъявляющей то же полномочие: по оси ключа
// (хук выпуска и наш эндпоинт) и по оси сессии (хук выпуска и хук обновления).
func TestRevokeAllCutoff_BothIssuanceLanesAgree(t *testing.T) {
	keyIssued := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	unavailable := errors.New("user_token_revocations: backend unavailable")
	at := func(t time.Time) *time.Time { return &t }

	// Момент входа сессии — из дословной записи поставщика, одна величина на
	// обе полосы сессии: запись обновления получает его же.
	sessionAt := capturedAuthTime(t, capturedBody(t, "provider-token-hook-authorization-code.json"))

	keyCases := []laneInput{
		{name: "ключ человека, отсечки нет", kind: domain.AssertionClientUser, wantIssue: true},
		{name: "ключ человека выдан до отсечки", kind: domain.AssertionClientUser, cutoff: at(keyIssued.Add(time.Hour))},
		{name: "ключ человека выдан ровно в момент отсечки", kind: domain.AssertionClientUser, cutoff: at(keyIssued)},
		{name: "ключ человека выдан после отсечки", kind: domain.AssertionClientUser,
			cutoff: at(keyIssued.Add(-time.Hour)), wantIssue: true},
		{name: "хранилище отсечек не ответило", kind: domain.AssertionClientUser, lookupErr: unavailable},
		{name: "ключ служебной учётки при отсечке человека", kind: domain.AssertionClientServiceAccount,
			cutoff: at(keyIssued.Add(365 * 24 * time.Hour)), wantIssue: true},
	}
	sessionCases := []laneInput{
		{name: "сессия человека, отсечки нет", wantIssue: true},
		{name: "сессия вошла до отсечки", cutoff: at(sessionAt.Add(time.Hour))},
		{name: "сессия вошла ровно в момент отсечки", cutoff: at(sessionAt)},
		{name: "сессия вошла после отсечки", cutoff: at(sessionAt.Add(-time.Hour)), wantIssue: true},
		{name: "сессия не назвала момента входа при отсечке", cutoff: at(sessionAt), sessionWithoutInstant: true},
		{name: "хранилище отсечек не ответило", lookupErr: unavailable},
	}

	users := cutoffUser()
	uoc := domain.UserOAuthClient{
		CredentialKind: domain.CredentialKindKeypair,
		ID:             laneOurUserKey,
		UserID:         cutoffUserID,
		OAuthClientID:  laneUserMirror,
		CreatedAt:      keyIssued,
	}
	soc := domain.ServiceAccountOAuthClient{
		CredentialKind: domain.CredentialKindKeypair,
		ID:             laneOurSAKey,
		SvaID:          laneSAID,
		OAuthClientID:  laneSAMirror,
	}
	sa := domain.ServiceAccount{ID: laneSAID, AccountID: cutoffAccountID, Enabled: true}

	// Один экземпляр службы состава на все полосы.
	enricher := service.NewTokenEnrichmentService(
		service.TokenEnrichmentConfig{Domain: "api.test.cloud", HydraIssuer: "https://hydra.test.cloud"},
		users,
	).
		WithUserTokenPort(&fakeUserTokenPort{client: uoc, user: users.users[0]}).
		WithSAPort(&fakeIssuanceSAPort{clientID: laneSAMirror, mapping: soc, sa: sa}).
		WithOwnClientPort(laneOwnClients{uoc: uoc, soc: soc})
	discard := slog.New(slog.NewTextHandler(io.Discard, nil))
	tokenHook := func(revs *fakeRevocations) *iamhooks.TokenHookHandler {
		return iamhooks.NewTokenHookHandler(
			iamhooks.TokenHookConfig{
				HookSharedSecret: issuanceHookSecret,
				Domain:           "api.test.cloud",
				HydraIssuer:      "https://hydra.test.cloud",
			},
			enricher, revs, &fakeAudit{}, discard,
		)
	}
	// hookIssued — выдал ли хук: ответ выдачи И непустой состав; всякий иной
	// ответ, кроме отказа, — находка, а не «не выдал».
	hookIssued := func(t *testing.T, w *httptest.ResponseRecorder, lane string) bool {
		t.Helper()
		_, minted := mintedClaims(t, w)
		issued := w.Code == http.StatusOK && minted
		require.Truef(t, issued || w.Code == http.StatusForbidden,
			"%s ответил не выдачей и не отказом: %d %s", lane, w.Code, w.Body.String())
		return issued
	}
	stampSession := func(t *testing.T, body map[string]any, in laneInput) {
		t.Helper()
		if in.sessionWithoutInstant {
			// Нулевой момент — тот, что поставщик сам шлёт для сессии, которую
			// не аутентифицировал.
			sessionClaims(t, body)["auth_time"] = "0001-01-01T00:00:00Z"
			return
		}
		sessionClaims(t, body)["auth_time"] = sessionAt.Format(time.RFC3339)
	}

	const (
		laneTokenHook   = "хук выпуска"
		laneRefreshHook = "хук обновления"
		laneEndpoint    = "наш токен-эндпоинт"
	)
	keyLanes := []revocationLane{
		{name: laneTokenHook, issue: func(t *testing.T, in laneInput, revs *fakeRevocations) bool {
			t.Helper()
			mirror := laneUserMirror
			if in.kind == domain.AssertionClientServiceAccount {
				mirror = laneSAMirror
			}
			body := capturedBody(t, "provider-token-hook-client-credentials.json")
			machineShaped(t, body, mirror)
			return hookIssued(t, postCaptured(t, tokenHook(revs), "/iam/v1/hooks/token", body), laneTokenHook)
		}},
		{name: laneEndpoint, issue: func(t *testing.T, in laneInput, revs *fakeRevocations) bool {
			t.Helper()
			uc, err := client_token.New(client_token.Config{
				AllowedAudiences: []string{"https://api.test.cloud"},
				DefaultAudience:  "https://api.test.cloud",
				TokenTTL:         15 * time.Minute,
				Clock:            func() time.Time { return keyIssued.Add(48 * time.Hour) },
			}, laneSigner{}, enricher, revs)
			require.NoError(t, err)
			cl := domain.AssertionClient{ID: laneOurUserKey, Kind: in.kind, OwnerID: cutoffUserID, OwnerActive: true}
			if in.kind == domain.AssertionClientServiceAccount {
				cl.ID, cl.OwnerID = laneOurSAKey, laneSAID
			}
			out, outcome, err := uc.Issue(context.Background(), client_token.Input{Client: cl})
			if err != nil {
				return false
			}
			require.Equal(t, clientassertion.OutcomeAccepted, outcome)
			require.NotEmpty(t, out.AccessToken)
			return true
		}},
	}
	sessionLanes := []revocationLane{
		{name: laneTokenHook, issue: func(t *testing.T, in laneInput, revs *fakeRevocations) bool {
			t.Helper()
			body := capturedBody(t, "provider-token-hook-authorization-code.json")
			stampSession(t, body, in)
			return hookIssued(t, postCaptured(t, tokenHook(revs), "/iam/v1/hooks/token", body), laneTokenHook)
		}},
		{name: laneRefreshHook, issue: func(t *testing.T, in laneInput, revs *fakeRevocations) bool {
			t.Helper()
			body := capturedBody(t, "provider-refresh-hook.json")
			stampSession(t, body, in)
			h := iamhooks.NewRefreshHookHandler(
				iamhooks.RefreshHookConfig{
					HookSharedSecret: "secret",
					Domain:           "api.test.cloud",
					HydraIssuer:      "https://hydra.test.cloud",
				},
				users, enricher, revs, &fakeAudit{}, discard,
			)
			return hookIssued(t, postCapturedRefresh(t, h, body), laneRefreshHook)
		}},
	}

	seen := map[string]*laneObservation{}
	comparedKey := compareLanes(t, "ключ", keyLanes, keyCases, seen)
	comparedSession := compareLanes(t, "сессия", sessionLanes, sessionCases, seen)

	// Перепись — из исполненного.
	ran, honoring := 0, 0
	names := make([]string, 0, len(seen))
	for name, o := range seen {
		names = append(names, name)
		if !o.ran {
			continue
		}
		ran++
		if o.issuedOnControl && o.refusedByCutoff {
			honoring++
		}
	}
	sort.Strings(names)
	ranKey, ranSession := ranOn(keyLanes, seen), ranOn(sessionLanes, seen)
	t.Logf("перепись: полос выдачи исполнено %d %v · сверяют отсечку %d · по осям: ключ %d, сессия %d "+
		"· входов сличено: ключ %d, сессия %d", ran, names, honoring, ranKey, ranSession, comparedKey, comparedSession)

	require.NotZerof(t, ran, "не исполнилось ни одной полосы — перепись не выполнилась, это не зелёное")
	require.GreaterOrEqualf(t, ranKey, 2,
		"ось ключа сличила %d полос: сравнение одной полосы с самой собой ничего не сравнивает", ranKey)
	require.GreaterOrEqualf(t, ranSession, 2,
		"ось сессии сличила %d полос: сравнение одной полосы с самой собой ничего не сравнивает", ranSession)
	require.Equalf(t, ran, honoring,
		"исполнилось полос %d, а вердикт отсечка сменила у %d: полоса, чей вердикт от отсечки не меняется, "+
			"отсечку не читает", ran, honoring)
}
