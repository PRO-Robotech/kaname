// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// client_revocation_through_both_sides_integration_test.go — F2-32: отзыв
// доходит и до ВЫДАЧИ, и до ПРЕДЪЯВЛЕНИЯ, и вопрос ставится сквозь обе стороны
// ОДНИМ прогоном.
//
// # Почему двух проб по половине недостаточно
//
// Первая половина — «после отзыва новый токен не выдаётся» — верна и зелена.
// Вторая — «отозванный токен не проходит» — верна и зелена на токене,
// отозванном ПО СУБЪЕКТУ. Целое ломается ровно посередине: если отзыв КЛИЕНТА
// не порождает отсечки для уже выданных ИМ токенов, обе половины остаются
// зелёными, а токен снятого клиента ходит до истечения срока. Это разрыв,
// невидимый ни с одной стороны по отдельности.
//
// # Почему проба утверждает, КАКАЯ запись порождена
//
// Поводов два, и они порождают РАЗНЫЕ записи: отзыв ключа клиента — запись,
// ключуемую клиентом; перевод владельца в не-`ACTIVE` — запись, ключуемую
// субъектом. Отзыв субъекта, порождённый вместо отсечки по клиенту, дал бы
// зелёную пробу при непровязанном ребре «отзыв клиента → уже выданные им
// токены»: токен несёт и субъекта, и клиента, и авторитет спрашивает про
// обоих. Поэтому по каждому поводу утверждается и присутствие СВОЕЙ записи, и
// ОТСУТСТВИЕ чужой.
//
// # Третий повод — истечение клиента — здесь не спрашивается
//
// Он закрыт by construction формой срока (F2-29): момент истечения выданного
// токена не позже момента истечения клиента, поэтому токенов, переживших
// клиента, не существует и читать на предъявлении нечего. Это сказано здесь
// намеренно: молчание читалось бы как забытый повод.
//
// # Почему проба живёт рядом с реестром
//
// Обе стороны спрашиваются против НАСТОЯЩЕЙ базы, и производитель отсечки —
// сама схема. Ставить этот вопрос против дублёра хранилища значило бы измерить
// договорённость между дублёром и пробой.
package pg_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/client_token"
	"github.com/PRO-Robotech/kaname/internal/clientassertion"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/handler/tokenintrospecthttp"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// cutoffCause — повод, порождающий отсечку, и запись, которую он обязан
// породить. Перечень ЗАКРЫТ, и оба повода подаются ОТДЕЛЬНЫМИ входами:
// реализация, читающая один, зелена на половине класса.
type cutoffCause struct {
	name string
	// apply исполняет повод против настоящей базы тем же способом, каким его
	// исполняет продукт.
	apply func(t *testing.T, f assertionFixture, kind domain.AssertionClientKind, clientID string)
	// keyedBy отвечает, какой ключ обязан нести порождённая запись.
	keyedBy func(clientID, ownerID string) (want, mustBeAbsent string)
	// issuanceOutcome — исход ВТОРОЙ половины: чем повод отвечает на попытку
	// выдать этому клиенту НОВЫЙ токен.
	issuanceOutcome func(t *testing.T, f assertionFixture, rig issuanceRig, clientID string)
}

// TestF2_32_RevocationReachesBothIssuanceAndPresentation — сквозь обе стороны.
func TestF2_32_RevocationReachesBothIssuanceAndPresentation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	causes := []cutoffCause{
		{
			name: "отозван ключ клиента",
			apply: func(t *testing.T, f assertionFixture, kind domain.AssertionClientKind, clientID string) {
				revokeRegisteredKey(t, f, kind, clientID)
			},
			keyedBy: func(clientID, ownerID string) (string, string) { return clientID, ownerID },
			issuanceOutcome: func(t *testing.T, f assertionFixture, rig issuanceRig, clientID string) {
				// Снятая строка не резолвится, и выдача до входа не доходит.
				_, err := f.repo.ResolveAssertionClient(context.Background(), clientID)
				require.True(t, domain.IsAssertionClientUnknown(err),
					"после отзыва ключа новый токен выдавать некому, получено: %v", err)
			},
		},
		{
			name:    "владелец переведён в не-ACTIVE",
			apply:   deactivateOwner,
			keyedBy: func(clientID, ownerID string) (string, string) { return ownerID, clientID },
			issuanceOutcome: func(t *testing.T, f assertionFixture, rig issuanceRig, clientID string) {
				row, err := f.repo.ResolveAssertionClient(context.Background(), clientID)
				require.NoError(t, err, "строка клиента обязана остаться видимой")
				require.False(t, row.OwnerActive, "состояние владельца обязано доехать как «не активен»")

				_, outcome, err := rig.uc.Issue(context.Background(), client_token.Input{Client: row})
				require.Error(t, err, "после снятия владельца новый токен не выдаётся")
				require.Equal(t, clientassertion.OutcomeOwnerNotActive, outcome)
			},
		},
	}

	for _, kind := range domain.AssertionClientKinds() {
		for _, cause := range causes {
			t.Run(string(kind)+"/"+cause.name, func(t *testing.T) {
				f := newAssertionFixture(t)
				rig := newIssuanceRig(t)
				revocations := kanamepg.NewMintedTokenRevocationRepo(f.pool)
				h := newIntrospectAuthority(rig, revocations)

				clientID, ownerID := seedAssertionClientOfKind(t, f, kind)

				// ── Положительный контроль. Пока отсечки нет, клиент и
				// выдаёт, и предъявляет успешно. Без него проба зелена на
				// авторитете, отвергающем всё.
				row, err := f.repo.ResolveAssertionClient(context.Background(), clientID)
				require.NoError(t, err)
				out, outcome, err := rig.uc.Issue(context.Background(), client_token.Input{Client: row})
				require.NoError(t, err)
				require.Equal(t, clientassertion.OutcomeAccepted, outcome)
				requireIntrospect(t, h, out.AccessToken, http.StatusOK, true,
					"до отсечки токен обязан проходить")

				// ── Повод порождает отсечку.
				cause.apply(t, f, kind, clientID)

				wantKey, absentKey := cause.keyedBy(clientID, ownerID)
				at, found, err := revocations.RevokedBefore(context.Background(), wantKey)
				require.NoError(t, err)
				require.True(t, found,
					"повод %q обязан породить запись отсечки, ключуемую %s", cause.name, wantKey)
				require.False(t, at.IsZero(), "запись отсечки обязана нести момент")

				_, foundOther, err := revocations.RevokedBefore(context.Background(), absentKey)
				require.NoError(t, err)
				require.False(t, foundOther,
					"повод %q породил запись, ключуемую %s, — не тем ключом: токен несёт оба, "+
						"и подмена ключа даёт зелёную пробу при непровязанном ребре", cause.name, absentKey)

				// ── Сторона ПРЕДЪЯВЛЕНИЯ: ТОТ ЖЕ, ранее выданный токен.
				requireIntrospect(t, h, out.AccessToken, http.StatusOK, false,
					"повод %q обязан снимать уже выданный токен", cause.name)

				// ── Сторона ВЫДАЧИ: новый токен этому клиенту не выдаётся.
				cause.issuanceOutcome(t, f, rig, clientID)
			})
		}
	}
}

// TestF2_32_UnavailableRevocationAuthorityRefuses — fail-closed.
//
// Недоступность хранилища отсечек НЕ ЕСТЬ «не отозван»: это третий исход,
// отличный от обоих суждений. Недоступность здесь НАСТОЯЩАЯ — закрытый пул
// против той же базы, а не дублёр, договорившийся с пробой вернуть ошибку.
//
// «Неопознанный ответ» отдельным входом не подаётся, и это сказано, а не
// умолчано: у типизированного порта ответов ровно два — «отсечка есть» и
// «отсечки нет», — а третий исход и есть ошибка. Входа «ответ не распознан» у
// него нет by construction, и утверждать о нём значило бы завести исход без
// производителя.
func TestF2_32_UnavailableRevocationAuthorityRefuses(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	f := newAssertionFixture(t)
	rig := newIssuanceRig(t)

	clientID, _ := seedAssertionClientOfKind(t, f, domain.AssertionClientUser)
	row, err := f.repo.ResolveAssertionClient(ctx, clientID)
	require.NoError(t, err)
	out, _, err := rig.uc.Issue(ctx, client_token.Input{Client: row})
	require.NoError(t, err)

	// Положительный контроль на доступном хранилище — иначе отказ был бы
	// неотличим от токена, негодного сам по себе.
	requireIntrospect(t, newIntrospectAuthority(rig, kanamepg.NewMintedTokenRevocationRepo(f.pool)),
		out.AccessToken, http.StatusOK, true, "на доступном хранилище токен проходит")

	// Второй пул к ТОЙ ЖЕ базе, закрытый до вопроса.
	dead, err := coredb.NewPool(ctx, f.dsn)
	require.NoError(t, err)
	dead.Close()

	rec := askAuthority(t, newIntrospectAuthority(rig, kanamepg.NewMintedTokenRevocationRepo(dead)), out.AccessToken)
	require.Equal(t, http.StatusServiceUnavailable, rec.Code,
		"недоступность авторитета обязана давать отказ, а не суждение «не отозван»")
}

// deactivateOwner переводит владельца клиента в не-`ACTIVE` тем же способом,
// каким это делает продукт: правкой состояния его строки.
//
// Оба не-`ACTIVE` состояния словаря участия человека подаются в пробе
// состояния владельца (`TestF2_30_...`); здесь предмет — ПОРОЖДЕНИЕ отсечки, и
// достаточно одного перехода из `ACTIVE`.
func deactivateOwner(t *testing.T, f assertionFixture, kind domain.AssertionClientKind, _ string) {
	t.Helper()
	ctx := context.Background()
	switch kind {
	case domain.AssertionClientUser:
		tag, err := f.pool.Exec(ctx,
			`UPDATE kaname.users SET invite_status='BLOCKED' WHERE id=$1 AND invite_status='ACTIVE'`, f.user)
		require.NoError(t, err)
		require.EqualValues(t, 1, tag.RowsAffected(), "переход обязан состояться ровно один раз")
	case domain.AssertionClientServiceAccount:
		tag, err := f.pool.Exec(ctx,
			`UPDATE kaname.service_accounts SET enabled=false WHERE id=$1 AND enabled`, f.sva)
		require.NoError(t, err)
		require.EqualValues(t, 1, tag.RowsAffected(), "переход обязан состояться ровно один раз")
	default:
		t.Fatalf("вид клиента вне закрытого словаря: %q", kind)
	}
}

// seedAssertionClientOfKind кладёт строку клиента названного вида и возвращает
// его идентификатор и идентификатор владельца.
func seedAssertionClientOfKind(t *testing.T, f assertionFixture, kind domain.AssertionClientKind) (clientID, ownerID string) {
	t.Helper()
	switch kind {
	case domain.AssertionClientUser:
		clientID = "uoc_mmmmmmmmmmmmmmmmm"
		f.seedUserClient(t, clientID, "kacho-usr-cutoff", testPublicKeyPEM, "ES256", nil)
		return clientID, f.user
	case domain.AssertionClientServiceAccount:
		clientID = "soc_mmmmmmmmmmmmmmmmm"
		f.seedSAClient(t, clientID, "kacho-sak-cutoff", testPublicKeyPEM, "ES256")
		return clientID, f.sva
	default:
		t.Fatalf("вид клиента вне закрытого словаря: %q", kind)
		return "", ""
	}
}

// newIntrospectAuthority — НАСТОЯЩИЙ авторитет отзыва: тот же набор ключей, что
// подписывает, и названное хранилище отсечек.
func newIntrospectAuthority(rig issuanceRig, revocations tokenintrospecthttp.RevocationReader) *tokenintrospecthttp.Handler {
	return tokenintrospecthttp.NewHandler(tokenintrospecthttp.Config{
		Issuer:      assertionIssuer,
		Keys:        rig.keys,
		Revocations: revocations,
		Clock:       time.Now,
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
}

// askAuthority спрашивает авторитет о токене.
func askAuthority(t *testing.T, h *tokenintrospecthttp.Handler, token string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{"token": {token}}
	req := httptest.NewRequest(http.MethodPost, tokenintrospecthttp.IntrospectPath, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// requireIntrospect утверждает ПАРУ: код ответа и суждение.
func requireIntrospect(t *testing.T, h *tokenintrospecthttp.Handler, token string, wantCode int, wantActive bool, msg string, args ...any) {
	t.Helper()
	rec := askAuthority(t, h, token)
	explain := fmt.Sprintf(msg, args...)
	require.Equal(t, wantCode, rec.Code, explain)
	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Equal(t, wantActive, body["active"], explain)
}
