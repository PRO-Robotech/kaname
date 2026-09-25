// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// client_token_revoke_all_integration_test.go — отсечка отзыва-всех владельца
// действует на НАШЕЙ полосе выдачи тем же правилом, что на полосе хука, против
// настоящей базы и настоящего контура (задача kaname#379).
//
// # Что здесь утверждается
//
// Наблюдаемое, а не «порт спросили»: после того как отсечка владельца
// закоммичена — любым путём записи, — тот же ключ пользователя, предъявленный
// НАШЕМУ эндпоинту, не получает токена; ответ отказа совпадает с ответом
// всякого другого отказа, и токена в нём нет.
//
// # Почему каждый путь записи подан отдельно — и откуда их перечень
//
// Утверждается свойство «любая записанная отсечка владельца», а не перечень
// тех, кто её пишет: вариантов использования, выводящих человека отовсюду,
// несколько, и их число меняется с продуктом. Строка у них одна и дверь к
// её оператору одна (kaname#313), а ПУТИ записи — внешние концы цепочек к
// этому оператору — разные: транзакция адаптера отзыва вместе с записью
// аудита, пишущая транзакция репозитория, транзакция сессии человека, запись
// на пуле. Проба, подающая один путь, была бы зелена при читателе, понимающем
// только его форму строки.
//
// Перечень путей НЕ выписывается здесь как истина: он выводится переписью по
// дереву (`cutoff_write_paths_census_test.go`), и эта проба требует, чтобы
// исполненные ею пути совпали с переписью, — путь, заведённый позже и сюда не
// поданный, краснеет названием, а не остаётся без пробы молча.
//
// # Чем проба защищена от собственной снисходительности
//
//   - положительный контроль ДО отсечки: тот же ключ токен получает — иначе
//     отказ после отсечки неотличим от контура, не выдающего никому;
//   - законный близнец ПОСЛЕ отсечки: ключ, выданный позже неё, токен
//     получает — отсечка прекращает прежние полномочия, а не запирает учётку;
//   - ключ служебной учётки того же аккаунта не затронут: отсечка — о человеке,
//     и ключ машины человеком не является;
//   - граница включительна: отсечка ставится РОВНО в момент выдачи ключа, и
//     равенство — отказ. Ключ «не позже отсечки» и есть то, что она называет.
package pg_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/tokenpolicy"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// revokeAllWriter — один писатель отсечки, названный тем путём записи, которым
// он пишет её в продукте.
type revokeAllWriter struct {
	name string
	// path — путь записи строки отсечки, которым этот писатель её пишет:
	// внешний конец цепочки к оператору записи строки. Сверяется с переписью
	// путей по дереву (`cutoff_write_paths_census_test.go`).
	path  string
	write func(t *testing.T, f assertionFixture, before time.Time)
}

// revokeAllWritersUnderTest — чем проба подаёт отсечку: по одному или больше на
// каждый путь записи строки.
//
// Полнота этого перечня не утверждается его длиной: её держит сверка с
// переписью путей по дереву (`TestRevokeAllProbeFeedsEveryWritePathOfTheCutoffRow`
// и начало пробы ниже).
func revokeAllWritersUnderTest() []revokeAllWriter {
	return []revokeAllWriter{
		{
			// Принудительный выход пишет отсечку транзакцией адаптера вместе с
			// записью аудита своего вида.
			name: "принудительный выход",
			path: "UserTokenRevocationRepo.UpsertRevokeAllTx",
			write: func(t *testing.T, f assertionFixture, before time.Time) {
				t.Helper()
				require.NoError(t, kanamepg.NewSessionRevocationsAdapter(f.pool).RevokeAllUserTokensTx(
					context.Background(), domain.UserID(f.user), before,
					"admin-force-logout", "", "iam.session.force_logout"))
			},
		},
		{
			// Отзыв всех токенов субъекта — тем же адаптером, своим видом аудита.
			name: "отзыв всех токенов",
			path: "UserTokenRevocationRepo.UpsertRevokeAllTx",
			write: func(t *testing.T, f assertionFixture, before time.Time) {
				t.Helper()
				require.NoError(t, kanamepg.NewSessionRevocationsAdapter(f.pool).RevokeAllUserTokensTx(
					context.Background(), domain.UserID(f.user), before,
					"admin-revoke", "", "iam.session.all_revoked"))
			},
		},
		{
			// Завершение восстановления — пишущей транзакцией репозитория, тем
			// же оператором, что зовёт его вариант использования.
			name: "завершение восстановления",
			path: "writeTx.UpsertUserTokenRevokeAll",
			write: func(t *testing.T, f assertionFixture, before time.Time) {
				t.Helper()
				ctx := context.Background()
				w, err := kanamepg.New(f.pool, nil).Writer(ctx)
				require.NoError(t, err)
				require.NoError(t, w.UpsertUserTokenRevokeAll(ctx, domain.UserTokenRevocation{
					UserID:       domain.UserID(f.user),
					RevokeBefore: before,
					Reason:       domain.RevokeReasonPasswordChange,
				}, ""))
				require.NoError(t, w.Commit(ctx))
			},
		},
		{
			// Транзакция сессии человека — путь, которым пишут отсечку выход из
			// сессии, смена пароля, завершение восстановления нашей полосой и
			// сброс второго фактора.
			name: "транзакция сессии человека",
			path: "humanSessionWriter.UpsertCutoff",
			write: func(t *testing.T, f assertionFixture, before time.Time) {
				t.Helper()
				ctx := context.Background()
				w, err := kanamepg.NewHumanSessionRepo(f.pool).Writer(ctx)
				require.NoError(t, err)
				require.NoError(t, w.UpsertCutoff(ctx, domain.UserTokenRevocation{
					UserID:       domain.UserID(f.user),
					RevokeBefore: before,
					Reason:       domain.RevokeReasonLogout,
				}, ""))
				require.NoError(t, w.Commit(ctx))
			},
		},
		{
			// Запись на пуле, без своей транзакции.
			name: "запись на пуле",
			path: "UserTokenRevocationRepo.UpsertRevokeAll",
			write: func(t *testing.T, f assertionFixture, before time.Time) {
				t.Helper()
				require.NoError(t, kanamepg.NewUserTokenRevocationRepo(f.pool).UpsertRevokeAll(
					context.Background(), domain.UserTokenRevocation{
						UserID:       domain.UserID(f.user),
						RevokeBefore: before,
						Reason:       "admin-revoke",
					}, ""))
			},
		},
	}
}

// userClientIssuedAt читает момент выдачи ключа из ЕГО строки — ровно ту
// величину, по которой отсечка судит ключ. Выписанное значение разошлось бы с
// часами базы, и граница пробы стала бы свойством прогона.
func userClientIssuedAt(t *testing.T, f assertionFixture, id string) time.Time {
	t.Helper()
	var at time.Time
	require.NoError(t, f.pool.QueryRow(context.Background(),
		`SELECT created_at FROM kaname.user_oauth_clients WHERE id = $1`, id).Scan(&at))
	require.False(t, at.IsZero(), "строка ключа обязана нести момент выдачи")
	return at.UTC()
}

// TestClientTokenOwnLane_RevokeAllCutoffRefusesAKeyIssuedNoLaterThanIt — по
// каждому пути записи отсечки, выведенному переписью.
func TestClientTokenOwnLane_RevokeAllCutoffRefusesAKeyIssuedNoLaterThanIt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	// Часы утверждения — свои у пробы: срок утверждения судится ими, а не
	// часами базы, по которым датируются ключ и отсечка.
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)

	// Полнота — сверкой с переписью путей по дереву, а не длиной перечня.
	inTree, parsed := cutoffWritePathsInTree(t)
	require.NotEmptyf(t, inTree, "перепись путей записи отсечки пуста среди %d файлов — не выполнилась", parsed)
	writers := revokeAllWritersUnderTest()
	executed := map[string]struct{}{}

	for _, w := range writers {
		t.Run(w.name, func(t *testing.T) {
			f := newAssertionFixture(t)
			contour := ctBuild(t, f, now)

			const (
				keyBeforeID = "uoc_rvka0000000000001"
				keyAfterID  = "uoc_rvka0000000000002"
				saKeyID     = "soc_rvka0000000000003"
			)
			before := ctNewKey(t)
			f.seedUserClient(t, keyBeforeID, "mirror-revoke-all-before", before.publicPEM, tokenpolicy.AlgES256, nil)
			issued := userClientIssuedAt(t, f, keyBeforeID)

			// (1) Положительный контроль ДО отсечки: ключ токен получает.
			code, body := ctPost(t, contour.endpoint, ctAssertion(t, before, keyBeforeID, "jti-control", now))
			require.Equal(t, 200, code, "контроль: до отсечки ключ обязан получать токен; ответ %v", body)

			// Эталон отказа — ДРУГОЙ отказ того же эндпоинта: клиент, которого
			// нет. Ответ отказа по отсечке обязан с ним совпадать — различимый
			// отказ есть оракул состояния владельца.
			stranger := ctNewKey(t)
			refCode, refBody := ctPost(t, contour.endpoint,
				ctAssertion(t, stranger, "uoc_rvka0000000000009", "jti-stranger", now))
			require.Equal(t, 401, refCode, "эталон отказа: незнакомый клиент отвергается")

			// (2) Писатель ставит отсечку РОВНО в момент выдачи ключа.
			w.write(t, f, issued)

			code, body = ctPost(t, contour.endpoint, ctAssertion(t, before, keyBeforeID, "jti-after-cutoff", now))
			require.Equal(t, 401, code,
				"%s: ключ, выданный не позже отсечки, не получает токена на нашем эндпоинте; ответ %v", w.name, body)
			require.NotContains(t, body, "access_token", "%s: в отказе не бывает токена", w.name)
			require.Equal(t, refBody, body, "%s: отказ по отсечке различим снаружи", w.name)

			// (3) Законный близнец: ключ, выданный ПОСЛЕ отсечки, токен получает.
			after := ctNewKey(t)
			f.seedUserClient(t, keyAfterID, "mirror-revoke-all-after", after.publicPEM, tokenpolicy.AlgES256, nil)
			afterIssued := userClientIssuedAt(t, f, keyAfterID)
			require.True(t, afterIssued.After(issued),
				"предпосылка близнеца: второй ключ выдан позже отсечки (%s против %s)", afterIssued, issued)
			code, body = ctPost(t, contour.endpoint, ctAssertion(t, after, keyAfterID, "jti-after-key", now))
			require.Equal(t, 200, code, "%s: ключ, выданный после отсечки, обязан получать токен; ответ %v", w.name, body)

			// (4) Ключ служебной учётки того же аккаунта отсечкой человека не
			// затронут.
			sa := ctNewKey(t)
			f.seedSAClient(t, saKeyID, "mirror-revoke-all-sa", sa.publicPEM, tokenpolicy.AlgES256)
			code, body = ctPost(t, contour.endpoint, ctAssertion(t, sa, saKeyID, "jti-sa", now))
			require.Equal(t, 200, code, "%s: ключ служебной учётки не затронут отсечкой человека; ответ %v", w.name, body)
			executed[w.path] = struct{}{}
		})
	}
	var unexecuted []string
	for _, p := range inTree {
		if _, ok := executed[p]; !ok {
			unexecuted = append(unexecuted, p)
		}
	}
	t.Logf("перепись: путей записи отсечки по дереву %d · исполнено пробой до конца %d · подач %d",
		len(inTree), len(executed), len(writers))
	require.Emptyf(t, unexecuted, "пути записи отсечки, не исполненные пробой до конца: %v", unexecuted)
}
