// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// client_token_revoke_all_integration_test.go — отсечка отзыва-всех владельца
// действует на НАШЕЙ полосе выдачи тем же правилом, что на полосе хука, против
// настоящей базы и настоящего контура (задача kaname#379).
//
// # Что здесь утверждается
//
// Наблюдаемое, а не «порт спросили»: после того как писатель отсечки
// закоммитил её, тот же ключ пользователя, предъявленный НАШЕМУ эндпоинту, не
// получает токена — ответ отказа совпадает с ответом всякого другого отказа, и
// токена в нём нет.
//
// # Почему писателей ТРИ и почему каждый подан отдельно
//
// Отсечку пишут принудительный выход, отзыв всех токенов субъекта и завершение
// восстановления. Строка у них одна, а пути записи разные: два идут
// транзакцией адаптера отзыва вместе со своей записью аудита, третий — пишущей
// транзакцией репозитория. Проба, подающая одного, была бы зелена при
// читателе, понимающем только его форму строки.
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
	name  string
	write func(t *testing.T, f assertionFixture, before time.Time)
}

// revokeAllWritersUnderTest — перечень писателей отсечки.
//
// Перечень ВЫПИСАН, и это названо: писатели живут в трёх разных пакетах и
// общим типом себя не объявляют. Цена — четвёртый писатель, заведённый и сюда
// не внесённый, останется без пробы; проба печатает число писателей, чтобы это
// было видно.
func revokeAllWritersUnderTest() []revokeAllWriter {
	return []revokeAllWriter{
		{
			// Принудительный выход пишет отсечку транзакцией адаптера вместе с
			// записью аудита своего вида.
			name: "принудительный выход",
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
// каждому писателю отсечки.
func TestClientTokenOwnLane_RevokeAllCutoffRefusesAKeyIssuedNoLaterThanIt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	// Часы утверждения — свои у пробы: срок утверждения судится ими, а не
	// часами базы, по которым датируются ключ и отсечка.
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)

	writers := revokeAllWritersUnderTest()
	require.Len(t, writers, 3, "писателей отсечки три; перечень выписан, и его длина — часть утверждения")

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
		})
	}
	t.Logf("перепись: писателей отсечки %d · каждый подан отдельным контуром", len(writers))
}
