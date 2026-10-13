// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_iam_test

// email_change_address_under_person_lock_integration_test.go — правило «новый
// адрес отличен от текущего» на запросе смены (kaname#780, ревью целостности
// пакета kn-296, DB-296-T1; ban #10) решает оператор записи принятого запроса
// под замком строки личности, а не чтение адреса до транзакции.
//
// # Сцена — транзакции в обратном порядке
//
// Исход прежней смены на адрес N идёт СВОЕЙ транзакцией дверью продукта
// (`RegistrationStore.EmailChangeWriter`): код предъявлен, адрес переписан на
// N, отметка поставлена, фиксации нет. Запрос смены на N пущен параллельно: его
// сессия и текущий адрес прочитаны ДО транзакции (там ещё прежний адрес), затем
// он встаёт в ожидание замка строки личности (`pg_blocking_pids`). Исход
// фиксируется — запрос продолжает со строкой, у которой адрес уже N.
//
//   - запрос на N ОБЯЗАН получить отказ поля «must differ from the current
//     address» и ничего не записать: живой отложенной смены на текущий адрес
//     не бывает. Принятый запрос — ЧЕСТНЫЙ-КРАСНЫЙ: решение о правиле принято
//     по адресу, прочитанному до чужой фиксации;
//   - законный близнец отличается ОДНИМ фактом — запрос просит другой адрес M:
//     та же сцена, тот же порядок, запрос принят, строка и письмо — на M. Так
//     отказ приписан совпадению с текущим адресом, а не ожиданию, сменённому
//     носителю или темпу.

import (
	"context"
	stderrors "errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// addressSceneEmailChange — глаголы смены тем же составом, что в корне; темп
// человека сужен до микросекунды, чтобы второй запрос сцены судил адрес, а не
// интервал (интервал держат пробы EC-17, EC-DB-02).
func addressSceneEmailChange(t *testing.T, l *sessionWriterLane) *humansession.RequestEmailChangeUseCase {
	t.Helper()
	request, err := humansession.NewRequestEmailChangeUseCase(humansession.EmailChangeDeps{
		Store:     sceneEmailChangeStore{sessions: l.s.sessions, inner: kanamepg.NewRegistrationStore(l.s.pool)},
		Methods:   kanamepg.NewLoginMethodRepo(l.s.pool),
		Pace:      humansession.VerificationPace{CodeTTL: 30 * time.Minute, Attempts: 5, Interval: time.Microsecond, Limit: 5, Window: 24 * time.Hour},
		Freshness: 15 * time.Minute,
		MailLimit: outboxtypes.InviteMailRateLimit{MaxPerWindow: 10000, Window: time.Hour},
	})
	require.NoError(t, err)
	return request
}

// pendingAddressChange — исход смены на адрес кода дверью продукта: код
// предъявлен, адрес переписан, отметка поставлена; транзакция НЕ зафиксирована
// и держит строку личности.
func pendingAddressChange(t *testing.T, ctx context.Context, l *sessionWriterLane, p writerPerson, code string) (domain.Email, pendingEnrollment) {
	t.Helper()
	w, err := kanamepg.NewRegistrationStore(l.s.pool).EmailChangeWriter(ctx, p.id)
	require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): транзакция исхода смены")
	t.Cleanup(func() { _ = w.Rollback(context.Background()) })
	now := time.Now().UTC()
	outcome, newEmail, err := w.PresentEmailChangeCode(ctx, p.id, domain.PresentedVerificationCode(code).Digest(), now, 5)
	require.NoError(t, err)
	require.Equal(t, humansession.CodeMatched, outcome, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): код смены предъявлен")
	_, err = w.ChangeEmail(ctx, p.id, newEmail)
	require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): адрес переписан писателем продукта")
	marked, err := w.MarkEmailVerified(ctx, p.id, newEmail, now)
	require.NoError(t, err)
	require.True(t, marked, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): отметка нового адреса")
	return newEmail, pendingEnrollment{finish: func(commit bool) error {
		if commit {
			return w.Commit(ctx)
		}
		return w.Rollback(ctx)
	}}
}

// liveEmailChange — живая отложенная смена личности: адрес и число таких строк.
func liveEmailChange(t *testing.T, ctx context.Context, l *sessionWriterLane, userID domain.UserID) (int, string) {
	t.Helper()
	var (
		n    int
		addr string
	)
	require.NoError(t, l.s.pool.QueryRow(ctx, `
		SELECT count(*), coalesce(max(new_email), '') FROM kaname.email_change_codes
		 WHERE user_id = $1 AND consumed_at IS NULL AND superseded_at IS NULL`, string(userID)).Scan(&n, &addr))
	return n, addr
}

// TestIntegration_EmailChangeRequestJudgesTheAddressCommittedDuringIt — запрос
// смены на адрес, который стал текущим чужой фиксацией за время запроса.
func TestIntegration_EmailChangeRequestJudgesTheAddressCommittedDuringIt(t *testing.T) {
	l := newSessionWriterLane(t)
	request := addressSceneEmailChange(t, l)
	for _, same := range []bool{true, false} {
		name := map[bool]string{true: "запрос на адрес, ставший текущим", false: "близнец: запрос на другой адрес"}[same]
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			p := l.seedPerson(t)
			_, err := request.Execute(ctx, humansession.RequestEmailChangeInput{Bearer: p.bearer, NewEmail: freshAddress()})
			require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): первый запрос смены")
			var code string
			require.NoError(t, l.s.pool.QueryRow(ctx, `SELECT payload->>'code' FROM kaname.invite_mail_outbox
				 WHERE event_type = 'mail.email-change.send' AND payload->>'user_id' = $1 ORDER BY id DESC LIMIT 1`,
				string(p.id)).Scan(&code), "НЕ-ВЫПОЛНИЛОСЬ(фикстура): код из строки очереди")
			changedTo, pending := pendingAddressChange(t, ctx, l, p, code)

			target := string(changedTo)
			if !same {
				target = freshAddress()
			}
			done := make(chan error, 1)
			go func() {
				_, err := request.Execute(ctx, humansession.RequestEmailChangeInput{Bearer: p.bearer, NewEmail: target})
				done <- err
			}()
			awaitVerbBlockedBy(t, ctx, l.s.pool, done, "запрос смены")
			require.NoError(t, pending.finish(true), "НЕ-ВЫПОЛНИЛОСЬ(фикстура): исход смены зафиксирован")
			err = <-done

			var current string
			require.NoError(t, l.s.pool.QueryRow(ctx, `SELECT email FROM kaname.users WHERE id = $1`, string(p.id)).Scan(&current))
			require.Equal(t, string(changedTo), current, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): текущий адрес — адрес исхода")
			live, addr := liveEmailChange(t, ctx, l, p.id)
			if !same {
				require.NoError(t, err, "близнец: запрос на другой адрес после чужой фиксации принят")
				require.Equal(t, 1, live, "близнец: живая отложенная смена одна")
				require.Equal(t, target, addr, "близнец: живая смена — на запрошенный адрес")
				return
			}
			require.Errorf(t, err, "ЧЕСТНЫЙ-КРАСНЫЙ: запрос смены на текущий адрес принят — правило судило адрес, "+
				"прочитанный до фиксации исхода (живых строк %d, адрес живой %q)", live, addr)
			var fe *humansession.FieldError
			require.Truef(t, stderrors.As(err, &fe), "ждался отказ поля, получено %T: %v", err, err)
			require.Equal(t, "newEmail", fe.Field, "поле отказа")
			require.Equal(t, humansession.RuleMustDiffer, fe.Rule, "правило отказа")
			require.Zero(t, live, "отказ ничего не записал: живой смены на текущий адрес нет")
		})
	}
}
