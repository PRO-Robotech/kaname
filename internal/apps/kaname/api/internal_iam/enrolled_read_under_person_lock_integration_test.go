// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_iam_test

// enrolled_read_under_person_lock_integration_test.go — условие уровня «по
// заведённому» решается ВНУТРИ транзакции записи глагола, под замком строки
// личности, несовместимым с заведением способа (kaname#770, находка ревью
// безопасности; ban #10). Глаголы — смена адреса (запрос и предъявление,
// `email_change_level.go`) и заведение второго фактора (`sf_enroll_level.go`,
// kaname#747).
//
// # Сцена
//
// Заведение способа, дающего «2», идёт СВОЕЙ транзакцией и не зафиксировано:
// строка ключа доступа вставлена писателем продукта (`AccessKeyRepo.Writer`,
// `InsertKey`) либо ожидающий код по времени переведён в `active` оператором
// подтверждения (`PersonWriter`, `ActivateTOTP`). Глагол сессии «1» пущен
// параллельно.
//
//   - глагол ОБЯЗАН ждать заведение: проба видит процесс, ждущий замка этой
//     транзакции (`pg_blocking_pids`). Глагол, вернувшийся раньше, —
//     ЧЕСТНЫЙ-КРАСНЫЙ: он решил по заведённому, не дождавшись заведения;
//   - заведение зафиксировано → глагол отвечает указанием повысить уровень и
//     ничего не записывает;
//   - законный близнец отличается ОДНИМ фактом — заведение откачено: тот же
//     глагол, дождавшись, проходит. Так отказ приписан заведённому способу, а
//     не ожиданию.

import (
	"context"
	stderrors "errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/ids"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/totpverify"
	"github.com/PRO-Robotech/kaname/internal/webauthnverify/webauthntest"
)

// enrolledLockBudget — предел ожидания пробы: глагол обязан встать в ожидание
// замка за это время. Не дождались — «не выполнилось», не красный.
const enrolledLockBudget = 20 * time.Second

// pendingEnrollment — незафиксированная транзакция заведения способа.
type pendingEnrollment struct {
	finish func(commit bool) error
}

// beginKeyEnrollment — строка ключа доступа личности вставлена писателем
// продукта и НЕ зафиксирована.
func beginKeyEnrollment(t *testing.T, ctx context.Context, pool *pgxpool.Pool, userID domain.UserID) pendingEnrollment {
	t.Helper()
	_, err := pool.Exec(ctx, `INSERT INTO kaname.own_ceilings (kind, limit_value) VALUES ('iam.user.accessKey', 8)
		ON CONFLICT (kind) DO UPDATE SET limit_value = EXCLUDED.limit_value`)
	require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): потолок вида ключа")
	keys := kanamepg.NewAccessKeyRepo(pool)
	w, err := keys.Writer(ctx)
	require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): транзакция заведения ключа")
	t.Cleanup(func() { _ = w.Rollback(context.Background()) })
	auth := webauthntest.New(t, webauthntest.AlgES256)
	minted, err := domain.NewCeremonyHandle()
	require.NoError(t, err)
	handle, err := w.EnsureCeremonyHandle(ctx, userID, minted)
	require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): рукоятка церемонии")
	_, err = w.InsertKey(ctx, domain.AccessKey{
		ID: domain.AccessKeyID(ids.NewHyphenID(ids.PrefixAccessKeyHyphen)), UserID: userID,
		CredentialID: auth.CredentialID(), PublicKey: auth.COSEPublicKey(t), Algorithm: auth.Algorithm(),
		UserHandle: handle.Bytes(), Name: "lock-scene-key", CreatedAt: time.Now().UTC(),
	})
	require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): строка ключа вставлена писателем продукта")
	return pendingEnrollment{
		finish: func(commit bool) error {
			if commit {
				return w.Commit(ctx)
			}
			return w.Rollback(ctx)
		},
	}
}

// beginTOTPActivation — ожидающий код по времени переведён в `active`
// оператором подтверждения под дверью продукта (`PersonWriter`) и НЕ
// зафиксирован.
func beginTOTPActivation(t *testing.T, ctx context.Context, l *sessionWriterLane, p writerPerson) pendingEnrollment {
	t.Helper()
	_, err := l.enroll.Execute(ctx, humansession.EnrollInput{Bearer: p.bearer})
	require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): заведение кода начато сессией «1» без ключа")
	var since time.Time
	require.NoError(t, l.s.pool.QueryRow(ctx,
		`SELECT created_at FROM kaname.user_login_methods WHERE user_id = $1 AND kind = 'totp' AND state = 'pending'`,
		string(p.id)).Scan(&since), "НЕ-ВЫПОЛНИЛОСЬ(фикстура): строка ожидающего кода")
	w, err := l.s.sessions.PersonWriter(ctx, p.id)
	require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): транзакция подтверждения кода")
	t.Cleanup(func() { _ = w.Rollback(context.Background()) })
	now := time.Now().UTC()
	activated, err := w.ActivateTOTP(ctx, p.id, since, totpverify.StepAt(now), now)
	require.NoError(t, err)
	require.True(t, activated, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): код переведён в active")
	return pendingEnrollment{
		finish: func(commit bool) error {
			if commit {
				return w.Commit(ctx)
			}
			return w.Rollback(ctx)
		},
	}
}

// awaitVerbBlockedBy — глагол встал в ожидание замка, который держит
// незафиксированная транзакция заведения (она одна в базе простаивает внутри
// транзакции). Глагол вернулся раньше — ЧЕСТНЫЙ-КРАСНЫЙ с его исходом; предел
// вышел — «не выполнилось».
func awaitVerbBlockedBy(t *testing.T, ctx context.Context, pool *pgxpool.Pool, done <-chan error, what string) {
	t.Helper()
	deadline := time.Now().Add(enrolledLockBudget)
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case err := <-done:
			t.Fatalf("%s ЧЕСТНЫЙ-КРАСНЫЙ: глагол решил по заведённому, не дождавшись незафиксированного заведения способа (исход: %v)", what, err)
		case <-tick.C:
		}
		var waiting int
		require.NoError(t, pool.QueryRow(ctx,
			`SELECT count(*) FROM pg_stat_activity w
			  WHERE w.datname = current_database()
			    AND EXISTS (SELECT 1 FROM pg_stat_activity b
			                 WHERE b.pid = ANY(pg_blocking_pids(w.pid)) AND b.state = 'idle in transaction')`).Scan(&waiting))
		if waiting > 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s НЕ-ВЫПОЛНИЛОСЬ: за %s глагол ни вернулся, ни встал в ожидание заведения", what, enrolledLockBudget)
		}
	}
}

// requireStepUpAfterEnrollment — указание повысить уровень «требуется 2,
// предъявлена 1».
func requireStepUpAfterEnrollment(t *testing.T, err error, what string) {
	t.Helper()
	require.Errorf(t, err, "%s ЧЕСТНЫЙ-КРАСНЫЙ: глагол выполнен сессией «1», хотя способ «2» заведён и зафиксирован раньше решения", what)
	var su *humansession.StepUpRequiredError
	require.Truef(t, stderrors.As(err, &su), "%s: ждалось указание повысить уровень, получено %T: %v", what, err, err)
	require.Equalf(t, iamerr.TextStepUpRequired, err.Error(), "%s: текст указания", what)
	require.Equalf(t, iamerr.StepUpChallenge("2", "1"), su.Challenge(), "%s: ступени вызова", what)
}

// enrolledEmailChange — глаголы смены адреса тем же составом, что в корне.
func enrolledEmailChange(t *testing.T, l *sessionWriterLane) (*humansession.RequestEmailChangeUseCase, *humansession.ConfirmEmailChangeUseCase) {
	t.Helper()
	deps := humansession.EmailChangeDeps{
		Store:     sceneEmailChangeStore{sessions: l.s.sessions, inner: kanamepg.NewRegistrationStore(l.s.pool)},
		Methods:   kanamepg.NewLoginMethodRepo(l.s.pool),
		Pace:      humansession.VerificationPace{CodeTTL: 30 * time.Minute, Attempts: 5, Interval: time.Minute, Limit: 5, Window: 24 * time.Hour},
		Freshness: 15 * time.Minute,
		MailLimit: outboxtypes.InviteMailRateLimit{MaxPerWindow: 10000, Window: time.Hour},
	}
	request, err := humansession.NewRequestEmailChangeUseCase(deps)
	require.NoError(t, err)
	confirm, err := humansession.NewConfirmEmailChangeUseCase(deps)
	require.NoError(t, err)
	return request, confirm
}

func freshAddress() string {
	return "lock-ec-" + strings.ToLower(ids.NewID("tst")[3:13]) + "@example.invalid"
}

// emailChangeRows — строк отложенной смены у личности.
func emailChangeRows(t *testing.T, ctx context.Context, pool *pgxpool.Pool, userID domain.UserID) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM kaname.email_change_codes WHERE user_id = $1`, string(userID)).Scan(&n))
	return n
}

// TestIntegration_EmailChangeRequestDecidesOnAKeyEnrolledDuringIt — запрос
// смены против заведения ключа доступа: зафиксировано — указание, откачено —
// запрос принят.
func TestIntegration_EmailChangeRequestDecidesOnAKeyEnrolledDuringIt(t *testing.T) {
	l := newSessionWriterLane(t)
	request, _ := enrolledEmailChange(t, l)
	for _, commit := range []bool{true, false} {
		name := map[bool]string{true: "заведение зафиксировано", false: "близнец: заведение откачено"}[commit]
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			p := l.seedPerson(t)
			pending := beginKeyEnrollment(t, ctx, l.s.pool, p.id)
			done := make(chan error, 1)
			go func() {
				_, err := request.Execute(ctx, humansession.RequestEmailChangeInput{Bearer: p.bearer, NewEmail: freshAddress()})
				done <- err
			}()
			awaitVerbBlockedBy(t, ctx, l.s.pool, done, "запрос смены")
			require.NoError(t, pending.finish(commit))
			err := <-done
			if !commit {
				require.NoError(t, err, "близнец: ключа нет — запрос сессии «1» принят")
				require.Equal(t, 1, emailChangeRows(t, ctx, l.s.pool, p.id), "близнец: запрос записан")
				return
			}
			requireStepUpAfterEnrollment(t, err, "запрос смены")
			require.Zero(t, emailChangeRows(t, ctx, l.s.pool, p.id), "отказ ничего не записал")
		})
	}
}

// TestIntegration_EmailChangeConfirmDecidesOnACodeActivatedDuringIt —
// предъявление кода смены против подтверждения кода по времени.
func TestIntegration_EmailChangeConfirmDecidesOnACodeActivatedDuringIt(t *testing.T) {
	l := newSessionWriterLane(t)
	request, confirm := enrolledEmailChange(t, l)
	for _, commit := range []bool{true, false} {
		name := map[bool]string{true: "подтверждение зафиксировано", false: "близнец: подтверждение откачено"}[commit]
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			p := l.seedPerson(t)
			_, err := request.Execute(ctx, humansession.RequestEmailChangeInput{Bearer: p.bearer, NewEmail: freshAddress()})
			require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): запрос смены сессией «1» без способа «2»")
			var code string
			require.NoError(t, l.s.pool.QueryRow(ctx, `SELECT payload->>'code' FROM kaname.invite_mail_outbox
				 WHERE event_type = 'mail.email-change.send' AND payload->>'user_id' = $1 ORDER BY id DESC LIMIT 1`,
				string(p.id)).Scan(&code), "НЕ-ВЫПОЛНИЛОСЬ(фикстура): код из строки очереди")
			pending := beginTOTPActivation(t, ctx, l, p)
			done := make(chan error, 1)
			go func() {
				_, err := confirm.Execute(ctx, humansession.ConfirmEmailChangeInput{Bearer: p.bearer, Code: code})
				done <- err
			}()
			awaitVerbBlockedBy(t, ctx, l.s.pool, done, "предъявление кода смены")
			require.NoError(t, pending.finish(commit))
			err = <-done
			var email string
			require.NoError(t, l.s.pool.QueryRow(ctx, `SELECT email FROM kaname.users WHERE id = $1`, string(p.id)).Scan(&email))
			if !commit {
				require.NoError(t, err, "близнец: кода нет — предъявление сессией «1» меняет адрес")
				require.NotEqual(t, p.email, email, "близнец: адрес сменён")
				return
			}
			requireStepUpAfterEnrollment(t, err, "предъявление кода смены")
			require.Equal(t, p.email, email, "отказ адреса не сменил")
		})
	}
}

// TestIntegration_SecondFactorEnrollDecidesOnAKeyEnrolledDuringIt — заведение
// второго фактора (kaname#747) против заведения ключа доступа.
func TestIntegration_SecondFactorEnrollDecidesOnAKeyEnrolledDuringIt(t *testing.T) {
	l := newSessionWriterLane(t)
	for _, commit := range []bool{true, false} {
		name := map[bool]string{true: "заведение ключа зафиксировано", false: "близнец: заведение ключа откачено"}[commit]
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			p := l.seedPerson(t)
			pending := beginKeyEnrollment(t, ctx, l.s.pool, p.id)
			done := make(chan error, 1)
			go func() {
				_, err := l.enroll.Execute(ctx, humansession.EnrollInput{Bearer: p.bearer})
				done <- err
			}()
			awaitVerbBlockedBy(t, ctx, l.s.pool, done, "заведение второго фактора")
			require.NoError(t, pending.finish(commit))
			err := <-done
			var rows int
			require.NoError(t, l.s.pool.QueryRow(ctx,
				`SELECT count(*) FROM kaname.user_login_methods WHERE user_id = $1 AND kind = 'totp'`, string(p.id)).Scan(&rows))
			if !commit {
				require.NoError(t, err, "близнец: ключа нет — заведение свежей «1» начато")
				require.Equal(t, 1, rows, "близнец: строка ожидающего заведения есть")
				return
			}
			requireStepUpAfterEnrollment(t, err, "заведение второго фактора")
			require.Zero(t, rows, "отказ заведения не начал")
		})
	}
}
