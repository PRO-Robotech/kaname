// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_iam_test

// session_row_writers_identity_deletion_integration_test.go — КАЖДЫЙ ПИСАТЕЛЬ
// СТРОК СЕССИИ ВХОДА БЕРЁТ ЗАМКИ В ОДНОМ ПОРЯДКЕ С УДАЛЕНИЕМ ЛИЧНОСТИ (задача
// kaname#382).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Удаление личности идёт по внешним ключам сверху вниз: строка `users`
// (`FOR UPDATE` самим удалением), затем каскадом её записи сессии, строки
// способов входа, отсечки. Писатель, взявший строку-ребёнка личности и лишь
// потом — строку личности (проверкой внешнего ключа вставки, которая берёт
// `FOR KEY SHARE`), идёт навстречу удалению: он держит ребёнка и ждёт личность,
// удаление держит личность и ждёт ребёнка. Порядок, который держит всё дерево,
// — «личность → всё прочее» (`lockUserForKeySQL`, `lockPersonForSessionSetSQL`).
//
// Полоса kaname#340 закрепила его пробой у принудительного выхода и смены
// пароля. Здесь — остальные писатели.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПЕРЕЧЕНЬ ПИСАТЕЛЕЙ ВЫВЕДЕН ИЗ ДЕРЕВА КОМАНДОЙ
//
// Операторы, пишущие строки `human_sessions`:
//
//	git grep -nE '(INSERT INTO|UPDATE|DELETE FROM) +(kaname\.)?human_sessions\b' -- '*.go' ':!*_test.go'
//
// Транзакции, их исполняющие, — вызывающие дверей писателя сессии и выдачи:
//
//	git grep -nE '\.(InsertSession|EndSession|EndOtherSessions|RotateBearer|PresentInSession)\(ctx' -- '*.go' ':!*_test.go'
//	git grep -n 'IssueSession(ctx' -- '*.go' ':!*_test.go'
//	git grep -n 'SweepUnservableSessions(' -- '*.go' ':!*_test.go'
//
// Писателей ОДИННАДЦАТЬ, и перепись их держит гейт дерева
// (`session_row_writers_census_test.go`): писатель без сцены — находка, сцена
// без писателя — тоже. У десяти — сцена внахлёст с удалением личности, вход —
// двумя (паролем и с запасным кодом: у второго до записи сессии есть строка
// фактора), у регистрации — причина ниже:
//
//	вход паролем                       — TestIntegration_SessionWriterPasswordLogin…
//	вход с запасным кодом              — TestIntegration_SessionWriterSecondFactorLogin…
//	выход                              — TestIntegration_SessionWriterLogout…
//	повышение паролем                  — TestIntegration_SessionWriterStepUp…
//	подтверждение второго фактора      — TestIntegration_SessionWriterSecondFactorConfirm…
//	перечеканка запасных кодов         — TestIntegration_SessionWriterBackupCodes…
//	снятие второго фактора             — TestIntegration_SessionWriterSecondFactorRemoval…
//	завершение восстановления          — TestIntegration_SessionWriterRecoveryCompletion…
//	уборка записей сессии              — TestIntegration_SessionWriterSweep…
//	смена пароля                       — TestIntegration_PasswordChangeAndIdentityDeletionDoNotDeadlock (kaname#340)
//	принудительный выход               — TestIntegration_ForceLogoutAndIdentityDeletionDoNotDeadlock (kaname#340)
//
// Регистрация (`register.go`) выдаёт сессию той же транзакцией, что ЗАВОДИТ
// личность: удаление не может прийти к личности, которой ещё нет в
// зафиксированном состоянии, — сцены внахлёст у неё нет by construction.
//
// ─────────────────────────────────────────────────────────────────────────────
// КАК СТРОИТСЯ СЦЕНА И ЧТО УТВЕРЖДАЕТСЯ
//
// Писатель — НАСТОЯЩИЙ вариант использования над настоящими адаптерами.
// Одноразовая задержка стоит на операторе, после которого писатель держит свои
// строки-дети личности; удаление запускается, когда писатель виден в ней, и
// сцена считается построенной, только когда держатель видел удаление ждущим
// ЗАМКА (`requireHoldSceneBuilt`). Утверждается: взаимных блокировок ноль
// (`pg_stat_database.deadlocks` +0), обе транзакции зафиксированы, личности
// после сцены нет, её записей сессии — тоже.
//
// Законный близнец каждой сцены — первый её шаг: та же личность с тем же
// посевом удаляется без конкурента и фиксируется.
//
// Контрольная рука — транзакция с ОБРАТНЫМ порядком захвата (строка сессии,
// затем строка личности проверкой внешнего ключа) в той же сцене: она обязана
// дать взаимную блокировку. Без неё «ноль» сцен выше был бы неотличим от сцены,
// которая блокировку увидеть не способна.

import (
	"context"
	"crypto/hmac"
	"crypto/sha1" // #nosec G505 -- RFC 6238 задаёт HMAC-SHA1; оракул кода, не защита
	"encoding/base32"
	"encoding/binary"
	stderrors "errors"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/assurance"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/keywrap"
	"github.com/PRO-Robotech/kaname/internal/passwordverify"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/totpverify"
)

const (
	writerScenePassword    = "the-writer-scene-passphrase-382"
	writerSceneNewPassword = "the-writer-scene-replacement-382"
	writerSceneSource      = "203.0.113.82"
	writerSceneHold        = "probe_session_writer_hold"
)

// zeroEnvelope — огибающая по времени нулевая: время держат пробы огибающей
// (Ф3 Р17), предмет сцены — порядок замков.
type zeroEnvelope struct{}

func (zeroEnvelope) Floor() time.Duration { return 0 }
func (zeroEnvelope) Admit(context.Context, domain.PasswordCostClass, passwordverify.EnvelopeTrigger) (passwordverify.Admission, error) {
	return passwordverify.Admission{}, nil
}

// sessionWriterLane — варианты использования полосы входа над настоящими
// адаптерами, собранные теми же конструкторами, что в корне
// (`cmd/kaname/loginlane.go`, `buildLoginLane`).
type sessionWriterLane struct {
	s        *concurrencyScene
	users    *kanamepg.Repository
	hasher   *passwordverify.Hasher
	owner    domain.UserID
	login    *humansession.LoginUseCase
	logout   *humansession.LogoutUseCase
	stepUp   *humansession.StepUpUseCase
	enroll   *humansession.EnrollSecondFactorUseCase
	confirm  *humansession.ConfirmSecondFactorUseCase
	regen    *humansession.RegenerateBackupCodesUseCase
	remove   *humansession.RemoveSecondFactorUseCase
	request  *humansession.RequestRecoveryUseCase
	complete *humansession.CompleteRecoveryUseCase
}

func newSessionWriterLane(t *testing.T) *sessionWriterLane {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	s := newConcurrencyScene(t)
	logger := slog.New(slog.DiscardHandler)
	hasher, err := passwordverify.NewHasher(passwordverify.Declared{
		Format: domain.PasswordHashFormatArgon2id,
		Params: map[domain.PasswordHashCostParam]uint32{
			domain.CostParamArgon2Memory: 65536, domain.CostParamArgon2Iterations: 3, domain.CostParamArgon2Parallelism: 4,
		},
	})
	require.NoError(t, err)
	verifier, err := passwordverify.New(4, quietVerifyObserver{})
	require.NoError(t, err)
	decoy, err := hasher.Hash("decoy-of-the-writer-scene")
	require.NoError(t, err)
	require.NoError(t, verifier.SetDecoy(decoy))
	rule, err := humansession.NewPasswordRule(12, nil, humansession.NopObserver{}, logger)
	require.NoError(t, err)
	key := make([]byte, keywrap.KeySize)
	for i := range key {
		key[i] = 9
	}
	wrapper, err := keywrap.New(key)
	require.NoError(t, err)
	totp, err := totpverify.New(wrapper)
	require.NoError(t, err)

	users := kanamepg.New(s.pool, nil)
	methods := kanamepg.NewLoginMethodRepo(s.pool)
	limits := humansession.Limits{AddressAttempts: 50, AddressWindow: 10 * time.Minute, SourceAttempts: 500, SourceWindow: 10 * time.Minute}
	nop := humansession.NopObserver{}

	l := &sessionWriterLane{s: s, users: users, hasher: hasher, owner: seedForceLogoutUser(t, ctx, s.pool)}
	l.login, err = humansession.NewLoginUseCase(humansession.LoginDeps{
		Store: s.sessions, Users: kanamepg.NewUserDirectory(users), Methods: methods, Verifier: verifier, Hasher: hasher,
		Limits: limits, TTL: 24 * time.Hour, Observer: nop, Now: time.Now, Logger: logger,
		Envelope: zeroEnvelope{}, TOTP: totp, Sets: verifier,
	})
	require.NoError(t, err)
	l.logout, err = humansession.NewLogoutUseCase(s.sessions, nop, time.Now, logger)
	require.NoError(t, err)
	sf := humansession.SecondFactorDeps{
		Store: s.sessions, Methods: methods, TOTP: totp, Sets: verifier, SetHasher: hasher, Verifier: verifier,
		Limits: limits, Freshness: 15 * time.Minute, Domain: "console.example.invalid", Observer: nop,
		Now: time.Now, Logger: logger,
	}
	l.stepUp, err = humansession.NewStepUpUseCase(sf)
	require.NoError(t, err)
	l.enroll, err = humansession.NewEnrollSecondFactorUseCase(sf)
	require.NoError(t, err)
	l.confirm, err = humansession.NewConfirmSecondFactorUseCase(sf)
	require.NoError(t, err)
	l.regen, err = humansession.NewRegenerateBackupCodesUseCase(sf)
	require.NoError(t, err)
	l.remove, err = humansession.NewRemoveSecondFactorUseCase(sf)
	require.NoError(t, err)
	l.request, err = humansession.NewRequestRecoveryUseCase(humansession.RequestRecoveryDeps{
		Store: s.sessions, CodeTTL: 5 * time.Minute, Dispatcher: humansession.SyncDispatcher{}, Observer: nop,
		Now: time.Now, Logger: logger,
	})
	require.NoError(t, err)
	l.complete, err = humansession.NewCompleteRecoveryUseCase(humansession.CompleteRecoveryDeps{
		Store: s.sessions, Hasher: hasher, Rule: rule, Limits: limits, TTL: 24 * time.Hour, Observer: nop,
		Now: time.Now, Logger: logger,
	})
	require.NoError(t, err)
	return l
}

// writerPerson — посеянная личность сцены: участник аккаунта (не владелец —
// владельца удаление не берёт вовсе), способ входа паролем, подтверждённый
// адрес и живая запись сессии.
type writerPerson struct {
	id     domain.UserID
	email  string
	bearer domain.SessionBearer
	// backup — запасные коды заведённого второго фактора; пусто — не заведён.
	backup []string
}

func (l *sessionWriterLane) seedPerson(t *testing.T) writerPerson {
	t.Helper()
	ctx := context.Background()
	uid := seedAccountMember(t, ctx, l.s.pool, l.owner)
	v, err := l.hasher.Hash(writerScenePassword)
	require.NoError(t, err)
	_, err = l.s.pool.Exec(ctx,
		`INSERT INTO kaname.user_login_methods (user_id, kind, verifier) VALUES ($1, 'password', $2)`,
		string(uid), v.Reveal())
	require.NoError(t, err, "посев: способ входа паролем")
	_, err = l.s.pool.Exec(ctx, `UPDATE kaname.users SET email_verified_at = now() WHERE id = $1`, string(uid))
	require.NoError(t, err, "посев: подтверждённый адрес")
	var email string
	require.NoError(t, l.s.pool.QueryRow(ctx, `SELECT email FROM kaname.users WHERE id = $1`, string(uid)).Scan(&email))
	bearer, err := domain.NewSessionBearer()
	require.NoError(t, err)
	seedOwnLoginSession(t, ctx, l.s.pool, uid, string(bearer.Digest()))
	requireLiveBefore(t, ctx, l.s.sessions, string(bearer.Digest()))
	return writerPerson{id: uid, email: email, bearer: bearer}
}

// seedEnrolledPerson — личность с заведённым и подтверждённым вторым фактором,
// заведённым настоящими глаголами над тем же проверяющим кода. Носитель —
// перевыпущенный подтверждением.
func (l *sessionWriterLane) seedEnrolledPerson(t *testing.T) writerPerson {
	t.Helper()
	ctx := context.Background()
	p := l.seedPerson(t)
	en, err := l.enroll.Execute(ctx, humansession.EnrollInput{Bearer: p.bearer})
	require.NoError(t, err, "посев: заведение начато")
	out, err := l.confirm.Execute(ctx, humansession.ConfirmInput{
		Bearer: p.bearer, Code: totpCode(t, en.Secret, totpverify.StepAt(time.Now())), Source: writerSceneSource,
	})
	require.NoError(t, err, "посев: заведение подтверждено")
	require.NotEmpty(t, out.BackupCodes, "посев: подтверждение выдало набор")
	p.bearer, p.backup = out.Bearer, out.BackupCodes
	return p
}

// totpCodeValue — код RFC 6238 ступени step: оракул пробы, не защита.
func totpCodeValue(secret totpverify.Secret, step int64) (string, error) {
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret.Base32())
	if err != nil {
		return "", err
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step)) // #nosec G115 -- ступень неотрицательна
	mac := hmac.New(sha1.New, raw)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	bin := (uint32(sum[off])&0x7f)<<24 | uint32(sum[off+1])<<16 | uint32(sum[off+2])<<8 | uint32(sum[off+3])
	return fmt.Sprintf("%06d", bin%1000000), nil
}

func totpCode(t *testing.T, secret totpverify.Secret, step int64) string {
	t.Helper()
	code, err := totpCodeValue(secret, step)
	require.NoError(t, err, "оракул кода")
	return code
}

// writerScene — один писатель строк сессии против удаления личности.
type writerScene struct {
	// table, event — оператор, после которого писатель держит свои строки.
	table, event string
	// seed — посев личности; прогонов несколько, и каждому — своя личность.
	seed func(t *testing.T) writerPerson
	// write — настоящий вариант использования над посеянной личностью.
	write func(ctx context.Context, p writerPerson) error
}

// runWriterScene — сцена внахлёст: писатель в задержке держит свои строки,
// удаление личности приходит в это окно.
func runWriterScene(t *testing.T, l *sessionWriterLane, sc writerScene) {
	t.Helper()
	ctx := context.Background()
	pool := l.s.pool

	lone := sc.seed(t)
	require.NoError(t, deletePerson(ctx, l.users, lone.id), "близнец: удаление без конкурента обязано фиксироваться")
	require.False(t, personExists(t, ctx, l.s, lone.id), "близнец: личность удалена")

	installOneShotHold(t, ctx, pool, writerSceneHold, sc.table, sc.event)
	deadlocksBefore := databaseDeadlocks(t, ctx, pool)

	const rounds = 3
	var waiters, writerFailures, deletionFailures, deletionAborted, survivors, leftovers int
	for round := 0; round < rounds; round++ {
		p := sc.seed(t)
		writeDone := make(chan error, 1)
		deleteDone := make(chan error, 1)
		armOneShotHold(t, ctx, pool, writerSceneHold, 1)
		go func() { writeDone <- sc.write(ctx, p) }()
		awaitSleepingBackend(t, ctx, pool)
		go func() { deleteDone <- deletePerson(ctx, l.users, p.id) }()
		writeErr := <-writeDone
		deleteErr := <-deleteDone
		disarmOneShotHold(t, ctx, pool, writerSceneHold)
		waiters += requireHoldSceneBuilt(t, ctx, pool, writerSceneHold)

		if writeErr != nil {
			writerFailures++
		}
		if deleteErr != nil {
			deletionFailures++
			if stderrors.Is(deleteErr, iamerr.ErrAborted) {
				deletionAborted++
			}
		}
		exists := personExists(t, ctx, l.s, p.id)
		if exists {
			survivors++
		}
		var rows int
		require.NoError(t, pool.QueryRow(ctx,
			`SELECT count(*) FROM kaname.human_sessions WHERE user_id = $1`, string(p.id)).Scan(&rows))
		if !exists && rows > 0 {
			leftovers += rows
		}
		t.Logf("прогон %d: писатель: ошибка=%v · удаление: ошибка=%v · личность после: %v · записей сессии после: %d",
			round, writeErr, deleteErr, exists, rows)
	}

	deadlocksAfter := deadlocksAfterPoolClose(t, ctx, l.s.dsn, pool)
	t.Logf("прогонов %d · ждавших замка %d · отказов писателя %d · отказов удаления %d (ABORTED %d) · "+
		"личностей, переживших удаление, %d · записей сессии удалённых личностей %d · pg_stat_database.deadlocks +%d",
		rounds, waiters, writerFailures, deletionFailures, deletionAborted, survivors, leftovers,
		deadlocksAfter-deadlocksBefore)

	assert.Zero(t, deadlocksAfter-deadlocksBefore,
		"pg_stat_database.deadlocks: писатель держит строку-ребёнка личности и ждёт личность, "+
			"удаление держит личность и ждёт ребёнка")
	assert.Zero(t, writerFailures, "отказы писателя, начавшего первым")
	assert.Zero(t, deletionFailures, "отказы удаления личности")
	assert.Zero(t, survivors, "личности, пережившие удаление")
	assert.Zero(t, leftovers, "записи сессии удалённых личностей")
}

// ─────────────────────────────────────────────────────────────────────────────
// Сцены по перечню.

func TestIntegration_SessionWriterPasswordLoginAndIdentityDeletionDoNotDeadlock(t *testing.T) {
	l := newSessionWriterLane(t)
	runWriterScene(t, l, writerScene{
		table: "human_sessions", event: "INSERT",
		seed: l.seedPerson,
		write: func(ctx context.Context, p writerPerson) error {
			_, err := l.login.Execute(ctx, humansession.LoginInput{
				Email: p.email, Password: writerScenePassword, Source: writerSceneSource,
			})
			return err
		},
	})
}

func TestIntegration_SessionWriterSecondFactorLoginAndIdentityDeletionDoNotDeadlock(t *testing.T) {
	l := newSessionWriterLane(t)
	runWriterScene(t, l, writerScene{
		table: "user_login_methods", event: "UPDATE",
		seed: l.seedEnrolledPerson,
		write: func(ctx context.Context, p writerPerson) error {
			_, err := l.login.Execute(ctx, humansession.LoginInput{
				Email: p.email, Password: writerScenePassword, Source: writerSceneSource,
				SecondFactor: &humansession.SecondFactorPresentation{Method: assurance.MethodLookupSecret, Code: p.backup[0]},
			})
			return err
		},
	})
}

func TestIntegration_SessionWriterLogoutAndIdentityDeletionDoNotDeadlock(t *testing.T) {
	l := newSessionWriterLane(t)
	runWriterScene(t, l, writerScene{
		table: "human_sessions", event: "UPDATE OF ended_at",
		seed: l.seedPerson,
		write: func(ctx context.Context, p writerPerson) error {
			ended, err := l.logout.Execute(ctx, p.bearer)
			if err == nil && !ended {
				return stderrors.New("выход не снял живую запись сессии")
			}
			return err
		},
	})
}

func TestIntegration_SessionWriterStepUpAndIdentityDeletionDoNotDeadlock(t *testing.T) {
	l := newSessionWriterLane(t)
	runWriterScene(t, l, writerScene{
		table: "human_sessions", event: "UPDATE OF presented_methods",
		seed: l.seedPerson,
		write: func(ctx context.Context, p writerPerson) error {
			_, err := l.stepUp.Execute(ctx, humansession.StepUpInput{
				Bearer: p.bearer, Method: assurance.MethodPassword, Password: writerScenePassword, Source: writerSceneSource,
			})
			return err
		},
	})
}

func TestIntegration_SessionWriterSecondFactorConfirmAndIdentityDeletionDoNotDeadlock(t *testing.T) {
	l := newSessionWriterLane(t)
	started := map[domain.UserID]totpverify.Secret{}
	runWriterScene(t, l, writerScene{
		table: "user_login_methods", event: "UPDATE",
		seed: func(t *testing.T) writerPerson {
			p := l.seedPerson(t)
			en, err := l.enroll.Execute(context.Background(), humansession.EnrollInput{Bearer: p.bearer})
			require.NoError(t, err, "посев: заведение начато")
			started[p.id] = en.Secret
			return p
		},
		write: func(ctx context.Context, p writerPerson) error {
			code, err := totpCodeValue(started[p.id], totpverify.StepAt(time.Now()))
			if err != nil {
				return err
			}
			_, err = l.confirm.Execute(ctx, humansession.ConfirmInput{Bearer: p.bearer, Code: code, Source: writerSceneSource})
			return err
		},
	})
}

func TestIntegration_SessionWriterBackupCodesAndIdentityDeletionDoNotDeadlock(t *testing.T) {
	l := newSessionWriterLane(t)
	runWriterScene(t, l, writerScene{
		table: "user_login_methods", event: "UPDATE",
		seed: l.seedEnrolledPerson,
		write: func(ctx context.Context, p writerPerson) error {
			_, err := l.regen.Execute(ctx, humansession.RegenerateBackupCodesInput{
				Bearer: p.bearer, Source: writerSceneSource,
				Factor: humansession.SecondFactorPresentation{Method: assurance.MethodLookupSecret, Code: p.backup[0]},
			})
			return err
		},
	})
}

func TestIntegration_SessionWriterSecondFactorRemovalAndIdentityDeletionDoNotDeadlock(t *testing.T) {
	l := newSessionWriterLane(t)
	runWriterScene(t, l, writerScene{
		table: "user_login_methods", event: "DELETE",
		seed: l.seedEnrolledPerson,
		write: func(ctx context.Context, p writerPerson) error {
			_, err := l.remove.Execute(ctx, humansession.RemoveSecondFactorInput{
				Bearer: p.bearer, Source: writerSceneSource,
				Factor: humansession.SecondFactorPresentation{Method: assurance.MethodLookupSecret, Code: p.backup[0]},
			})
			return err
		},
	})
}

func TestIntegration_SessionWriterRecoveryCompletionAndIdentityDeletionDoNotDeadlock(t *testing.T) {
	l := newSessionWriterLane(t)
	codes := map[domain.UserID]string{}
	runWriterScene(t, l, writerScene{
		table: "user_login_methods", event: "UPDATE",
		seed: func(t *testing.T) writerPerson {
			ctx := context.Background()
			p := l.seedPerson(t)
			require.NoError(t, l.request.Execute(ctx, humansession.RequestRecoveryInput{
				Email: p.email, Source: writerSceneSource,
			}), "посев: запрос кода")
			var code string
			require.NoError(t, l.s.pool.QueryRow(ctx,
				`SELECT payload->>'code' FROM kaname.invite_mail_outbox
				  WHERE resource_id = $1 AND event_type = 'mail.recovery.send'`, string(p.id)).Scan(&code),
				"посев: письмо с кодом поставлено")
			require.NotEmpty(t, code, "посев: письмо несёт код")
			codes[p.id] = code
			return p
		},
		write: func(ctx context.Context, p writerPerson) error {
			_, err := l.complete.Execute(ctx, humansession.CompleteRecoveryInput{
				Email: p.email, Code: codes[p.id], NewPassword: writerSceneNewPassword, Source: writerSceneSource,
			})
			return err
		},
	})
}

func TestIntegration_SessionWriterSweepAndIdentityDeletionDoNotDeadlock(t *testing.T) {
	l := newSessionWriterLane(t)
	runWriterScene(t, l, writerScene{
		table: "human_sessions", event: "DELETE",
		seed: func(t *testing.T) writerPerson {
			p := l.seedPerson(t)
			_, err := l.s.pool.Exec(context.Background(),
				`UPDATE kaname.human_sessions SET ended_at = now() - interval '2 hours', ended_reason = 'logout'
				  WHERE user_id = $1`, string(p.id))
			require.NoError(t, err, "посев: запись сессии, которую уборка уже берёт")
			return p
		},
		write: func(ctx context.Context, p writerPerson) error {
			n, _, err := l.s.sessions.SweepUnservableSessions(ctx, time.Hour, 1000)
			if err == nil && n == 0 {
				return stderrors.New("уборка не взяла ни одной записи — сцена судила бы пустое место")
			}
			return err
		},
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// Контрольная рука: ОБРАТНЫЙ порядок захвата в той же сцене обязан дать
// взаимную блокировку.

func TestIntegration_ReverseLockOrderControlArmDeadlocksWithIdentityDeletion(t *testing.T) {
	l := newSessionWriterLane(t)
	ctx := context.Background()
	pool := l.s.pool
	installOneShotHold(t, ctx, pool, writerSceneHold, "human_sessions", "UPDATE OF last_presented_at")
	deadlocksBefore := databaseDeadlocks(t, ctx, pool)

	const rounds = 3
	var waiters, failures int
	for round := 0; round < rounds; round++ {
		p := l.seedPerson(t)
		writeDone := make(chan error, 1)
		deleteDone := make(chan error, 1)
		armOneShotHold(t, ctx, pool, writerSceneHold, 1)
		go func() {
			writeDone <- func() error {
				tx, err := pool.Begin(ctx)
				if err != nil {
					return err
				}
				defer func() { _ = tx.Rollback(ctx) }()
				// Строка сессии — ПЕРВОЙ, строка личности — после неё, проверкой
				// внешнего ключа отсечки: порядок, встречный удалению.
				if _, err := tx.Exec(ctx,
					`UPDATE kaname.human_sessions SET last_presented_at = now() WHERE user_id = $1`, string(p.id)); err != nil {
					return err
				}
				if _, err := tx.Exec(ctx,
					`INSERT INTO kaname.user_token_revocations (user_id, revoke_before, reason)
					 VALUES ($1, now(), 'logout')
					 ON CONFLICT (user_id) DO UPDATE SET revoke_before = EXCLUDED.revoke_before`, string(p.id)); err != nil {
					return err
				}
				return tx.Commit(ctx)
			}()
		}()
		awaitSleepingBackend(t, ctx, pool)
		go func() { deleteDone <- deletePerson(ctx, l.users, p.id) }()
		writeErr := <-writeDone
		deleteErr := <-deleteDone
		disarmOneShotHold(t, ctx, pool, writerSceneHold)
		waiters += requireHoldSceneBuilt(t, ctx, pool, writerSceneHold)
		if writeErr != nil || deleteErr != nil {
			failures++
		}
		t.Logf("прогон %d: обратный порядок: ошибка=%v · удаление: ошибка=%v", round, writeErr, deleteErr)
	}
	deadlocksAfter := deadlocksAfterPoolClose(t, ctx, l.s.dsn, pool)
	t.Logf("прогонов %d · ждавших замка %d · прогонов с отказом %d · pg_stat_database.deadlocks +%d",
		rounds, waiters, failures, deadlocksAfter-deadlocksBefore)
	require.Equal(t, int64(rounds), deadlocksAfter-deadlocksBefore,
		"контрольная рука с обратным порядком захвата обязана давать взаимную блокировку в каждом прогоне — "+
			"иначе сцены писателей не способны её увидеть, и их «ноль» ничего не утверждает")
}
