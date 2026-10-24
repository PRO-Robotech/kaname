// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_iam_test

// access_key_registration_versus_person_deletion_integration_test.go —
// завершение регистрации ключа доступа против удаления той же личности
// (задача PRO-Robotech/kaname#775).
//
// Сцена: транзакция регистрации взяла строку рукоятки церемонии
// (`EnsureCeremonyHandle`, ветвь конфликта) и строку испытания
// (`ConsumeChallenge`) и спит в однократной задержке после потребления
// испытания, не зафиксировавшись. В окно приходит удаление личности: оно берёт
// строку `users` и каскадом идёт к детям — к той же рукоятке. Затем задержка
// отпускается, и вставка ключа берёт личность проверкой внешнего ключа.
// Регистрация, взявшая детей раньше личности, держит их и ждёт личность,
// удаление держит личность и ждёт детей — взаимная блокировка (40P01).
// Держатель задержки ждёт, пока удаление не встанет в ожидание ЗАМКА; не
// встало — отказ фикстуры, а не вердикт о предмете.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_keys"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/webauthnverify"
	"github.com/PRO-Robotech/kaname/internal/webauthnverify/webauthntest"
)

const registrationDeletionHold = "probe_registration_deletion_hold"

const (
	regSceneRPID   = "console.example.invalid"
	regSceneOrigin = "https://" + regSceneRPID
)

func regKeyDeps(l *sessionWriterLane) access_keys.Deps {
	return access_keys.Deps{
		Store:     kanamepg.NewAccessKeyRepo(l.s.pool),
		Freshness: kanamepg.NewHumanSessionFreshness(l.s.pool),
		Methods:   kanamepg.NewLoginMethodRepo(l.s.pool),
		Binding: webauthnverify.Binding{RPID: regSceneRPID, Origins: []string{regSceneOrigin},
			Algorithms: []webauthnverify.Algorithm{webauthnverify.AlgES256}},
		FreshnessWindow: 15 * time.Minute,
		Now:             time.Now,
	}
}

// regPending — выданное испытание регистрации и собранный на нём результат.
func regPending(t *testing.T, l *sessionWriterLane, user domain.UserID) access_keys.FinishRegistrationInput {
	t.Helper()
	begin, err := access_keys.NewBeginRegistrationUseCase(regKeyDeps(l))
	require.NoError(t, err)
	out, err := begin.Execute(context.Background(), access_keys.BeginRegistrationInput{UserID: user, Actor: user})
	require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): испытание регистрации выдано")
	auth := webauthntest.New(t, webauthntest.AlgES256)
	cdj, att := auth.Register(t, webauthntest.RegistrationOptions{Challenge: out.Challenge, Origin: regSceneOrigin, RPID: regSceneRPID})
	rk := true
	return access_keys.FinishRegistrationInput{UserID: user, Actor: user, CredentialID: auth.CredentialID(),
		ClientDataJSON: cdj, AttestationObject: att, Discoverable: &rk}
}

func regAwaitOp(t *testing.T, l *sessionWriterLane, id string) *operations.Operation {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	require.NoError(t, operations.Wait(ctx), "НЕ ВЫПОЛНИЛОСЬ: исполнитель операций не завершил очередь")
	got, err := operations.NewRepo(l.s.pool, "kaname").Get(context.Background(), id)
	require.NoError(t, err)
	require.True(t, got.Done, "операция %s не терминальна", id)
	return got
}

func regKeysOf(t *testing.T, l *sessionWriterLane, user domain.UserID) int {
	t.Helper()
	var n int
	require.NoError(t, l.s.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM kaname.user_access_keys WHERE user_id = $1`, string(user)).Scan(&n))
	return n
}

// installRegistrationHold — однократная задержка после потребления испытания:
// держит замки, пока в базе не появится ждущий замка, но не дольше 5 с.
// Исход — `_seen` (сколько ждущих держатель видел, отпуская).
func installRegistrationHold(t *testing.T, l *sessionWriterLane) {
	t.Helper()
	ctx := context.Background()
	name := registrationDeletionHold
	for _, q := range []string{
		`CREATE SEQUENCE kaname.` + name + `_seq`,
		`CREATE SEQUENCE kaname.` + name + `_seen MINVALUE 0`,
	} {
		_, err := l.s.pool.Exec(ctx, q)
		require.NoError(t, err, "состояние задержки: %s", q)
	}
	_, err := l.s.pool.Exec(ctx, `
		CREATE FUNCTION kaname.`+name+`() RETURNS trigger
		LANGUAGE plpgsql AS $$
		DECLARE
			v_deadline timestamptz := clock_timestamp() + interval '5 seconds';
			v_seen     int;
		BEGIN
			IF nextval('kaname.`+name+`_seq') <> 1 THEN
				RETURN NULL;
			END IF;
			LOOP
				PERFORM pg_stat_clear_snapshot();
				SELECT count(*) INTO v_seen FROM pg_stat_activity
				 WHERE datname = current_database() AND wait_event_type = 'Lock';
				EXIT WHEN v_seen >= 1 OR clock_timestamp() >= v_deadline;
				PERFORM pg_sleep(0.005);
			END LOOP;
			PERFORM setval('kaname.`+name+`_seen', v_seen, true);
			RETURN NULL;
		END $$`)
	require.NoError(t, err, "функция задержки")
	_, err = l.s.pool.Exec(ctx, `CREATE TRIGGER `+name+` AFTER UPDATE ON kaname.access_key_challenges
		FOR EACH STATEMENT EXECUTE FUNCTION kaname.`+name+`()`)
	require.NoError(t, err, "триггер задержки")
}

// TestIntegration_AccessKeyRegistrationAndPersonDeletionDoNotDeadlock — обе
// транзакции фиксируются, ни одна не получает 40P01; ключа у удалённой
// личности нет. Законный близнец — та же регистрация без конкурента: ключ
// заведён (сцена способна дойти до вставки).
func TestIntegration_AccessKeyRegistrationAndPersonDeletionDoNotDeadlock(t *testing.T) {
	l := newSessionWriterLane(t)
	ctx := context.Background()
	pool := l.s.pool
	_, err := pool.Exec(ctx, `
		INSERT INTO kaname.own_ceilings (kind, limit_value) VALUES ('iam.user.accessKey', 8)
		ON CONFLICT (kind) DO UPDATE SET limit_value = EXCLUDED.limit_value`)
	require.NoError(t, err, "Дано: потолок вида ключа объявлен")
	p := l.seedPerson(t)

	finish, err := access_keys.NewFinishRegistrationUseCase(regKeyDeps(l), operations.NewRepo(pool, "kaname"))
	require.NoError(t, err)
	twinOp, err := finish.Execute(ctx, regPending(t, l, p.id))
	require.NoError(t, err, "близнец: регистрация без конкурента принята")
	twin := regAwaitOp(t, l, twinOp.ID)
	require.Nil(t, twin.Error, "близнец: регистрация без конкурента исполнена: %v", twin.Error)
	require.Equal(t, 1, regKeysOf(t, l, p.id), "близнец: ключ заведён")

	pending := regPending(t, l, p.id)
	installRegistrationHold(t, l)
	deadlocksBefore := databaseDeadlocks(t, ctx, pool)
	op, err := finish.Execute(ctx, pending)
	require.NoError(t, err, "синхронная часть регистрации принята")
	awaitSleepingBackend(t, ctx, pool)
	deleted := make(chan error, 1)
	go func() { deleted <- deletePerson(ctx, l.users, p.id) }()
	done := regAwaitOp(t, l, op.ID)
	delErr := <-deleted

	var seen int64
	require.NoError(t, pool.QueryRow(ctx, `SELECT last_value FROM kaname.`+registrationDeletionHold+`_seen`).Scan(&seen))
	if seen < 1 {
		t.Fatalf("отказ фикстуры: держатель отпустил замки по сроку, не видя ждущего — сцена не построена "+
			"(регистрация: %v · удаление: %v)", done.Error, delErr)
	}
	keys := regKeysOf(t, l, p.id)
	deadlocksAfter := deadlocksAfterPoolClose(t, ctx, l.s.dsn, pool)
	t.Logf("ждавших замка %d · регистрация: ошибка=%v · удаление: ошибка=%v · ключей после %d · deadlocks +%d",
		seen, done.Error, delErr, keys, deadlocksAfter-deadlocksBefore)
	assert.NoError(t, delErr, "удаление личности фиксируется")
	assert.Nil(t, done.Error, "регистрация исполнена без взаимной блокировки")
	assert.Zero(t, keys, "у удалённой личности ключей нет")
	assert.Zero(t, deadlocksAfter-deadlocksBefore, "pg_stat_database.deadlocks")
}
