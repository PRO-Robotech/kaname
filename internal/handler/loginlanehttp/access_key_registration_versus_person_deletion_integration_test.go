// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package loginlanehttp_test

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

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_keys"
)

const registrationDeletionHold = "probe_registration_deletion_hold"

// installRegistrationHold — однократная задержка после потребления испытания:
// держит замки, пока в базе не появится ждущий замка, но не дольше 5 с.
// Исход — `_seen` (сколько ждущих держатель видел, отпуская).
func installRegistrationHold(t *testing.T, h *sessionLane) {
	t.Helper()
	name := registrationDeletionHold
	for _, q := range []string{
		`CREATE SEQUENCE kaname.` + name + `_seq`,
		`CREATE SEQUENCE kaname.` + name + `_seen MINVALUE 0`,
	} {
		_, err := h.pool.Exec(h.ctx, q)
		require.NoError(t, err, "состояние задержки: %s", q)
	}
	_, err := h.pool.Exec(h.ctx, `
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
	_, err = h.pool.Exec(h.ctx, `CREATE TRIGGER `+name+` AFTER UPDATE ON kaname.access_key_challenges
		FOR EACH STATEMENT EXECUTE FUNCTION kaname.`+name+`()`)
	require.NoError(t, err, "триггер задержки")
}

// laneDeadlocks — счётчик взаимных блокировок базы своим соединением.
func laneDeadlocks(t *testing.T, h *sessionLane) int64 {
	t.Helper()
	conn, err := pgx.Connect(h.ctx, h.dsn)
	require.NoError(t, err)
	defer func() { _ = conn.Close(h.ctx) }()
	var n int64
	require.NoError(t, conn.QueryRow(h.ctx,
		`SELECT deadlocks FROM pg_stat_database WHERE datname = current_database()`).Scan(&n))
	return n
}

// TestIntegration_AccessKeyRegistrationAndPersonDeletionDoNotDeadlock — обе
// транзакции фиксируются, ни одна не получает 40P01; ключа у удалённой
// личности нет. Законный близнец — та же регистрация без конкурента: ключ
// заведён (сцена способна дойти до вставки).
func TestIntegration_AccessKeyRegistrationAndPersonDeletionDoNotDeadlock(t *testing.T) {
	h := newSessionLane(t)
	u := h.user.ID
	h.login(t, integrationPassword)

	twin, err := h.finishRegistration(t, h.beginRegistration(t, u))
	require.NoError(t, err, "близнец: регистрация без конкурента принята")
	require.Nil(t, twin.Error, "близнец: регистрация без конкурента исполнена: %v", twin.Error)
	require.Equal(t, 1, h.keysOf(t, u), "близнец: ключ заведён")

	pending := h.beginRegistration(t, u)
	installRegistrationHold(t, h)
	deadlocksBefore := laneDeadlocks(t, h)

	uc, err := access_keys.NewFinishRegistrationUseCase(h.keyDeps(), operations.NewRepo(h.pool, "kaname"))
	require.NoError(t, err)
	op, err := uc.Execute(h.ctx, pending.in)
	require.NoError(t, err, "синхронная часть регистрации принята")

	// Держатель уснул в задержке — удаление приходит в окно.
	deadline := time.Now().Add(10 * time.Second)
	for {
		var sleeping int
		require.NoError(t, h.pool.QueryRow(h.ctx, `SELECT count(*) FROM pg_stat_activity
			 WHERE datname = current_database() AND wait_event = 'PgSleep'`).Scan(&sleeping))
		if sleeping > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("отказ фикстуры: регистрация не вошла в задержку за 10 с — сцена не построена")
		}
		time.Sleep(10 * time.Millisecond)
	}
	deleted := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_, err := h.pool.Exec(ctx, `DELETE FROM kaname.users WHERE id = $1`, string(u))
		deleted <- err
	}()
	done := h.awaitOp(t, op.ID)
	delErr := <-deleted

	var seen int64
	require.NoError(t, h.pool.QueryRow(h.ctx, `SELECT last_value FROM kaname.`+registrationDeletionHold+`_seen`).Scan(&seen))
	if seen < 1 {
		t.Fatalf("отказ фикстуры: держатель отпустил замки по сроку, не видя ждущего — сцена не построена")
	}
	deadlocksAfter := laneDeadlocks(t, h)
	t.Logf("ждавших замка %d · регистрация: ошибка=%v · удаление: ошибка=%v · deadlocks +%d",
		seen, done.Error, delErr, deadlocksAfter-deadlocksBefore)
	assert.NoError(t, delErr, "удаление личности фиксируется")
	assert.Nil(t, done.Error, "регистрация исполнена без взаимной блокировки")
	assert.Zero(t, h.keysOf(t, u), "у удалённой личности ключей нет")
}
