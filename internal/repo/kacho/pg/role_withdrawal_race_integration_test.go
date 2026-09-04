// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// role_withdrawal_race_integration_test.go — СПОРНЫЕ ПУТИ отзыва роли под
// конкуренцией.
//
// Приёмка `services/iam/docs/engineering/acceptance/role-withdrawal-has-a-producer.md`
// (APPROVED круга 4); сценарии IAM-RW-1-26, IAM-RW-1-27, IAM-RW-1-28. Задача
// продукта #1913. Требование `data-integrity.md` §«Чек-лист нового ссылочного
// поля», п. 5: спорный путь без пробы под конкуренцией не мёржится — гонку
// юнит-тестом не поймать.
//
// # Порядок в -26 ОБЯЗАТЕЛЕН именно этот, и замок назван
//
// Снятие начинается ПЕРВЫМ и берёт свой замок; выдача идёт следом. Обратный
// порядок (создание первым) зелен на ВСЕХ ТРЁХ замках, включая два негодных, и
// различающей силы не имеет: страж успевает прочитать роль живой раньше, чем
// снятие её тронуло, при любом замке.
//
// # Чего эта проба НЕ различает — сказано, чтобы её не читали шире
//
// ВЫБОР ЗАМКА она не различает, и объявлять обратное было бы заявлением шире
// сделанного. Запись решения выбирала `FOR SHARE` из довода «снятие правит
// неключевой столбец»; на сегодняшней схеме довод неверен — референт живости
// `roles_id_live_uk UNIQUE (id, live)` делает `live` КЛЮЧЕВОЙ, и `FOR KEY SHARE`
// конфликтует со снятием тоже. Инъекция это подтвердила: с `FOR KEY SHARE` все
// восемь вставок отвергнуты ровно так же.
//
// Проба утверждает СВОЙСТВО §2.4 — «новой ссылки на помеченную роль не появляется
// ни одной», — а не выбор замка. Вывод записи решения остаётся в силе по второму
// доводу: `FOR SHARE` верен и тогда, когда живость перестанет быть ключевой.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/moduleroles"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

// raceRole — живая роль модуля со своими проекциями, субъектом и аккаунтом.
//
// Фикстура полная НАМЕРЕННО: гонка, поставленная на роль без проекций, зеленела
// бы на любом ключе — отвергать было бы нечего.
func raceRole(t *testing.T, ctx context.Context, pool *pgxpool.Pool, suffix string) domain.RoleID {
	t.Helper()

	name := domain.RoleName("vpc.rwrace" + suffix + ".admin")
	id := domain.SystemRoleID(name)

	// Аккаунт и человек ссылаются друг на друга отложенными ключами — одной
	// транзакцией, иначе их не вставить ни в каком порядке.
	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `
		INSERT INTO users (id, account_id, external_id, email, invite_status)
		VALUES ($1, $2, $3, $4, 'ACTIVE') ON CONFLICT DO NOTHING`,
		"usr_rwrace"+suffix, "acc_rwrace"+suffix, "ext-rwrace"+suffix,
		"rwrace"+suffix+"@example.test")
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `
		INSERT INTO accounts (id, name, owner_user_id)
		VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`,
		"acc_rwrace"+suffix, "rwrace-"+strings.ToLower(suffix), "usr_rwrace"+suffix)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))

	_, err = pool.Exec(ctx, `
		INSERT INTO roles (id, cluster_id, name, description, permissions, rules, owner_module)
		VALUES ($1, $2, $3, 'race probe', '["vpc.network.*.get"]'::jsonb, '[]'::jsonb, 'vpc')`,
		string(id), domain.ClusterSingletonID, string(name))
	require.NoError(t, err, "фикстура роли")

	_, err = pool.Exec(ctx, `
		INSERT INTO kacho_iam.role_verb (role_id, object_type, verb)
		VALUES ($1, 'vpc.network', 'get')`, string(id))
	require.NoError(t, err, "фикстура проекции глаголов")

	_, err = pool.Exec(ctx, `
		INSERT INTO kacho_iam.role_rule_ref (role_id, module, resource, verb)
		VALUES ($1, 'vpc', 'network', 'get')`, string(id))
	require.NoError(t, err, "фикстура проекции сегментов")

	return id
}

// retireInTx снимает роль в СВОЕЙ транзакции и держит её открытой до сигнала.
//
// Транзакция явная, а не через мост: предмет пробы — окно между взятием замка и
// коммитом, и закрывать его чужим кодом значило бы мерить не то.
func retireInTx(t *testing.T, ctx context.Context, pool *pgxpool.Pool, id domain.RoleID,
	locked chan<- struct{}, release <-chan struct{}) error {
	t.Helper()

	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Порядок «проекции → пометка» держит ключ; здесь он исполняется явно, тем же
	// порядком, что в писателе.
	for _, table := range []string{"role_verb", "role_rule_ref", "role_rule_selectors",
		"access_binding_target_members"} {
		if _, err = tx.Exec(ctx,
			`DELETE FROM kacho_iam.`+table+` WHERE role_id = $1`, string(id)); err != nil {
			return err
		}
	}
	if _, err = tx.Exec(ctx, `
		UPDATE kacho_iam.roles
		   SET live = false, retired_at = now(), retired_reason = 'гонка', retired_by = 'гонка'
		 WHERE id = $1 AND owner_module = 'vpc' AND live`, string(id)); err != nil {
		return err
	}

	close(locked)
	<-release
	return tx.Commit(ctx)
}

// TestIAMRW126RetirementAgainstANewGrant — IAM-RW-1-26.
//
// Снятие берёт замок ПЕРВЫМ; N попыток создать выдачу идут конкурентно. Исходов
// ровно два, и третьего нет: выдача создана ДО пометки и переживает снятие, либо
// отвергнута. НОВОЙ ссылки на помеченную роль не появляется ни одной.
func TestIAMRW126RetirementAgainstANewGrant(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx, pool := catalogPool(t)
	id := raceRole(t, ctx, pool, "grant")

	const attempts = 8
	locked := make(chan struct{})
	release := make(chan struct{})

	var retireErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		retireErr = retireInTx(t, ctx, pool, id, locked, release)
	}()
	<-locked

	created := make([]bool, attempts)
	refused := make([]bool, attempts)
	var leaked []string
	var mu sync.Mutex

	var attemptWG sync.WaitGroup
	for i := 0; i < attempts; i++ {
		attemptWG.Add(1)
		go func(i int) {
			defer attemptWG.Done()
			// Срок на попытку: она БЛОКИРУЕТСЯ на замке снимающей транзакции, и
			// без срока проба висела бы, а не отвечала.
			c, cancel := context.WithTimeout(ctx, 20*time.Second)
			defer cancel()
			_, err := pool.Exec(c, `
				INSERT INTO kacho_iam.access_bindings
				       (id, subject_type, subject_id, role_id, resource_type, resource_id, status)
				VALUES ($1, 'user', $2, $3, 'cluster', $4, 'ACTIVE')`,
				fmt.Sprintf("acb_rwrace%02d", i), "usr_rwracegrant", string(id),
				domain.ClusterSingletonID)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				created[i] = true
			default:
				refused[i] = true
				var pgErr *pgconn.PgError
				if errors.As(err, &pgErr) && pgErr.ConstraintName != "access_bindings_role_is_live" {
					leaked = append(leaked, pgErr.Code+": "+pgErr.ConstraintName)
				}
			}
		}(i)
	}

	// Снятие отпускается ПОСЛЕ того, как попытки встали на замок: иначе они прошли
	// бы до пометки, и проба измерила бы отсутствие гонки.
	time.Sleep(300 * time.Millisecond)
	close(release)
	wg.Wait()
	attemptWG.Wait()
	require.NoError(t, retireErr, "снятие обязано пройти: оно взяло замок первым")

	var createdN, refusedN int
	for i := 0; i < attempts; i++ {
		if created[i] {
			createdN++
		}
		if refused[i] {
			refusedN++
		}
	}
	t.Logf("перепись: попыток %d, создано %d, отвергнуто %d", attempts, createdN, refusedN)
	require.Equal(t, attempts, createdN+refusedN,
		"исходов ровно два, и третьего нет: попытка без исхода означает, что проба "+
			"не дождалась ответа")
	assert.Empty(t, leaked,
		"отказ пришёл не от стража, а от чужой связи — вызывающий получил бы отказ "+
			"не о том: %v", leaked)

	// НЕСУЩЕЕ: новой ссылки на ПОМЕЧЕННУЮ роль нет ни одной.
	var live bool
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT live FROM roles WHERE id = $1`, string(id)).Scan(&live))
	require.False(t, live, "роль обязана быть снята — иначе гонки не было")

	var bindings int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM access_bindings WHERE role_id = $1`, string(id)).Scan(&bindings))
	assert.Equal(t, createdN, bindings,
		"строк выдачи в базе не столько, сколько попыток отчиталось успехом: "+
			"либо появилась ссылка на помеченную роль, либо успех был ложным")

	// НЕСУЩЕЕ УТВЕРЖДЕНИЕ §2.4: новой ссылки на ПОМЕЧЕННУЮ роль не появляется.
	//
	// Оба исхода попытки законны, поэтому числом их не различить — различает
	// ВРЕМЯ: выдача, созданная ПОЗЖЕ момента снятия, и есть та новая ссылка,
	// которой §2.4 требует не допустить.
	//
	// Замка это утверждение НЕ различает: инъекция `FOR KEY SHARE` оставила его
	// зелёным, и почему — сказано в шапке файла. Оно закрепляет свойство, а не
	// выбор средства.
	var late int
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*)
		  FROM access_bindings b
		  JOIN roles r ON r.id = b.role_id
		 WHERE b.role_id = $1 AND r.retired_at IS NOT NULL AND b.created_at > r.retired_at`,
		string(id)).Scan(&late))
	assert.Zero(t, late,
		"появилось %d выдач ПОЗЖЕ момента снятия роли: это новая ссылка на помеченную "+
			"роль — ровно то, чего §2.4 требует не допустить. Причину искать в замке "+
			"стража либо в его раннем выходе", late)
}

// TestIAMRW127RetirementAgainstRevival — IAM-RW-1-27.
//
// Снятие и оживление идут одновременно. Проходит ровно одно; итоговое состояние
// СОГЛАСОВАНО (`live = (retired_at IS NULL)`), строка ОДНА, `id` не изменился.
func TestIAMRW127RetirementAgainstRevival(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx, pool := catalogPool(t)
	id := raceRole(t, ctx, pool, "revive")

	repo := kachopg.New(pool, nil)
	runner := moduleroles.NewRepoTxRunner(repo)

	var wg sync.WaitGroup
	var retireErr, reviveErr error
	start := make(chan struct{})

	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		retireErr = runner.RunInWriteTx(ctx, func(ctx context.Context, w moduleroles.RoleWriter) error {
			_, err := w.RetireRole(ctx, id, "vpc", "гонка снятия", "actor-retire")
			return err
		})
	}()
	go func() {
		defer wg.Done()
		<-start
		reviveErr = runner.RunInWriteTx(ctx, func(ctx context.Context, w moduleroles.RoleWriter) error {
			_, err := w.ReviveRole(ctx, id)
			return err
		})
	}()
	close(start)
	wg.Wait()

	// Оба исхода законны: оживление живой роли — «оживлять нечего», снятие уже
	// снятой — «снимать нечего». Отказом ни то, ни другое не является.
	require.NoError(t, retireErr, "снятие отказало: %v", retireErr)
	require.NoError(t, reviveErr, "оживление отказало: %v", reviveErr)

	var rows int
	var live bool
	var retiredAt *time.Time
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM roles WHERE id = $1`, string(id)).Scan(&rows))
	assert.Equal(t, 1, rows, "строка обязана остаться ОДНА: id выводится из имени")

	require.NoError(t, pool.QueryRow(ctx,
		`SELECT live, retired_at FROM roles WHERE id = $1`, string(id)).Scan(&live, &retiredAt))
	assert.Equal(t, live, retiredAt == nil,
		"состояние рассогласовано: live=%v при retired_at=%v — согласие держит CHECK, "+
			"и его нарушение означало бы, что проверку обошли", live, retiredAt)
	t.Logf("перепись: строк %d, живость %v, момент снятия %v", rows, live, retiredAt != nil)
}

// TestIAMRW128RetirementAgainstProjectionWrite — IAM-RW-1-28.
//
// Снятие и запись проекции идут конкурентно. Состояние «роль помечена снятой, а
// живая проекция существует» не наблюдается НИ В ОДИН момент — его отвергает
// ключ живости; проигравшая транзакция получает `23503`, а не частичный
// результат.
func TestIAMRW128RetirementAgainstProjectionWrite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx, pool := catalogPool(t)
	id := raceRole(t, ctx, pool, "proj")

	locked := make(chan struct{})
	release := make(chan struct{})

	var retireErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		retireErr = retireInTx(t, ctx, pool, id, locked, release)
	}()
	<-locked

	// Запись проекции в СВОЕЙ транзакции, пока снятие держит свою.
	writeErr := make(chan error, 1)
	go func() {
		c, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		_, err := pool.Exec(c, `
			INSERT INTO kacho_iam.role_verb (role_id, object_type, verb)
			VALUES ($1, 'vpc.network', 'list')`, string(id))
		writeErr <- err
	}()

	time.Sleep(300 * time.Millisecond)
	close(release)
	wg.Wait()
	require.NoError(t, retireErr, "снятие обязано пройти: оно взяло замок первым")

	werr := <-writeErr
	require.Error(t, werr,
		"запись проекции под снятой ролью прошла: состояние «роль помечена, а живая "+
			"проекция существует» стало наблюдаемым, и ключ живости его не отверг")
	var pgErr *pgconn.PgError
	require.ErrorAs(t, werr, &pgErr, "отказ пришёл не от сервера: %v", werr)
	assert.Equal(t, pgerrcode23503, pgErr.Code,
		"отказ обязан прийти нарушением ссылочной целостности, а не иным классом: %s %s",
		pgErr.Code, pgErr.ConstraintName)

	// Частичного результата нет: строк проекции у снятой роли ноль.
	var projections int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.role_verb WHERE role_id = $1`, string(id)).Scan(&projections))
	assert.Zero(t, projections,
		"у снятой роли осталась строка проекции — право продолжает действовать")
	t.Logf("перепись: отказ %s %s, строк проекции у снятой роли %d",
		pgErr.Code, pgErr.ConstraintName, projections)
}

// pgerrcode23503 — нарушение ссылочной целостности. Литерал назван константой,
// потому что он появляется в утверждении: голое число в `assert` читается как
// магическое.
const pgerrcode23503 = "23503"
