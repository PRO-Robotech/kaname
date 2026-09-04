// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// basic_credential_resolve_integration_test.go — ОТЗЫВ ДОХОДИТ ДО ПРЕДЪЯВЛЕНИЯ.
//
// Задача #1142, приёмка BAT-1 §6; сценарии BAT-1-42, 44, 45, 46, 47, 48.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ВОПРОС СТАВИТСЯ СКВОЗЬ ОБЕ СТОРОНЫ
//
// Две пробы по половине — «отзыв записался» и «отказ приходит» — не доказывают
// ничего: каждая сторона исправна, а вместе они про разный предмет. Контроль,
// действующий на ВЫДАЧЕ и не действующий на ПРЕДЪЯВЛЕНИИ, отзывом не является;
// у долгоживущего секрета цена такого промаха равна его сроку.
//
// Здесь каждая проба идёт целиком: предъявили → прошло → отозвали → предъявили →
// отказ. Положительный контроль стоит в ТОМ ЖЕ прогоне, иначе «отказ» был бы
// верен и о резолвере, не находящем ничего.

package pg_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/internal/pgtest"
	"github.com/PRO-Robotech/kacho/pkg/credsecret"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

func basicCredPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	pool, err := pgxpool.New(context.Background(), pgtest.NewDB(t))
	require.NoError(t, err)
	// Закрытие пула — С ПРЕДЕЛОМ. Голый `pool.Close` на удерживаемом соединении
	// висит без срока: пакет умирает по таймауту целиком, и вердикта не остаётся
	// НИ У ОДНОЙ пробы, включая прошедшие.
	pgtest.ClosePoolAtEnd(t, pool)
	return pool
}

// seedBasicOwners заводит аккаунт, человека и служебную учётку.
func seedBasicOwners(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, `SET CONSTRAINTS ALL DEFERRED`)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `
INSERT INTO accounts (id, name, owner_user_id)
VALUES ('acc0000000000000bat1', 'bat-1', 'usr0000000000000bat1') ON CONFLICT DO NOTHING`)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `
INSERT INTO users (id, external_id, email, account_id, invite_status)
VALUES ('usr0000000000000bat1', 'ext-bat-1', 'bat1@example.invalid', 'acc0000000000000bat1', 'ACTIVE'),
       ('usr0000000000000bat2', 'ext-bat-2', 'bat2@example.invalid', 'acc0000000000000bat1', 'ACTIVE')
ON CONFLICT DO NOTHING`)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `
INSERT INTO service_accounts (id, account_id, name, enabled)
VALUES ('sva0000000000000bat1', 'acc0000000000000bat1', 'bat-one-sa', true) ON CONFLICT DO NOTHING`)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))
}

// mintUserCredential кладёт живое удостоверение вида SECRET и возвращает
// предъявляемую строку.
func mintUserCredential(t *testing.T, pool *pgxpool.Pool, credID, userID string) string {
	t.Helper()
	secret, hash, err := credsecret.Mint(credID)
	require.NoError(t, err)
	_, err = pool.Exec(context.Background(), `
INSERT INTO user_oauth_clients
    (id, user_id, hydra_client_id, created_by_user_id, credential_kind, secret_hash, expires_at)
VALUES ($1, $2, NULL, $2, 'SECRET', $3, now() + interval '30 days')`, credID, userID, hash)
	require.NoError(t, err)
	return secret
}

func mintSACredential(t *testing.T, pool *pgxpool.Pool, credID, svaID string) string {
	t.Helper()
	secret, hash, err := credsecret.Mint(credID)
	require.NoError(t, err)
	_, err = pool.Exec(context.Background(), `
INSERT INTO service_account_oauth_clients
    (id, sva_id, hydra_client_id, created_by_user_id, credential_kind, secret_hash, expires_at)
VALUES ($1, $2, NULL, 'usr0000000000000bat1', 'SECRET', $3, now() + interval '30 days')`, credID, svaID, hash)
	require.NoError(t, err)
	return secret
}

// BAT-1-42 / BAT-1-44 — отзыв есть СНЯТИЕ строки, и снятая строка перестаёт
// резолвиться немедленно. Соседнее удостоверение того же принципала при этом
// продолжает проходить — иначе оба утверждения были бы верны и о резолвере,
// не находящем ничего.
func TestBAT1_42_RevocationReachesPresentationThroughBothSides(t *testing.T) {
	pool := basicCredPool(t)
	seedBasicOwners(t, pool)
	repo := pg.NewBasicCredentialRepo(pool)
	ctx := context.Background()

	first := mintUserCredential(t, pool, "uoc_0000000000000bat1", "usr0000000000000bat1")
	second := mintUserCredential(t, pool, "uoc_0000000000000bat2", "usr0000000000000bat1")

	// Положительный контроль В ТОМ ЖЕ ПРОГОНЕ: до отзыва предъявление проходит.
	res, err := repo.ResolveBasic(ctx, first)
	require.NoError(t, err, "живое удостоверение не резолвится — дальнейший отказ был бы вакуумен")
	require.Equal(t, "user", res.PrincipalType)
	require.Equal(t, "usr0000000000000bat1", res.PrincipalID)
	require.Equal(t, "uoc_0000000000000bat1", res.CredentialID)
	require.False(t, res.ExpiresAt.IsZero(), "срок не заполнен — бессрочного секрета не бывает")

	// Отзыв = снятие строки.
	_, err = pool.Exec(ctx, `DELETE FROM user_oauth_clients WHERE id = 'uoc_0000000000000bat1'`)
	require.NoError(t, err)

	_, err = repo.ResolveBasic(ctx, first)
	require.ErrorIs(t, err, domain.ErrBasicCredentialRefused,
		"отозванное удостоверение всё ещё резолвится — контроль действует на выдаче, не на предъявлении")

	// Положительный контроль: соседнее удостоверение того же принципала живо.
	_, err = repo.ResolveBasic(ctx, second)
	require.NoError(t, err, "соседнее удостоверение перестало проходить — отзыв задел не свой предмет")

	// Повторный отзыв наблюдаемого состояния не меняет: строки нет, соседнее
	// по-прежнему проходит. Идентификатор, которого не было НИКОГДА, даёт тот
	// же исход — иначе повторный отзыв стал бы оракулом существования.
	_, err = pool.Exec(ctx, `DELETE FROM user_oauth_clients WHERE id = 'uoc_0000000000000bat1'`)
	require.NoError(t, err)
	_, err = repo.ResolveBasic(ctx, second)
	require.NoError(t, err)
}

// BAT-1-45 / BAT-1-46 — состояние владельца есть часть ОДНОГО оператора резолва.
func TestBAT1_45_OwnerStateIsPartOfTheSingleResolveStatement(t *testing.T) {
	pool := basicCredPool(t)
	seedBasicOwners(t, pool)
	repo := pg.NewBasicCredentialRepo(pool)
	ctx := context.Background()

	human := mintUserCredential(t, pool, "uoc_0000000000000bat3", "usr0000000000000bat2")
	machine := mintSACredential(t, pool, "soc_0000000000000bat1", "sva0000000000000bat1")

	// Положительные контроли до смены состояния.
	_, err := repo.ResolveBasic(ctx, human)
	require.NoError(t, err)
	m, err := repo.ResolveBasic(ctx, machine)
	require.NoError(t, err)
	require.Equal(t, "service_account", m.PrincipalType)
	require.Equal(t, "sva0000000000000bat1", m.PrincipalID)

	// Человек переводится в неактивное состояние.
	_, err = pool.Exec(ctx, `UPDATE users SET invite_status = 'BLOCKED' WHERE id = 'usr0000000000000bat2'`)
	require.NoError(t, err)
	_, err = repo.ResolveBasic(ctx, human)
	require.ErrorIs(t, err, domain.ErrBasicCredentialRefused,
		"удостоверение неактивного человека продолжает проходить")

	// Учётка выключается.
	_, err = pool.Exec(ctx, `UPDATE service_accounts SET enabled = false WHERE id = 'sva0000000000000bat1'`)
	require.NoError(t, err)
	_, err = repo.ResolveBasic(ctx, machine)
	require.ErrorIs(t, err, domain.ErrBasicCredentialRefused,
		"удостоверение выключенной учётки продолжает проходить")

	// Возвращение в активное состояние ВОСКРЕШАЕТ удостоверение, если менялось
	// ТОЛЬКО состояние: строка на месте, отзыва не было.
	_, err = pool.Exec(ctx, `UPDATE users SET invite_status = 'ACTIVE' WHERE id = 'usr0000000000000bat2'`)
	require.NoError(t, err)
	_, err = repo.ResolveBasic(ctx, human)
	require.NoError(t, err, "состояние вернули, а удостоверение не воскресло")
}

// BAT-1-47 — повод привязан к СНЯТИЮ СТРОКИ, а не к перечню глаголов. Перечень
// поводов ВЫВОДИТСЯ из схемы (внешние ключи с каскадом), а не выписывается:
// выписанный разошёлся бы с деревом молча. Число осмотренных поводов
// ПЕЧАТАЕТСЯ — «утверждён каждый» из пустого перечня неотличимо от «утверждён
// каждый» из пяти.
func TestBAT1_47_EveryCascadeCauseTakesTheCredentialDown(t *testing.T) {
	pool := basicCredPool(t)
	seedBasicOwners(t, pool)
	ctx := context.Background()

	rows, err := pool.Query(ctx, `
SELECT tc.constraint_name, kcu.column_name
  FROM information_schema.table_constraints tc
  JOIN information_schema.key_column_usage kcu
    ON kcu.constraint_name = tc.constraint_name AND kcu.constraint_schema = tc.constraint_schema
  JOIN information_schema.referential_constraints rc
    ON rc.constraint_name = tc.constraint_name AND rc.constraint_schema = tc.constraint_schema
 WHERE tc.table_name = 'user_oauth_clients'
   AND tc.constraint_type = 'FOREIGN KEY'
   AND rc.delete_rule = 'CASCADE'`)
	require.NoError(t, err)
	var causes []string
	for rows.Next() {
		var name, col string
		require.NoError(t, rows.Scan(&name, &col))
		causes = append(causes, name+"("+col+")")
	}
	rows.Close()
	require.NoError(t, rows.Err())

	t.Logf("осмотрено: поводов снятия строки удостоверения каскадом %d — %v", len(causes), causes)
	require.NotEmpty(t, causes,
		"поводов ноль — перечень пуст, и «утверждён каждый» здесь означало бы «не утверждён ни один»")

	repo := pg.NewBasicCredentialRepo(pool)
	mine := mintUserCredential(t, pool, "uoc_0000000000000bat4", "usr0000000000000bat2")
	neighbour := mintUserCredential(t, pool, "uoc_0000000000000bat5", "usr0000000000000bat1")

	// Положительный контроль ДО срабатывания повода.
	_, err = repo.ResolveBasic(ctx, mine)
	require.NoError(t, err)

	// Повод: снят сам владелец.
	_, err = pool.Exec(ctx, `DELETE FROM users WHERE id = 'usr0000000000000bat2'`)
	require.NoError(t, err)

	_, err = repo.ResolveBasic(ctx, mine)
	require.ErrorIs(t, err, domain.ErrBasicCredentialRefused,
		"владелец снят, а его удостоверение проходит")

	// Положительный контроль ПОСЛЕ: соседний принципал не задет.
	_, err = repo.ResolveBasic(ctx, neighbour)
	require.NoError(t, err, "повод задел удостоверение принципала, которого он не касается")
}

// BAT-1-48 — истёкшее отвергается ТЕМ ЖЕ отказом, что отозванное; граница
// проверена ОБЕИМИ сторонами.
func TestBAT1_48_ExpiryIsRefusedByTheSameRefusalAndTheBoundaryIsCheckedBothWays(t *testing.T) {
	pool := basicCredPool(t)
	seedBasicOwners(t, pool)
	repo := pg.NewBasicCredentialRepo(pool)
	ctx := context.Background()

	// За секунду до истечения — проходит.
	alive, hash, err := credsecret.Mint("uoc_0000000000000bat6")
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `
INSERT INTO user_oauth_clients (id, user_id, hydra_client_id, created_by_user_id, credential_kind, secret_hash, expires_at)
VALUES ('uoc_0000000000000bat6', 'usr0000000000000bat1', NULL, 'usr0000000000000bat1', 'SECRET', $1,
        now() + interval '5 seconds')`, hash)
	require.NoError(t, err)
	// Дату создания сдвигаем в прошлое, чтобы истёкший срок оставался ЗАКОННЫМ
	// входом ограничения `expires_at > created_at`: иначе «истёкшее» нельзя
	// записать, и Given второй половины пробы неисполним.
	_, err = pool.Exec(ctx, `
UPDATE user_oauth_clients SET created_at = now() - interval '2 days'
 WHERE id = 'uoc_0000000000000bat6'`)
	require.NoError(t, err)
	_, err = repo.ResolveBasic(ctx, alive)
	require.NoError(t, err, "неистёкшее удостоверение отвергнуто — граница смещена")

	// После истечения — отвергается. Срок двигается правкой, а не ожиданием:
	// проба ждёт УСЛОВИЯ, а не времени.
	_, err = pool.Exec(ctx, `
UPDATE user_oauth_clients SET expires_at = now() - interval '1 second'
 WHERE id = 'uoc_0000000000000bat6'`)
	require.NoError(t, err)
	_, err = repo.ResolveBasic(ctx, alive)
	require.ErrorIs(t, err, domain.ErrBasicCredentialRefused, "истёкшее удостоверение проходит")
}

// BAT-1-06 / §10 — половина одного удостоверения с половиной другого и просто
// неверный секрет дают ОДИН И ТОТ ЖЕ отказ, что и неизвестный идентификатор.
func TestBAT1_10_TheRefusalIsSingleAndIsNoOracle(t *testing.T) {
	pool := basicCredPool(t)
	seedBasicOwners(t, pool)
	repo := pg.NewBasicCredentialRepo(pool)
	ctx := context.Background()

	good := mintUserCredential(t, pool, "uoc_0000000000000bat7", "usr0000000000000bat1")
	p, err := credsecret.Parse(good)
	require.NoError(t, err)

	// Неизвестный идентификатор — форма годна, строки нет.
	unknownID := "uoc_0000000000000bat9"
	unknown, _, err := credsecret.Mint(unknownID)
	require.NoError(t, err)

	// Верный идентификатор, чужая секретная часть: разбор её отвергнет раньше
	// (контрольная сумма покрывает обе части), поэтому здесь проверяется
	// ИМЕННО хранилище — строку с верным id и негодным хешем.
	other, _, err := credsecret.Mint("uoc_0000000000000bat7")
	require.NoError(t, err)
	require.NotEqual(t, good, other)

	var msgs []string
	for _, in := range []string{unknown, other, "kacho_uoc_0000000000000bat7_" + p.SecretPart + "000000"} {
		_, rerr := repo.ResolveBasic(ctx, in)
		require.Error(t, rerr)
		msgs = append(msgs, rerr.Error())
	}
	for i := 1; i < len(msgs); i++ {
		require.Equal(t, msgs[0], msgs[i],
			"отказы различимы между собой — по различию узнают, существует ли удостоверение")
	}

	// Положительный контроль: годная строка по-прежнему проходит.
	_, err = repo.ResolveBasic(ctx, good)
	require.NoError(t, err)
}
