// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

// account_delete_cleanup_form_integration_test.go — снятие собственнического
// основания снимает и ВЫВЕДЕННОЕ из него право администратора.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Модель не хранит право администратора аккаунта отдельно: она выводит его из
// владения (`define admin: … or owner`). Значит удаление аккаунта обязано снять
// собственническое основание — иначе бывший владелец остаётся СТОЯЩИМ
// администратором объекта, которого уже нет, и заметно это было бы не пробой, а
// обращением.
//
// Обратная сторона того же вывода — она и делает пробу небанальной: снять прямой
// кортеж `v_get` мало, пока лежит `owner`, и снять `owner` мало, пока лежит
// прямой `v_get`. Утверждаются ОБА исхода после снятия ОБОИХ оснований.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ИЗМЕНИЛОСЬ ПРОТИВ ПРЕЖНЕЙ РЕДАКЦИИ
//
// Прежняя поднимала внешний движок отношений, писала в него кортежи руками и
// спрашивала его же. Движка нет, а вывод остался: его делает форма
// (`repo/kaname/pg/relverdict`) в той же базе, где лежит выдача. Спрашивается
// дверь решения (`internal/authzcascade`) — ровно то значение, которое получают
// собственные стражи iam в боевой посадке.

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

// ownerFixture кладёт аккаунт и ровно те два основания, которые материализует
// создание аккаунта: собственническое и прямой глагол чтения на себе.
func ownerFixture(t *testing.T, ctx context.Context, pool *pgxpool.Pool, acc, owner, accName string) {
	t.Helper()
	// ОДНОЙ транзакцией: ключ владельца отложен до КОММИТА
	// (`accounts_owner_fk … DEFERRABLE INITIALLY DEFERRED`), поэтому посев по
	// одному оператору в автокоммите отвергается на первом же.
	tx, err := pool.Begin(ctx)
	require.NoError(t, err, "транзакция посева")
	defer func() { _ = tx.Rollback(ctx) }()
	run := func(sql string, args ...any) {
		t.Helper()
		_, err := tx.Exec(ctx, sql, args...)
		require.NoErrorf(t, err, "посев (%s)", sql)
	}
	// Имя аккаунта — ОТДЕЛЬНЫМ параметром, а не идентификатором: схема требует
	// единственной форме имени дерева (`accounts_name_check`), и подчёркивание, законное
	// в идентификаторе, в имени отвергается.
	run(`INSERT INTO kaname.accounts (id, name, owner_user_id) VALUES ($1, $2, $3)
	     ON CONFLICT DO NOTHING`, acc, accName, owner)
	run(`INSERT INTO kaname.users (id, external_id, email, account_id)
	     VALUES ($1, $1, $1 || '@kacho.local', $2) ON CONFLICT DO NOTHING`, owner, acc)
	run(`INSERT INTO kaname.relation_fact (object_type, object_id, relation, subject)
	     VALUES ('account', $1, 'owner', 'user:' || $2),
	            ('account', $1, 'v_get', 'user:' || $2)`, acc, owner)
	require.NoError(t, tx.Commit(ctx), "коммит посева: форма читает СВОЕЙ транзакцией и "+
		"незакоммиченного не увидит — проба зеленела бы на пустоте")
}

func TestAccountDelete_RevokingOwnershipRemovesDerivedAdmin_OnTheForm(t *testing.T) {
	door, pool := formDoor(t)
	ctx := context.Background()

	const (
		acc   = "acc_own_revoke"
		owner = "usr_own_revoke"
		subj  = "user:" + owner
	)
	ownerFixture(t, ctx, pool, acc, owner, "own-revoke-account")
	obj := "account:" + acc

	// До снятия: право администратора ВЫВЕДЕНО из владения, прямого кортежа
	// `admin` не лежит вовсе. Положительный контроль несущий — без него отрицание
	// ниже зеленело бы и на форме, которая не отвечает «да» никогда.
	admin, err := door.Check(ctx, subj, "admin", obj)
	require.NoError(t, err)
	require.True(t, admin,
		"владелец не выводит право администратора: строка лежит под именем `owner`, "+
			"вопрос задан про `admin` — форма, ищущая имя буквально, отказывает держателю законного права")
	get, err := door.Check(ctx, subj, "v_get", obj)
	require.NoError(t, err)
	require.True(t, get, "владелец не держит материализованный `v_get` на своём аккаунте")

	// Снятие ровно того набора, который снимает удаление аккаунта.
	_, err = pool.Exec(ctx,
		`DELETE FROM kaname.relation_fact
		  WHERE object_type = 'account' AND object_id = $1 AND subject = $2`, acc, subj)
	require.NoError(t, err)

	admin, err = door.Check(ctx, subj, "admin", obj)
	require.NoError(t, err)
	require.False(t, admin,
		"после снятия оснований бывший владелец ПО-ПРЕЖНЕМУ выводит право администратора — "+
			"стоящее право на объект, которого больше нет")
	get, err = door.Check(ctx, subj, "v_get", obj)
	require.NoError(t, err)
	require.False(t, get, "после снятия оснований бывший владелец продолжает читать аккаунт")
}
