// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// access_binding_fga_outbox_integration_test.go — интеграционные пробы контракта
// записи fga_outbox в транзакции писателя access_bindings.
//
// Покрывает атомарную запись и откат:
//
// - CREATE-EMIT: AccessBindingsW().Insert + EmitRelationWrite + Commit
// оставляет N строк выдачи в kaname.fga_outbox (event_type=fga.tuple.write).
// - DELETE-EMIT: AccessBindingsW().Delete + EmitRelationDelete + Commit
// оставляет N строк отзыва в kaname.fga_outbox (event_type=fga.tuple.delete).
// - ROLLBACK: откат транзакции писателя удаляет И строку выдачи,
// И строки fga_outbox (запрет #10).

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/PRO-Robotech/corelib/ids"

	"github.com/PRO-Robotech/kaname/internal/domain"
	repoab "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/bindingset"
)

func TestAB_FGAOutboxTx_FGAOutbox_CreateEmitsWriteRows(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "w15cr")
	acc := seedAccount(t, ctx, repo, "acc-w15-create", uid)

	binding := domain.AccessBinding{
		ID:           domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding)),
		SubjectType:  domain.SubjectTypeUser,
		SubjectID:    domain.SubjectID(uid),
		RoleID:       domain.SystemViewerRoleID,
		ResourceType: "account",
		ResourceID:   string(acc.ID),
	}
	tuples := []repoab.RelationTuple{
		{User: "user:" + string(uid), Relation: "viewer", Object: "account:" + string(acc.ID)},
	}

	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	_, err = bindingset.Insert(ctx, w.AccessBindingsW(), binding)
	require.NoError(t, err)
	require.NoError(t, w.AccessBindingsW().EmitRelationWrite(ctx, tuples))
	require.NoError(t, w.Commit(ctx))

	// Проверяем наличие строки fga_outbox.
	var et string
	var payloadRaw string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT event_type, payload::text
		 FROM kaname.fga_outbox
		 ORDER BY id DESC LIMIT 1`).Scan(&et, &payloadRaw))
	require.Equal(t, "fga.tuple.write", et)
	var payload map[string]string
	require.NoError(t, json.Unmarshal([]byte(payloadRaw), &payload))
	require.Equal(t, "user:"+string(uid), payload["user"])
	require.Equal(t, "viewer", payload["relation"])
	require.Equal(t, "account:"+string(acc.ID), payload["object"])
}

func TestAB_FGAOutboxTx_FGAOutbox_DeleteEmitsDeleteRows(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "w15dl")
	acc := seedAccount(t, ctx, repo, "acc-w15-delete", uid)
	binding := insertAB(t, ctx, repo, domain.AccessBinding{
		SubjectType:  domain.SubjectTypeUser,
		SubjectID:    domain.SubjectID(uid),
		RoleID:       domain.SystemViewerRoleID,
		ResourceType: "account",
		ResourceID:   string(acc.ID),
	})

	tuples := []repoab.RelationTuple{
		{User: "user:" + string(uid), Relation: "viewer", Object: "account:" + string(acc.ID)},
	}

	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	require.NoError(t, w.AccessBindingsW().Delete(ctx, binding.ID))
	require.NoError(t, w.AccessBindingsW().EmitRelationDelete(ctx, tuples))
	require.NoError(t, w.Commit(ctx))

	var et string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT event_type FROM kaname.fga_outbox WHERE event_type = $1 LIMIT 1`,
		"fga.tuple.delete").Scan(&et))
	require.Equal(t, "fga.tuple.delete", et)
}

// TestAB_FGAOutboxTx_FGAOutbox_RollbackDiscardsBothRowAndEmit проверяет запрет #10:
// откат транзакции писателя ДОЛЖЕН удалять и записанную строку fga_outbox.
// Подтверждает атомарность записи в транзакции (обработчик не видит осиротевших строк).
func TestAB_FGAOutboxTx_FGAOutbox_RollbackDiscardsBothRowAndEmit(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "w15rb")
	acc := seedAccount(t, ctx, repo, "acc-w15-rollback-test", uid)

	candidateID := domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding))
	binding := domain.AccessBinding{
		ID:           candidateID,
		SubjectType:  domain.SubjectTypeUser,
		SubjectID:    domain.SubjectID(uid),
		RoleID:       domain.SystemViewerRoleID,
		ResourceType: "account",
		ResourceID:   string(acc.ID),
	}
	tuples := []repoab.RelationTuple{
		{User: "user:" + string(uid), Relation: "viewer", Object: "account:" + string(acc.ID)},
	}

	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	_, err = bindingset.Insert(ctx, w.AccessBindingsW(), binding)
	require.NoError(t, err)
	require.NoError(t, w.AccessBindingsW().EmitRelationWrite(ctx, tuples))
	require.NoError(t, w.Rollback(ctx)) // явный откат

	// Ни строка выдачи, ни строка fga_outbox не должны быть видимы.
	var bindingCount int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.access_bindings WHERE id = $1`,
		string(candidateID)).Scan(&bindingCount))
	require.Equal(t, 0, bindingCount, "binding row must be rolled back")

	var fgaCount int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.fga_outbox
		 WHERE payload->>'user' = $1 AND payload->>'object' = $2`,
		"user:"+string(uid), "account:"+string(acc.ID)).Scan(&fgaCount))
	require.Equal(t, 0, fgaCount, "fga_outbox row must be rolled back atomically with binding row")
}

// TestAB_FGAOutboxTx_FGAOutbox_EmitWriteTx_EmptyTuplesNoop подтверждает, что 0 кортежей
// безопасно оставляет состояние прежним (допустимость пустой отправки решает вызывающий).
func TestAB_FGAOutboxTx_FGAOutbox_EmitWriteTx_EmptyTuplesNoop(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	// Снимаем начальный размер outbox: миграции посева ставят кортежи отношений в очередь
	// (0009 fga_writer@iam_fgaproxy, 0010 — оператор system_viewer@cluster,
	// 0014 — читатель system_viewer@cluster). Проверяем, что пустая отправка добавила НОЛЬ строк
	// (по дельте, устойчивой к любому нынешнему и будущему посеву: статический фильтр «== 0»
	// незаметно ломался при каждом добавлении нового посева корня кластера).
	var before int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.fga_outbox`).Scan(&before))

	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	require.NoError(t, w.AccessBindingsW().EmitRelationWrite(ctx, nil))
	require.NoError(t, w.AccessBindingsW().EmitRelationDelete(ctx, []repoab.RelationTuple{}))
	require.NoError(t, w.Commit(ctx))

	var after int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.fga_outbox`).Scan(&after))
	require.Equal(t, before, after, "empty tuples → no emit, no new row")
}
