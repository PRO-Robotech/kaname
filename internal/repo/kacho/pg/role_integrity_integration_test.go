// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// role_integrity_integration_test.go — выборка неразрешённых сегментов против
// ЖИВОЙ базы.
//
// Приёмка `role-degradation-is-visible-in-get-and-list.md`, RED-шаг 3 (§9),
// сценарий IAM-RH-1-02. Проба домена утверждает ФУНКЦИЮ на чистых величинах;
// здесь утверждается другое — что состояние 513001 в ЭТОМ дереве ПРЕДСТАВИМО,
// то есть что вопрос к проекции задаётся той же формой имени, какой проекция
// заполнена. Первое второго не покрывает: разойдись словари — функция осталась
// бы верной, а ответ всегда «ничего не разрешено».

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/pgtest"
	// Закрытие С ПРЕДЕЛОМ, а не «когда-нибудь»: отложенное `pool.Close()` ждёт
	// возврата ВСЕХ соединений, а проба, упавшая внутри открытой транзакции, своё
	// не вернёт — её горутину завершает `FailNow`. Пакет тогда упирается в
	// `-timeout` и печатает FAIL, под которым нет вердикта НИ У ОДНОЙ пробы,
	// включая прошедшие: «не выполнилось» приезжает к читателю под видом красного.
	// Требование дерева, держится гейтом `TestPoolCloseInTestsIsBounded`.
	coredb "github.com/PRO-Robotech/kacho/pkg/db"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	kachopg "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg"
)

func TestRoleIntegrity_UnresolvedSegments_AgainstLiveProjection(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	// Закрытие С ПРЕДЕЛОМ, а не «когда-нибудь»: отложенное `pool.Close()` ждёт
	// возврата ВСЕХ соединений, а проба, упавшая внутри открытой транзакции, своё
	// не вернёт — её горутину завершает `FailNow`. Пакет тогда упирается в
	// `-timeout` и печатает FAIL, под которым нет вердикта НИ У ОДНОЙ пробы,
	// включая прошедшие: «не выполнилось» приезжает к читателю под видом красного.
	// Требование дерева, держится гейтом `TestPoolCloseInTestsIsBounded`.
	pgtest.ClosePoolAtEnd(t, pool)
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "rint")
	acc := seedAccount(t, ctx, repo, "acc-rint", uid)
	role := seedCustomRole(t, ctx, repo, acc.ID, "integrity_probe")

	// Строки проекции кладём НАПРЯМУЮ: предмет пробы — вопрос к ней, а не путь
	// её заполнения (у него свой писатель и свои пробы).
	_, err = pool.Exec(ctx, `
		INSERT INTO kacho_iam.role_verb (role_id, object_type, verb)
		VALUES ($1, 'vpc.network', 'get'), ($1, 'vpc.network', 'list')`, string(role.ID))
	require.NoError(t, err)

	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()

	seg := func(objectType, verb string) domain.RoleSegment {
		return domain.RoleSegment{RoleID: role.ID, ObjectType: objectType, Verb: verb}
	}

	t.Run("спроецированные сегменты неразрешёнными не считаются", func(t *testing.T) {
		got, gerr := rd.Roles().UnresolvedSegments(ctx, []domain.RoleSegment{
			seg("vpc.network", "get"), seg("vpc.network", "list"),
		})
		require.NoError(t, gerr)
		require.Empty(t, got[role.ID],
			"обе пары лежат в проекции — неразрешённых быть не может; "+
				"непустой ответ означает, что вопрос задан не той формой имени")
	})

	t.Run("форма 513001: объявлено, не спроецировано ни одного", func(t *testing.T) {
		got, gerr := rd.Roles().UnresolvedSegments(ctx, []domain.RoleSegment{
			seg("probe.thing", "get"), seg("probe.thing", "list"),
		})
		require.NoError(t, gerr)
		require.Len(t, got[role.ID], 2,
			"тип, которого проекция не знает, обязан дать неразрешённые сегменты")
		// СОСТАВ, а не только число: срез заведён ради того, чтобы состояние
		// правила знало, КАКОЙ сегмент потерян (#1962). Сверка по числу
		// зеленела бы на выборке, вернувшей два любых сегмента.
		require.ElementsMatch(t,
			[]domain.RoleSegment{seg("probe.thing", "get"), seg("probe.thing", "list")},
			got[role.ID],
			"срез обязан называть ИМЕННО те сегменты, которые не разрешились")
	})

	t.Run("часть спроецирована, часть нет", func(t *testing.T) {
		got, gerr := rd.Roles().UnresolvedSegments(ctx, []domain.RoleSegment{
			seg("vpc.network", "get"), seg("probe.thing", "get"),
		})
		require.NoError(t, gerr)
		require.Len(t, got[role.ID], 1)
		require.Equal(t, []domain.RoleSegment{seg("probe.thing", "get")}, got[role.ID],
			"неразрешённым обязан быть НЕ спроецированный, а не любой из двух")
	})

	t.Run("якорь удовлетворяется любой строкой своего типа", func(t *testing.T) {
		got, gerr := rd.Roles().UnresolvedSegments(ctx, []domain.RoleSegment{seg("vpc.network", "")})
		require.NoError(t, gerr)
		require.Empty(t, got[role.ID],
			"правило `verbs: [\"*\"]` даёт ОДИН сегмент, и он разрешается любой строкой типа")
	})

	t.Run("якорь на типе без единой строки неразрешён", func(t *testing.T) {
		got, gerr := rd.Roles().UnresolvedSegments(ctx, []domain.RoleSegment{seg("probe.thing", "")})
		require.NoError(t, gerr)
		require.Equal(t, []domain.RoleSegment{seg("probe.thing", "")}, got[role.ID],
			"якорь обязан вернуться ЯКОРЕМ — с пустым глаголом, а не с подставленным")
	})

	t.Run("пустой вход законен и вопроса не задаёт", func(t *testing.T) {
		got, gerr := rd.Roles().UnresolvedSegments(ctx, nil)
		require.NoError(t, gerr)
		require.Empty(t, got)
	})
}
