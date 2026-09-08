// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// module_relation_write_grant_integration_test.go — ПРАВО МОДУЛЯ ПИСАТЬ КОРТЕЖИ
// СПРАШИВАЕТСЯ НА КЛАСТЕРЕ, И ОТЗЫВ ЭТОГО ПРАВА ЗАКРЫВАЕТ ЗАПИСЬ.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ (#914, решение 1)
//
// Способность модуля писать кортежи держалась на служебном синглтоне — якоре,
// которого нет в иерархии `cluster → account → project`. У такого якоря нет ни
// яруса, ни владельца: выдачей это не выражается, перечисление выдач о нём
// молчит, и отзывать нечем. Решение записано в
// `services/iam/docs/engineering/architecture/grant-surface-boundaries.md`:
// словарь якорей НЕ растёт, а способность переезжает на КЛАСТЕРНОЕ отношение и
// выражается обычной системной выдачей.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ПРОБА СПРАШИВАЕТ ВЕРДИКТ, А НЕ СЧИТАЕТ СТРОКИ
//
// Строка в таблице — это то, что мы записали; вердикт — то, что получает
// вызывающий. Между ними лежит и модель (объявлено ли отношение на этом типе), и
// разворот членства (доходит ли выдача группе до её члена). Проба, считающая
// строки, зеленеет на выдаче, которой вердикт не находит, — то есть ровно на том
// состоянии, ради которого перенос и делается.
//
// Отрицательное плечо обязательно и берётся НЕ выдуманным: `kacho-api-gateway` —
// такая же модульная служебная учётка того же посева, которой это право
// НАМЕРЕННО не выдано. Законный близнец, а не «какой-нибудь чужой субъект».

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/pgtest"

	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
)

// relationWriteRelation — отношение, которым гейт записи кортежей задаёт свой
// вопрос. Имя берётся не из литерала пробы, а из прод-константы гейта: проба,
// пишущая имя сама, остаётся зелёной, когда гейт спрашивает другое.
const relationWriteRelation = authzguard.RelationWriteRelation

// modulesThatWriteRelations — модули, чей путь регистрации ресурса пишет кортежи
// через iam. Перечень короткий и закрытый, поэтому назван, а не выведен: он и
// есть предмет утверждения, а выведенный из той же таблицы, из которой читает
// проверяемое, он утверждал бы тождество.
var modulesThatWriteRelations = []string{"vpc", "compute", "nlb", "registry", "storage"}

// moduleWithoutRelationWrite — законный близнец: модульная учётка того же
// посева, которой право писать кортежи не выдано намеренно.
const moduleWithoutRelationWrite = "api-gateway"

func askRelationWrite(t *testing.T, ctx context.Context, asker *relverdict.Asker, svc string) bool {
	t.Helper()
	allowed, err := asker.Allowed(ctx,
		"service_account:"+authzguard.ServiceAccountIDForService(svc),
		"cluster", domain.ClusterSingletonID, relationWriteRelation, nil)
	require.NoError(t, err, "вопрос о праве писать кортежи обязан быть задаваем: %s", svc)
	return allowed
}

// TestIntegration_R914_RelationWriteIsAskedOnTheCluster — свежая платформа: право
// писать кортежи есть у каждого пишущего модуля и НЕТ у того, кому его не
// выдавали; якоря вне иерархии не осталось ни одного.
func TestIntegration_R914_RelationWriteIsAskedOnTheCluster(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	// Закрытие С ПРЕДЕЛОМ: закрытие пула ждёт возврата ВСЕХ соединений, а
	// проба, упавшая внутри открытой транзакции, своё уже не вернёт — отложенное
	// закрытие встанет ждать писателя, которого нет, и пакет упрётся в предел
	// прогона. Тогда «не выполнилось» приходит к читателю под видом красного, и
	// вердикта нет ни у одной пробы пакета.
	pgtest.ClosePoolAtEnd(t, pool)

	asker := relverdict.NewAsker(pool)

	for _, svc := range modulesThatWriteRelations {
		assert.Truef(t, askRelationWrite(t, ctx, asker, svc),
			"модуль %s пишет кортежи на пути регистрации ресурса — без этого права "+
				"владение, поставленное при создании, не пишется ни для одного арендатора", svc)
	}

	assert.False(t, askRelationWrite(t, ctx, asker, moduleWithoutRelationWrite),
		"отрицательное плечо: учётке, которой право не выдавали, вердикт обязан отказать — "+
			"иначе он отвечает «да» всем и гейтом не является")

	// Якорь вне иерархии обязан исчезнуть ЦЕЛИКОМ, а не получить дубль на
	// кластере: два действующих основания об одном предмете расходятся молча, и
	// отзыв кластерного оставил бы работающим прежнее.
	//
	// Отбор ПОЛОЖИТЕЛЬНЫЙ — по имени того самого якоря, а не «всё, кроме трёх
	// ярусов». Список-исключение стареет молча: он растёт от работы, к пробе
	// отношения не имеющей, и, исключив лишнее, даёт ноль, не посмотрев ни на
	// одну строку. Здесь спрашивается ровно тот якорь, с которого право уезжает.
	offHierarchyAnchors := []string{"iam_fgaproxy"}
	var offHierarchy int
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*) FROM kaname.relation_fact
		 WHERE object_type = ANY($1::text[])`, offHierarchyAnchors).Scan(&offHierarchy))
	assert.Zero(t, offHierarchy,
		"основание доступа на якоре вне иерархии %v: его не видно перечислением выдач и нечем отозвать",
		offHierarchyAnchors)
}

// TestIntegration_R914_RevokingTheClusterGrantClosesTheWrite — ИСХОД отзыва, а не
// факт эмиссии.
//
// Аддитивный путь зелен по всякому утверждению вида «вызвали / эмитировали» и
// неверен ровно в том, ради чего отзыв делается. Поэтому здесь спрашивается
// вердикт ДО и ПОСЛЕ, а рядом стоит положительный контроль: отзыв ОДНОЙ выдачи
// не трогает соседнее основание.
func TestIntegration_R914_RevokingTheClusterGrantClosesTheWrite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	// Закрытие С ПРЕДЕЛОМ: закрытие пула ждёт возврата ВСЕХ соединений, а
	// проба, упавшая внутри открытой транзакции, своё уже не вернёт — отложенное
	// закрытие встанет ждать писателя, которого нет, и пакет упрётся в предел
	// прогона. Тогда «не выполнилось» приходит к читателю под видом красного, и
	// вердикта нет ни у одной пробы пакета.
	pgtest.ClosePoolAtEnd(t, pool)

	asker := relverdict.NewAsker(pool)
	repo := kanamepg.New(pool, nil)

	require.True(t, askRelationWrite(t, ctx, asker, "vpc"),
		"предпосылка отзыва: до него право действует. Иначе «после отзыва отказ» истинно "+
			"тождественно и ничего не измеряет")

	var bindingID string
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT id FROM kaname.access_bindings
		 WHERE is_system AND granted_relation = $1 AND resource_type = 'cluster'
		   AND status = 'ACTIVE' AND revoked_at IS NULL`, relationWriteRelation).Scan(&bindingID),
		"право обязано быть ВЫДАЧЕЙ: отзывать нечего, пока его нет на поверхности выдач")
	id := domain.AccessBindingID(bindingID)

	// Реестр выданного — то, что отзыв повторяет. Пустой реестр означал бы
	// отзыв, который не отзывает: строка выдачи исчезла, доступ остался.
	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	stored, err := rd.AccessBindings().SelectEmittedTuples(ctx, id)
	_ = rd.Rollback(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, stored, "реестр выданного пуст — отзыву нечего снимать")

	// Штатный отзыв: снять защиту, снять выдачу, снять факт — тремя вызовами,
	// которыми это делает путь отзыва в use-case.
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	_, err = w.AccessBindingsW().SetDeletionProtection(ctx, id, false)
	if err != nil {
		_ = w.Rollback(ctx)
		require.NoError(t, err)
	}
	require.NoError(t, w.Commit(ctx))

	w, err = repo.Writer(ctx)
	require.NoError(t, err)
	failed := func(err error) bool {
		if err == nil {
			return false
		}
		_ = w.Rollback(ctx)
		assert.NoError(t, err)
		return true
	}
	if failed(w.AccessBindingsW().DeleteGuarded(ctx, id)) {
		t.FailNow()
	}
	if failed(w.AccessBindingsW().EmitRelationDelete(ctx, stored)) {
		t.FailNow()
	}
	if failed(w.Commit(ctx)) {
		t.FailNow()
	}

	assert.False(t, askRelationWrite(t, ctx, asker, "vpc"),
		"отзыв обязан ЗАКРЫВАТЬ запись кортежей: иначе выдача исчезла, а право осталось — "+
			"состояние, которого не видно ни на одной поверхности")

	// Положительный контроль. Без него «отказ после отзыва» неотличим от пробы,
	// которая сломала вердикт целиком.
	quotaReader, err := asker.Allowed(ctx,
		"service_account:"+authzguard.ServiceAccountIDForService("vpc"),
		"cluster", domain.ClusterSingletonID, "quota_reader", nil)
	require.NoError(t, err)
	assert.True(t, quotaReader,
		"положительный контроль: отзыв ОДНОЙ выдачи не трогает соседнее основание того же субъекта")
}
