// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// register_resource_applied_type_integration_test.go — РЕГИСТРАЦИЯ ОБЪЕКТА ТИПА,
// ЗАВЕДЁННОГО ПРИМЕНЕНИЕМ МАНИФЕСТА В РАБОТАЮЩЕМ ПРОЦЕССЕ (kacho#1990).
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО УТВЕРЖДАЕТСЯ — ИСХОД РЕГИСТРАЦИИ, А НЕ ФОРМА ПЕРЕВОДА
//
// Проба спрашивает наблюдаемое: прошла ли регистрация и появилась ли строка
// зеркала. Утверждать «перевод позвал такую-то функцию» значило бы закрепить
// СПОСОБ, а не свойство: следующая замена оболочки оставила бы пробу зелёной на
// сломанном исходе.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ЗДЕСЬ ДВА ПОЛОЖИТЕЛЬНЫХ КОНТРОЛЯ, А НЕ ОДИН
//
//	живой сосед       тип, который знает и сборка, и каталог, регистрируется и
//	                  ложится в зеркало точечным именем. Без него «строка не
//	                  появилась» было бы неотличимо от «путь регистрации не
//	                  работает вовсе»;
//	предпосылка       сборка заведённого типа НЕ знает. Впиши кто-нибудь его в
//	                  манифест дерева — и проба зеленела бы вхолостую, а отличить
//	                  это от исправного перевода было бы нечем.
//
// ─────────────────────────────────────────────────────────────────────────────
// ФИКСТУРА ЗАВОДИТСЯ ОПЕРАТОРОМ ВСТАВКИ, И ЭТО РЕШЕНИЕ
//
// Предмет пробы — РЕГИСТРАЦИЯ, а не применитель манифеста: его сквозной путь уже
// утверждают пробы каталога, и повторять их значило бы завести два места об
// одном предмете. Строки каталога здесь — УСЛОВИЕ сценария, поэтому кладутся
// прямо; отказ вставки называет себя условием, а не предметом.
package internal_iam_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/pgtest"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	internaliam "github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/api/internal_iam"
	"github.com/PRO-Robotech/kacho-iam/internal/authzmap"
	kachopg "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg"
	"github.com/PRO-Robotech/kacho-iam/internal/testsupport/iampgtest"
)

// Тип, заведённый ПРИМЕНЕНИЕМ: словарь сборки о нём не знает by construction —
// его нет ни в одном манифесте дерева.
const (
	appliedModule = "probemod"
	appliedRes    = "alpha"
	appliedDotted = appliedModule + "." + appliedRes
	appliedType   = "probemod_alpha"
)

// newRegisterUCApplied — тот же use-case, что собирает композиционный корень,
// над настоящим пулом. Собирается здесь своим вызовом, а не переиспользует
// хелпер соседнего файла: тому нужен только пул зеркала, а этой пробе — ещё и
// читатель каталога, и подмена одного хелпера двумя предметами сделала бы
// непонятным, что именно провязано.
func newRegisterUCApplied(t *testing.T) (*internaliam.RegisterResourceUseCase, *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, iampgtest.NewTestPostgres(t))
	require.NoError(t, err)
	// Закрытие С ПРЕДЕЛОМ: отложенное ждёт соединение, которое проба, упавшая
	// внутри открытой транзакции, не вернёт никогда, и уносит вердикт всего пакета.
	pgtest.ClosePoolAtEnd(t, pool)
	uc := internaliam.NewRegisterResourceUseCase(
		kachopg.NewFGAOutboxEmitter(),
		kachopg.NewResourceMirrorEmitter(),
		kachopg.NewPoolTxBeginner(pool),
		kachopg.NewCatalogTypeReader(),
	)
	return uc, pool
}

// seedAppliedType кладёт УСЛОВИЕ сценария: живую строку каталога, какую положил
// бы применитель манифеста в работающем процессе.
func seedAppliedType(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	_, err := pool.Exec(ctx,
		`INSERT INTO kacho_iam.catalog_module (module) VALUES ($1) ON CONFLICT DO NOTHING`,
		appliedModule)
	require.NoError(t, err, "условие сценария не создано: строка модуля")
	_, err = pool.Exec(ctx,
		`INSERT INTO kacho_iam.catalog_resource (module, resource, dotted, object_type)
		 VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING`,
		appliedModule, appliedRes, appliedDotted, appliedType)
	require.NoError(t, err, "условие сценария не создано: строка ресурса")
}

func mirrorRowCount(t *testing.T, ctx context.Context, pool *pgxpool.Pool, objType, objID string) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.resource_mirror WHERE object_type = $1 AND object_id = $2`,
		objType, objID).Scan(&n))
	return n
}

// TestRegisterResource_AppliedTypeReachesTheMirror — kacho#1990.
//
// Тип заведён применением; регистрация его объекта обязана пройти и положить
// строку зеркала под ТОЧЕЧНЫМ именем живой строки каталога.
func TestRegisterResource_AppliedTypeReachesTheMirror(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует Postgres")
	}
	ctx := context.Background()
	uc, pool := newRegisterUCApplied(t)

	// КОНТРОЛЬ ПРЕДПОСЫЛКИ. Знай словарь сборки этот тип — перевод сборкой дал бы
	// верный ответ по совпадению, и проба перестала бы что-либо утверждать.
	if dotted, known := authzmap.DottedType(appliedType); known {
		t.Fatalf("словарь сборки знает %q (→ %q): предпосылка отпала, проба стала бы вакуумной",
			appliedType, dotted)
	}

	// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ НА ЖИВОМ СОСЕДЕ. Без него «строки нет» неотличимо от
	// «путь регистрации не работает вовсе».
	const liveObj = "compute_instance:inst-live-1990"
	require.NoError(t, uc.Register(ctx, &iamv1.RegisterResourceRequest{
		SubjectId:       "project:prj-1990",
		Relation:        "parent",
		Object:          liveObj,
		ParentProjectId: "prj-1990",
	}), "живой сосед не зарегистрировался — путь регистрации сломан, о предмете пробы вердикта нет")
	require.Equal(t, 1, mirrorRowCount(t, ctx, pool, "compute.instance", "inst-live-1990"),
		"живой сосед не лёг в зеркало точечным именем")

	// ПРЕДМЕТ.
	seedAppliedType(t, ctx, pool)
	const appliedObj = appliedType + ":obj-1990"
	err := uc.Register(ctx, &iamv1.RegisterResourceRequest{
		SubjectId:       "project:prj-1990",
		Relation:        "parent",
		Object:          appliedObj,
		ParentProjectId: "prj-1990",
	})
	require.NoError(t, err,
		"регистрация объекта типа, заведённого ПРИМЕНЕНИЕМ, отвергнута: строки зеркала нет, "+
			"а без неё правило не отберёт объект ни при каком материализаторе (kacho#1990)")

	require.Equal(t, 1, mirrorRowCount(t, ctx, pool, appliedDotted, "obj-1990"),
		"строка зеркала не появилась под точечным именем живой строки каталога %q", appliedDotted)
	require.Equal(t, 0, mirrorRowCount(t, ctx, pool, appliedType, "obj-1990"),
		"строка зеркала легла под именем словаря МОДЕЛИ %q — колонка названа словарём каталога",
		appliedType)
}

// TestUnregisterResource_AppliedTypeLeavesNoMirrorRow — обратная сторона того же
// перевода, и она обязательна.
//
// Снятие, не нашедшее строку, оставляет ЗАПИСЬ О ЖИВОМ ОБЪЕКТЕ у платформы,
// которая объявила его снятым, — то есть право, которое не отзывается. Проба на
// одной регистрации это не поймала бы: там строка появляется, и «появилась»
// выглядит достаточным.
func TestUnregisterResource_AppliedTypeLeavesNoMirrorRow(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует Postgres")
	}
	ctx := context.Background()
	uc, pool := newRegisterUCApplied(t)
	seedAppliedType(t, ctx, pool)

	const objID = "obj-1990-teardown"
	req := &iamv1.RegisterResourceRequest{
		SubjectId:       "project:prj-1990",
		Relation:        "parent",
		Object:          appliedType + ":" + objID,
		ParentProjectId: "prj-1990",
	}
	require.NoError(t, uc.Register(ctx, req))
	require.Equal(t, 1, mirrorRowCount(t, ctx, pool, appliedDotted, objID),
		"условие сценария не создано: снимать нечего")

	require.NoError(t, uc.Unregister(ctx, &iamv1.UnregisterResourceRequest{
		SubjectId: req.SubjectId,
		Relation:  req.Relation,
		Object:    req.Object,
	}))
	require.Equal(t, 0, mirrorRowCount(t, ctx, pool, appliedDotted, objID),
		"снятие не убрало строку зеркала: объект, объявленный снятым, продолжает отбираться правилом")
}
