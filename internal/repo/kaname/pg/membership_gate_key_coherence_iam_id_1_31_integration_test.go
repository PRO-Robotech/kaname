// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// membership_gate_key_coherence_iam_id_1_31_integration_test.go — ДОБОР B1 к
// красной полосе сценария IAM-ID-1-31 (приёмка IAM-ID-1, S3.1, отпечаток
// f4ffbd08d7079a39f631ac63f9f25bd2e2af21dadf7d2d8b5d3a4bdbe9828070, круг 18).
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ЗДЕСЬ УТВЕРЖДАЕТСЯ — ИСХОД РЕАЛЬНОГО ДОСТУПА, А НЕ ФОРМА КАТАЛОГА/МОДЕЛИ
//
// Структурная полоса (`gate_object_and_self_read_coverage…`, `neighbour…`) читает
// каталог и компилирует модель прав. Она НЕ исполняет реального `Check` на
// РЕАЛЬНО МАТЕРИАЛИЗОВАННОМ объекте членства — поэтому расхождение ключа
// authz-объекта (край собрал `<аккаунт>:<user>`, а реконсайлер материализовал
// что-то другое — либо наоборот) проходит структурные пробы и в рантайме даёт
// fail-closed: админу СВОЕГО аккаунта тоже отказ. Это класс
// `security-hardening §«Разрыв, невидимый ни с одной стороны по отдельности»`
// (class-exposure kaname#292, пункт B1 «Чего измерить нельзя»).
//
// Держатель этого класса — только проба СКВОЗЬ материализацию: реальный `Check`
// (материализованный кортеж области в журнале прямого факта) на объекте, ключ
// которого собран ТОЧНО так, как его собирает край.
//
// ─────────────────────────────────────────────────────────────────────────────
// КЛЮЧ authz-ОБЪЕКТА — КОМПОЗИТ (решение диспетчера, действует для всех проб)
//
// Ключ authz-объекта членства — композит `iam_membership:<account>:<user>`: край
// собирает его из аккаунта (проверенного контекста вызывающего) и `user`;
// реконсайлер ОБЯЗАН материализовать кортежи области ТЕМ ЖЕ композитом. Нового
// кросс-сервисного резолва и ребра нет. Кодирование делимитер-безопасное —
// идентификаторы непрозрачны и `:` не несут.
//
// ЭТА ПРОБА ИСТОЧНИК-НЕЗАВИСИМА. Она НЕ утверждает, ОТКУДА край берёт строку
// аккаунта (сессия / скоуп запроса — решается владельцем): композит-ключ здесь
// формируется из ПОСЕЯННЫХ аккаунта и личности, а не из какого-либо канала края.
// Предмет пробы — kaname-сторона: материализует ли реконсайлер область по
// членству тем же композит-ключом, и изолирован ли соседний аккаунт.
//
// ─────────────────────────────────────────────────────────────────────────────
// ДВЕ СТОРОНЫ (§gate-authoring «отрицание только в паре с положительным»)
//
//   - ПОЛОЖИТЕЛЬНЫЙ БЛИЗНЕЦ (RED сегодня): админ СВОЕГО аккаунта A обязан достать
//     личность через композит-членство `iam_membership:<A>:<p>` — реконсайлер
//     обязан материализовать по нему кортеж области. Сегодня НЕ материализует
//     (тип `iam_membership` не заведён, области по членству нет) → админу своего
//     аккаунта fail-closed отказ. Это честный красный: предмета (материализации
//     композит-членства) НЕТ.
//   - ОТРИЦАНИЕ (изоляция, зелёное сегодня и после фикса): админ СОСЕДНЕГО
//     аккаунта B НЕ вправе достать `iam_membership:<A>:<p>` — этот объект
//     принадлежит аккаунту A. Один изменённый факт против близнеца: ТОТ ЖЕ объект
//     `iam_membership:<A>:<p>`, отличается лишь аккаунт админа (A против B).
//
// Без положительного близнеца отрицание вакуумно: «до объекта не достаёт никто»
// сегодня истинно тривиально (ничего не материализовано). Красный близнеца и
// делает пару различающей.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ КРАСНЫЙ ЧЕСТЕН, А НЕ «НЕ ВЫПОЛНИЛОСЬ»
//
// Порядок несущий (`change-graph.md §5`): СНАЧАЛА вся проверка фикстуры (аккаунты
// и владельцы посеяны, членств ровно два, владельческие привязки материализованы,
// и — контроль машинности — реконсайлер+журнал реально достают личность на
// `iam_user`), и лишь ПОТОМ проба возможности (близнец достаёт композит-членство).
// Реконсайлер и журнал исполняются без ошибки; красный приходит от отсутствия
// материализации композит-членства, а не от сорванной фикстуры.
//
// TEST-ONLY (ban #13): прод-код не тронут.
// Прогон: `go test ./internal/repo/kaname/pg/ -run MembershipGate_IAMID131`
// (testcontainers + Docker). Пропускается под -short.

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// membershipCompositeKey — композит-ключ authz-объекта членства, решённый
// диспетчером: `<account>:<user>`. Строится из аккаунта членства и личности
// (источник-независимо от канала края). Делимитер-безопасен: id непрозрачны.
func membershipCompositeKey(accID domain.AccountID, userID domain.UserID) string {
	return string(accID) + ":" + string(userID)
}

// bindingReachesObject — реальный `Check` СКВОЗЬ материализацию: достаёт ли
// субъект `fgaUser` объект `object` через выдачу `bID` — есть ли в журнале
// прямого факта ХОТЯ БЫ ОДИН материализованный кортеж (любого отношения) этой
// выдачи на этот объект. Относение-агностичен намеренно: «достаёт личность» —
// это факт достижимости, а не конкретный ярус; ярус несуществующего сегодня типа
// `iam_membership` выписывать наперёд нельзя.
func bindingReachesObject(t *testing.T, ctx context.Context, pool *pgxpool.Pool, bID domain.AccessBindingID, fgaUser, object string) bool {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.access_binding_emitted_tuples
		  WHERE binding_id = $1 AND fga_user = $2 AND object = $3`,
		string(bID), fgaUser, object).Scan(&n))
	return n > 0
}

// TestMembershipGate_IAMID131_OwnAccountReaches_NeighbourIsolated — ДОБОР B1,
// ЧЕСТНЫЙ КРАСНЫЙ. Реальный `Check` на композит-членстве.
func TestMembershipGate_IAMID131_OwnAccountReaches_NeighbourIsolated(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)
	rec, _ := newReconciler(pool)

	// ── фикстура: человек-личность в ДВУХ аккаунтах A и B ─────────────────────
	ownerA := mustSeedUser(t, ctx, pool, "b1-own-a")
	ownerB := mustSeedUser(t, ctx, pool, "b1-own-b")
	accA := seedAccount(t, ctx, repo, "acc-b1-a", ownerA)
	accB := seedAccount(t, ctx, repo, "acc-b1-b", ownerB)

	p := domain.UserID(seedNativeUser(t, ctx, pool, accA.ID, "b1p"))
	// Членства заводятся явно и идемпотентно (ON CONFLICT DO UPDATE): зеркало S1
	// могло уже завести членство в колонке-аккаунте A, второе членство в B кладём
	// сами — расхождение, ради которого сценарий и написан.
	seedMembership(t, ctx, pool, p, accA.ID, "ACTIVE")
	seedMembership(t, ctx, pool, p, accB.ID, "ACTIVE")

	var nmem int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.memberships WHERE user_id = $1`, string(p)).Scan(&nmem))
	require.Equal(t, 2, nmem,
		"предпосылка сценария: у личности ровно два членства (A и B) — иначе изоляция соседа беспредметна")

	require.NoError(t, seed.BackfillOwnerBindings(ctx, pool))
	ownerBIDA := ownerBindingFor(t, ctx, pool, accA.ID)
	ownerBIDB := ownerBindingFor(t, ctx, pool, accB.ID)

	// ── контроль машинности: реконсайлер+журнал реально достают личность ──────
	// Без этого красный ниже был бы неотличим от «не выполнилось». Реконсайлим
	// `iam.user` (тип, материализуемый уже сегодня) и убеждаемся, что владелец
	// аккаунта A достаёт личность на объекте `iam_user:<p>`.
	require.NoError(t, rec.ReconcileObject(ctx, "iam.user", string(p)))
	require.True(t,
		bindingReachesObject(t, ctx, pool, ownerBIDA, "user:"+string(ownerA), "iam_user:"+string(p)),
		"машинность: реконсайлер и журнал прямого факта работают — админ аккаунта A достаёт личность "+
			"на `iam_user:<p>`. Без этого контроля красный ниже читался бы как «не выполнилось», а не как "+
			"отсутствие предмета")

	// ── драйв предмета: материализация области по членству ────────────────────
	// Владельческие привязки покрывают КОНТЕНТ своих аккаунтов (`*.*`); после
	// фикса реконсайлер обязан материализовать по ним и объекты членства.
	require.NoError(t, rec.ReconcileBinding(ctx, ownerBIDA))
	require.NoError(t, rec.ReconcileBinding(ctx, ownerBIDB))
	// Пообъектный путь — тот самый ключ, что собирает край для контекста A.
	// Источник-независимо: ключ формируется из посеянных аккаунта A и личности p,
	// а не из какого-либо канала края. На неизвестном сегодня типе `iam.membership`
	// это безошибочный no-op (GetIAMDirectObject → spec не найден → {}, false, nil).
	compositeA := membershipCompositeKey(accA.ID, p)
	objA := "iam_membership:" + compositeA
	require.NoError(t, rec.ReconcileObject(ctx, "iam.membership", compositeA))

	// ── ОТРИЦАНИЕ (изоляция): админ соседнего аккаунта B НЕ достаёт объект A ────
	assert.False(t,
		bindingReachesObject(t, ctx, pool, ownerBIDB, "user:"+string(ownerB), objA),
		"изоляция IAM-ID-1-31: админ СОСЕДНЕГО аккаунта B не вправе достать личность в контексте A — "+
			"объект %s принадлежит аккаунту A (композит-членство несёт РОВНО ОДИН аккаунт-предок). "+
			"Один изменённый факт против положительного близнеца: тот же объект, другой аккаунт админа.", objA)

	// ── ПОЛОЖИТЕЛЬНЫЙ БЛИЗНЕЦ (честный красный сегодня): админ своего A достаёт ─
	assert.True(t,
		bindingReachesObject(t, ctx, pool, ownerBIDA, "user:"+string(ownerA), objA),
		"IAM-ID-1-31 (B1) — КОГЕРЕНТНОСТЬ КЛЮЧА КРАЙ↔РЕКОНСАЙЛЕР. Админ СВОЕГО аккаунта A обязан достать "+
			"личность через композит-членство %s: реконсайлер обязан материализовать кортеж области ТЕМ ЖЕ "+
			"композит-ключом <аккаунт>:<user>, который собирает край. Сегодня реконсайлер композит-членство "+
			"НЕ материализует (тип `iam_membership` не заведён, области по членству нет) → в рантайме "+
			"край соберёт объект, под которым кортежа нет, и админу СВОЕГО аккаунта прилетит fail-closed "+
			"отказ. Разрыв невидим с каждой стороны по отдельности (структурная полоса его не ловит), "+
			"поэтому держатель — этот реальный Check на материализованном объекте.", objA)

	t.Logf("перепись: членств у личности %d · объект близнеца %s · "+
		"машинность (админ A достаёт iam_user:<p>) подтверждена · "+
		"изоляция соседа B и достижимость своего A проверены на журнале прямого факта",
		nmem, objA)
}
