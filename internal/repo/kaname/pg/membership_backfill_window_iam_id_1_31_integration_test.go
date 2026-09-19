// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// membership_backfill_window_iam_id_1_31_integration_test.go — ДОБОР B2 к
// красной полосе сценария IAM-ID-1-31 (приёмка IAM-ID-1, S3.1).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРИВЯЗКА — К СУЩЕСТВУ, А НЕ К ОТПЕЧАТКУ
//
// СУЩЕСТВО: объект гейта — членство, адресуемое СОБСТВЕННЫМ неизменяемым id
// (`iam_membership:<mbr-…>`); шаг CONTRACT (переезд гейта на этот объект) не
// вправе опередить шаг MIGRATE (материализацию кортежей области по ВСЕМ
// существующим членствам).
//
// Отпечаток родительской приёмки ДВИЖЕТСЯ (круг ревью не закрыт):
// c5937b4e → 24b4bf85 → следующий; ПОДЛЕЖИТ ПЕРЕПИНУ здесь после закрытия круга.
// Обесцененный f4ffbd08 якорем намеренно НЕ называется (`change-graph.md §2`).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ — ПОРЯДОК И ПОЛНОТА БЭКФИЛЛА (expand→migrate→contract)
//
// Смена `object_type` записей каталога с `iam_user` на `iam_membership` — шаг
// CONTRACT: он меняет ОБЪЕКТ, про который спрашивает гейт. Он не вправе вступить
// в силу, пока реконсайлер не материализовал кортежи области для ВСЕХ
// существующих членств (MIGRATE). Иначе в окне переключения `v_get`/`v_list` по
// членству, чья область ещё не материализована, дают fail-closed — и админу
// СВОЕГО аккаунта отказывают в чтении личности.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ЭТО УСИЛЕНИЕ, А НЕ ОСЛАБЛЕНИЕ
//
// Прежняя редакция РЕКОНСТРУИРОВАЛА ключ конкатенацией `<account>:<user>` и
// спрашивала про ОДНУ строку. Два порока сразу:
//
//   - ключ воспроизводил логику продукта, и кортежа под ним не было бы НИКОГДА —
//     красный приходил от самой конкатенации, а не от отсутствия предмета;
//   - «полнота» утверждалась по ОДНОЙ строке, то есть полнотой не была: бэкфилл,
//     материализующий первое встреченное членство и бросающий остальные, прошёл
//     бы такую пробу зелёным.
//
// Теперь ключ ЧИТАЕТСЯ из посеянной строки, а полнота утверждается ПЕРЕПИСЬЮ по
// ВСЕМ строкам членства: непокрытых обязан быть ноль при непустой популяции.
// Покрытие считается не «есть хоть какой-то кортеж», а «достижимо ВЫДАЧЕЙ
// ВЛАДЕЛЬЦА СВОЕГО аккаунта» — иначе кортеж чужой выдачи зачёлся бы за покрытие.
//
// ─────────────────────────────────────────────────────────────────────────────
// ДВЕ СТОРОНЫ, ОДИН ИЗМЕНЁННЫЙ ФАКТ (исполнён ли проход бэкфилла)
//
//   - ОКНО ДО МАТЕРИАЛИЗАЦИИ — fail-closed, НЕ открытый доступ: пока проход не
//     прошёл, админ своего аккаунта членство НЕ достаёт. Это положительный
//     контроль БЕЗОПАСНОСТИ окна; он и делает полноту ниже осмысленной парой —
//     иначе «достаёт после прохода» зеленело бы на реализации, открывающей
//     доступ всегда.
//   - ПОЛНОТА ПОСЛЕ ПРОХОДА: каждое существующее членство материализовано.
//
// Один изменённый факт между сторонами — исполнён ли проход: та же популяция,
// те же выдачи.
//
// TEST-ONLY (ban #13): прод-код не тронут.
// Прогон: `go test ./internal/repo/kaname/pg/ -run MembershipBackfillWindow_IAMID131`
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

// membershipCoverageCensus — перепись покрытия членств кортежами области.
//
// Считает ДВЕ величины, а не одну: сколько строк членства всего и сколько из них
// НЕ достижимы выдачей владельца СВОЕГО аккаунта. «Ноль непокрытых» обязано быть
// отличимо от «ноль прочитанных» (`testing.md §«Гейт на класс»` п. 3), поэтому
// популяция возвращается вместе с находками.
func membershipCoverageCensus(t *testing.T, ctx context.Context, pool *pgxpool.Pool) (total, uncovered int) {
	t.Helper()
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.memberships`).Scan(&total))
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*) FROM kaname.memberships m
		 WHERE NOT EXISTS (
		   SELECT 1
		     FROM kaname.access_binding_emitted_tuples e
		     JOIN kaname.access_bindings b ON b.id = e.binding_id
		    WHERE e.object = 'iam_membership:' || m.id
		      AND b.resource_type = 'account'
		      AND b.resource_id = m.account_id)`).Scan(&uncovered))
	return total, uncovered
}

// TestMembershipBackfillWindow_IAMID131_FailClosedThenComplete — ДОБОР B2.
// Окно бэкфилла закрыто; полнота бэкфилла — переписью по всем членствам.
func TestMembershipBackfillWindow_IAMID131_FailClosedThenComplete(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	// ── фикстура: СУЩЕСТВУЮЩЕЕ членство, предшествующее переключению каталога ──
	ownerA := mustSeedUser(t, ctx, pool, "b2-own-a")
	accA := seedAccount(t, ctx, repo, "acc-b2-a", ownerA)
	p := domain.UserID(seedNativeUser(t, ctx, pool, accA.ID, "b2p"))
	seedMembership(t, ctx, pool, p, accA.ID, "ACTIVE") // идемпотентно поверх зеркала S1

	// Второе членство в ЧУЖОМ аккаунте: популяция переписи обязана быть шире
	// одной строки, иначе «полнота» неотличима от «эта одна строка покрыта».
	ownerC := mustSeedUser(t, ctx, pool, "b2-own-c")
	accC := seedAccount(t, ctx, repo, "acc-b2-c", ownerC)
	seedMembership(t, ctx, pool, p, accC.ID, "ACTIVE")

	// ── КЛЮЧ ЧИТАЕТСЯ ИЗ СТРОКИ, А НЕ СОБИРАЕТСЯ ПРОБОЙ ───────────────────────
	requireMembershipIDIsFormBound(t, ctx, pool)
	mbrA := membershipObjectID(t, ctx, pool, p, accA.ID)
	objA := "iam_membership:" + mbrA
	ownerUser := "user:" + string(ownerA)

	require.NoError(t, seed.BackfillOwnerBindings(ctx, pool))
	ownerBIDA := ownerBindingFor(t, ctx, pool, accA.ID)

	// ── предпосылка переписи: популяция НЕПУСТА ───────────────────────────────
	totalBefore, uncoveredBefore := membershipCoverageCensus(t, ctx, pool)
	require.Positivef(t, totalBefore,
		"популяция членств пуста — утверждение о полноте было бы истинно тривиально, "+
			"а проба отчиталась бы зелёным, не спросив ничего")

	// ── ОКНО ДО МАТЕРИАЛИЗАЦИИ: fail-closed, не открытый доступ ────────────────
	// Владельческая привязка заведена, но её кортежи ещё НЕ материализованы.
	require.Falsef(t,
		bindingReachesObject(t, ctx, pool, ownerBIDA, ownerUser, objA),
		"окно бэкфилла IAM-ID-1-31 (B2): ДО прохода доступ обязан быть fail-closed, а не открытый — "+
			"неготовое членство %s недостижимо. Открытый доступ в окне означал бы утечку до бэкфилла.", objA)
	require.Equalf(t, totalBefore, uncoveredBefore,
		"окно бэкфилла: ДО прохода непокрытыми обязаны быть ВСЕ %d членств — покрытыми оказались %d. "+
			"Иначе «полнота после прохода» ниже зеленела бы на том, что было материализовано ДО него, "+
			"и один изменённый факт между сторонами (исполнен ли проход) перестал бы быть единственным",
		totalBefore, totalBefore-uncoveredBefore)

	// ── контроль машинности: реальный проход бэкфилла исполняется ─────────────
	// Порядок несущий (`change-graph.md §5`): сначала фикстура и машинность,
	// затем проба предмета.
	runner, _ := newBackfill(pool)
	res, err := runner.RunOnce(ctx)
	require.NoError(t, err)
	require.True(t, res.Executed, "единственный RunOnce обязан исполнить проход бэкфилла")
	require.True(t,
		ledgerHasTuple(t, ctx, pool, ownerBIDA, ownerUser, "admin", "account:"+string(accA.ID)),
		"машинность: проход бэкфилла исполнился и материализует владельческий scope-self на `account:<A>`. "+
			"Без этого контроля красный ниже читался бы как «не выполнилось», а не как отсутствие предмета")

	// ── ПОЛНОТА ПОСЛЕ ПРОХОДА — ПЕРЕПИСЬЮ ПО ВСЕМ ЧЛЕНСТВАМ ───────────────────
	totalAfter, uncoveredAfter := membershipCoverageCensus(t, ctx, pool)
	assert.Zerof(t, uncoveredAfter,
		"IAM-ID-1-31 (B2) — ПОРЯДОК/ПОЛНОТА БЭКФИЛЛА. После прохода непокрытых членств обязано быть НОЛЬ, "+
			"а их %d из %d: у этих строк нет кортежа области, достижимого выдачей владельца СВОЕГО аккаунта. "+
			"Переключение `object_type` каталога (CONTRACT) в таком состоянии давало бы `v_get`/`v_list` по "+
			"неготовому членству fail-closed — то есть отказ админу СВОЕГО аккаунта. Членство обязано быть "+
			"материализовано (MIGRATE) ДО того, как гейт на него обопрётся (CONTRACT).",
		uncoveredAfter, totalAfter)
	assert.Truef(t,
		bindingReachesObject(t, ctx, pool, ownerBIDA, ownerUser, objA),
		"IAM-ID-1-31 (B2) — БЛИЗНЕЦ ПОЛНОТЫ на ИМЕНОВАННОЙ строке. Админ СВОЕГО аккаунта A обязан достать "+
			"личность через членство %s, прочитанное из посеянной строки. Перепись выше считает популяцию, "+
			"этот близнец называет КООРДИНАТУ — вместе они отличают «покрыто всё» от «покрыто что-то».", objA)

	t.Logf("перепись: членств всего %d · до прохода непокрытых %d (окно fail-closed) · "+
		"после прохода непокрытых %d · ключ ПРОЧИТАН из строки (%s) · "+
		"бэкфилл исполнился и материализует scope-self на account:<A>",
		totalAfter, uncoveredBefore, uncoveredAfter, mbrA)
}
