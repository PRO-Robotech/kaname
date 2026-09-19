// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// membership_backfill_window_iam_id_1_31_integration_test.go — ДОБОР B2 к
// красной полосе сценария IAM-ID-1-31 (приёмка IAM-ID-1, S3.1, отпечаток
// f4ffbd08d7079a39f631ac63f9f25bd2e2af21dadf7d2d8b5d3a4bdbe9828070, круг 18).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ — ПОРЯДОК И ПОЛНОТА БЭКФИЛЛА (expand→migrate→contract)
//
// Смена `object_type` записей каталога с `iam_user` на `iam_membership` — это
// шаг CONTRACT: он меняет ОБЪЕКТ, про который спрашивает гейт. Он не вправе
// вступить в силу, пока реконсайлер не материализовал кортежи области для ВСЕХ
// существующих членств (шаг MIGRATE). Иначе в окне переключения `v_get`/`v_list`
// по членству, чья область ещё не материализована, дают fail-closed — и админу
// СВОЕГО аккаунта отказывают в чтении личности. Класс
// `code-authoring §2.3` (свойство, включаемое через реконсайлер) +
// `verdict-and-landing §expand→migrate→contract` (class-exposure kaname#292, B2).
//
// ЭТА ПРОБА ИСТОЧНИК-НЕЗАВИСИМА (как и B1): композит-ключ формируется из
// посеянных аккаунта и личности, а не из канала края.
//
// ─────────────────────────────────────────────────────────────────────────────
// ДВЕ СТОРОНЫ, ОДИН ИЗМЕНЁННЫЙ ФАКТ (исполнён ли бэкфилл)
//
//   - ОКНО ДО МАТЕРИАЛИЗАЦИИ — fail-closed, НЕ открытый доступ (зелёное сегодня и
//     после фикса): пока бэкфилл не прошёл, админ своего аккаунта композит-членство
//     НЕ достаёт. Это положительный контроль БЕЗОПАСНОСТИ окна: неготовое членство
//     закрыто, а не открыто. Он и делает completeness ниже осмысленной парой —
//     иначе «достаёт после бэкфилла» зеленело бы на реализации, открывающей доступ
//     всегда.
//   - ПОЛНОТА ПОСЛЕ БЭКФИЛЛА (честный красный сегодня): после прохода бэкфилла
//     существующее членство материализовано → админ своего аккаунта достаёт
//     личность через `iam_membership:<A>:<p>`. Сегодня бэкфилл композит-членство
//     НЕ материализует → админу своего аккаунта отказ. Честный красный: предмета
//     (материализации области членства бэкфиллом) НЕТ.
//
// Один изменённый факт между сторонами — исполнён ли проход бэкфилла: тот же
// объект, тот же субъект.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ КРАСНЫЙ ЧЕСТЕН, А НЕ «НЕ ВЫПОЛНИЛОСЬ»
//
// Порядок (`change-graph.md §5`): фикстура (членство посеяно, владельческая
// привязка заведена, окно до бэкфилла закрыто), затем контроль машинности
// (реальный проход бэкфилла материализует владельческий scope-self на
// `account:<A>` — доказано соседней пробой P8_02), и лишь ПОТОМ проба полноты.
// Бэкфилл исполняется без ошибки; красный — от отсутствия материализации
// композит-членства, а не от сорванной фикстуры.
//
// TEST-ONLY (ban #13): прод-код не тронут.
// Прогон: `go test ./internal/repo/kaname/pg/ -run MembershipBackfillWindow_IAMID131`
// (testcontainers + Docker). Пропускается под -short.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// TestMembershipBackfillWindow_IAMID131_FailClosedThenComplete — ДОБОР B2,
// ЧЕСТНЫЙ КРАСНЫЙ. Окно бэкфилла закрыто; полнота бэкфилла — предмет отсутствует.
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

	var nmem int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.memberships WHERE user_id = $1 AND account_id = $2`,
		string(p), string(accA.ID)).Scan(&nmem))
	require.Equal(t, 1, nmem, "предпосылка: существующее членство (p, A) заведено до переключения каталога")

	require.NoError(t, seed.BackfillOwnerBindings(ctx, pool))
	ownerBIDA := ownerBindingFor(t, ctx, pool, accA.ID)

	compositeA := membershipCompositeKey(accA.ID, p)
	objA := "iam_membership:" + compositeA
	ownerUser := "user:" + string(ownerA)

	// ── ОКНО ДО МАТЕРИАЛИЗАЦИИ: fail-closed, не открытый доступ ────────────────
	// Владельческая привязка заведена, но её кортежи ещё НЕ материализованы
	// (журнал пуст до прохода). Композит-членство недостижимо — окно закрыто.
	require.False(t,
		bindingReachesObject(t, ctx, pool, ownerBIDA, ownerUser, objA),
		"окно бэкфилла IAM-ID-1-31 (B2): ДО материализации доступ обязан быть fail-closed, а не открытый — "+
			"неготовое членство %s недостижимо. Открытый доступ в окне означал бы утечку до бэкфилла.", objA)

	// ── контроль машинности: реальный проход бэкфилла материализует ───────────
	// Без этого красный ниже был бы неотличим от «не выполнилось». Проход
	// материализует владельческий scope-self на `account:<A>` (доказано P8_02).
	runner, _ := newBackfill(pool)
	res, err := runner.RunOnce(ctx)
	require.NoError(t, err)
	require.True(t, res.Executed, "единственный RunOnce обязан исполнить проход бэкфилла")
	require.True(t,
		ledgerHasTuple(t, ctx, pool, ownerBIDA, ownerUser, "admin", "account:"+string(accA.ID)),
		"машинность: проход бэкфилла исполнился и материализует владельческий scope-self на `account:<A>`. "+
			"Без этого контроля красный ниже читался бы как «не выполнилось», а не как отсутствие предмета")

	// ── ПОЛНОТА ПОСЛЕ БЭКФИЛЛА (честный красный сегодня) ──────────────────────
	assert.True(t,
		bindingReachesObject(t, ctx, pool, ownerBIDA, ownerUser, objA),
		"IAM-ID-1-31 (B2) — ПОРЯДОК/ПОЛНОТА БЭКФИЛЛА. После прохода бэкфилла существующее членство %s "+
			"обязано быть материализовано → админ СВОЕГО аккаунта A достаёт по нему личность. Сегодня бэкфилл "+
			"композит-членство НЕ материализует → переключение `object_type` каталога (contract) в это окно "+
			"давало бы `v_get`/`v_list` по неготовому членству fail-closed, то есть отказ админу своего "+
			"аккаунта. Членство обязано быть материализовано (migrate) ДО того, как гейт на него обопрётся "+
			"(contract).", objA)

	t.Logf("перепись: членство (p,A) существует (%d) · окно до бэкфилла закрыто (fail-closed) · "+
		"бэкфилл исполнился и материализует scope-self на account:<A> · "+
		"полнота по композит-членству %s проверена на журнале прямого факта", nmem, objA)
}
