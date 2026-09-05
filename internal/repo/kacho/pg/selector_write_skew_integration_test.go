// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// selector_write_skew_integration_test.go — ОДНОВРЕМЕННОСТЬ снятия строки
// каталога и записи селектора, её называющего (задача продукта #1985).
//
// # Предмет: это ПЕРЕКОС ЗАПИСИ, а не «спросить, затем сделать»
//
// Каждая сторона исполнена одним оператором и корректна НА СВОЁМ СНИМКЕ:
//
//   - страж живости селектора читает `catalog_resource` по снимку пишущей
//     транзакции и видит строку живой — незакоммиченного снятия он не видит;
//   - вырезание применителя читает `role_rule_selectors` по своему — только что
//     записанной, незакоммиченной строки селектора оно не видит.
//
// Обе коммитятся, и селектор остаётся называть снятый тип. Программной проверкой
// это не закрывается ни с одной стороны (запрет #10) — только ОБЩИМ ЗАМКОМ.
//
// # Почему пробы ДВЕ, а не одна
//
// Порядок обеих сторон произволен, и «исход один и тот же при любом порядке» —
// утверждение о ДВУХ порядках. Проба одного порядка зеленела бы на замке,
// который держит только его.
//
// Исходы у порядков РАЗНЫЕ, и это не расхождение: селектор записан раньше —
// применитель обязан его увидеть и вырезать; строка каталога снята раньше —
// запись селектора обязана быть отвергнута. Общее у них ровно то, что и
// утверждается: ПОВИСШИХ НОЛЬ.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
)

// skewRetireVerbsDirect / skewRetireDirect — модель СОСТОЯНИЯ применителя,
// дошедшего до снятия строки, в незакоммиченной транзакции.
//
// Оператор написан здесь, а не взят у писателя, намеренно: пробе нужна не его
// форма, а ровно тот факт, который видит страж живости, — `live = false` в чужой
// незакоммиченной транзакции. Вторым производственным писателем это не является
// и разойтись с `RetireResource` не может: сходятся они по одной колонке, и
// именно она здесь и утверждается.
//
// Порядок ОБЯЗАТЕЛЕН и повторяет применителя: глагол ссылается на ЖИВОЙ ресурс
// (`catalog_verb_resource_live_fk`), поэтому ресурс снимается ПОСЛЕ своих
// глаголов. Снятие ресурса вперёд глаголов отвергается ключом — что проба и
// обнаружила на первом же прогоне.
const skewRetireVerbsDirect = `
	UPDATE kacho_iam.catalog_verb
	   SET retired_at = now(), live = false, retired_reason = 'проба перекоса записи'
	 WHERE module = $1 AND resource = $2 AND live`

const skewRetireDirect = `
	UPDATE kacho_iam.catalog_resource
	   SET retired_at = now(), live = false, retired_reason = 'проба перекоса записи'
	 WHERE dotted = $1 AND live`

// upsertSelector — запись селектора ТЕМ ЖЕ путём, каким идут оба
// производственных писателя: `ON CONFLICT (role_id, rule_fp) DO UPDATE`. Простая
// вставка `writeSelector` повтора не выдерживает и меряла бы не то.
func upsertSelector(ctx context.Context, pool *pgxpool.Pool,
	role domain.RoleID, fp string, types []string) error {
	_, err := pool.Exec(ctx, `
		INSERT INTO kacho_iam.role_rule_selectors
		  (role_id, rule_fp, arm, object_types, resource_names, match_labels, created_at, updated_at)
		VALUES ($1, $2, 'anchor', $3, '{}', '{}'::jsonb, now(), now())
		ON CONFLICT (role_id, rule_fp) DO UPDATE
		   SET object_types = EXCLUDED.object_types, updated_at = now()`,
		string(role), fp, types)
	return err
}

// TestSelectorWriteSkew_SelectorFirst — селектор записан РАНЬШЕ снятия.
//
// Без общего замка применитель не видит незакоммиченной строки селектора и
// проходит мимо; строка остаётся называть снятый тип. С замком запись селектора
// держит строку каталога, снятие ЖДЁТ её коммита — и вырезание, идущее следом,
// уже видит записанное.
func TestSelectorWriteSkew_SelectorFirst(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует Postgres")
	}
	ctx, pool := catalogPool(t)
	applier := applierOver(t, pool)

	const doomed = applierProbeModule + ".skewfirstgone"
	_, err := applier.Apply(ctx, probeManifest(
		probeResource("skewfirstgone", "get"),
		probeResource("skewfirststay", "get"),
	))
	require.NoError(t, err)

	role := catalogRole(t, ctx, pool, "skew1985first")

	read0 := selectorObjectTypesRead(t, ctx, pool)
	dangling0, list0 := selectorsNamingDeadTypes(t, ctx, pool)
	require.Positivef(t, read0, "прочитано ноль элементов object_types — перепись "+
		"беспредметна, и её «повисших ноль» получено даром")
	require.Zerof(t, dangling0, "на входе уже есть повисшие %v — измеренное дальше "+
		"будет смешано с чужим", list0)

	// ── СТОРОНА B: селектор записан и НЕ закоммичен ───────────────────────────
	txB, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = txB.Rollback(ctx) }()

	_, err = txB.Exec(ctx, `
		INSERT INTO kacho_iam.role_rule_selectors
		  (role_id, rule_fp, arm, object_types, resource_names, match_labels, created_at, updated_at)
		VALUES ($1, 'fp-skew-first', 'anchor', $2, '{}', '{}'::jsonb, now(), now())`,
		string(role), []string{doomed})
	require.NoErrorf(t, err, "ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: живой тип обязан записаться — "+
		"иначе одновременности не из чего строить: %v", err)

	// ── СТОРОНА A: применитель снимает ту же строку каталога ──────────────────
	done := make(chan error, 1)
	go func() {
		_, aerr := applier.Apply(ctx, probeManifest(probeResource("skewfirststay", "get")))
		done <- aerr
	}()

	blocked := false
	select {
	case aerr := <-done:
		require.NoErrorf(t, aerr, "применение отвергнуто: %v", aerr)
	case <-time.After(2 * time.Second):
		blocked = true
	}
	t.Logf("снятие дождалось коммита записи селектора: %v", blocked)

	require.NoError(t, txB.Commit(ctx))
	if blocked {
		require.NoErrorf(t, <-done, "применение отвергнуто после разблокировки")
	}

	// ── ИСХОД ────────────────────────────────────────────────────────────────
	read1 := selectorObjectTypesRead(t, ctx, pool)
	dangling1, list1 := selectorsNamingDeadTypes(t, ctx, pool)
	t.Logf("перепись: элементов object_types прочитано %d → %d · повисших %d %v",
		read0, read1, dangling1, list1)

	require.Truef(t, blocked, "снятие НЕ дождалось записи селектора — общего замка нет, "+
		"и обе стороны разошлись по своим снимкам. Замок обязан стоять на стороне стража "+
		"живости: он единственный читает каталог в момент записи селектора")
	require.Zerof(t, dangling1, "селектор остался называть снятый тип: %v\n"+
		"Каждая сторона корректна на своём снимке — значит закрывается это только "+
		"общим замком, а не проверкой в коде (запрет #10)", list1)
}

// TestSelectorWriteSkew_RetireFirst — снятие раньше записи селектора.
//
// Без общего замка страж живости читает каталог по СВОЕМУ снимку, видит строку
// живой и пропускает запись; обе коммитятся — повисший. С замком запись ЖДЁТ
// коммита снятия и после него перечитывает строку по её новой версии: живой она
// уже не является, и запись отвергается — тем же отказом, что и всякая запись
// снятого типа.
func TestSelectorWriteSkew_RetireFirst(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует Postgres")
	}
	ctx, pool := catalogPool(t)
	applier := applierOver(t, pool)

	const doomed = applierProbeModule + ".skewsecondgone"
	_, err := applier.Apply(ctx, probeManifest(probeResource("skewsecondgone", "get")))
	require.NoError(t, err)

	role := catalogRole(t, ctx, pool, "skew1985second")

	dangling0, list0 := selectorsNamingDeadTypes(t, ctx, pool)
	require.Zerof(t, dangling0, "на входе уже есть повисшие %v", list0)

	// ── СТОРОНА A: строка каталога помечена снятой, НЕ закоммичено ────────────
	txA, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = txA.Rollback(ctx) }()

	_, err = txA.Exec(ctx, skewRetireVerbsDirect, applierProbeModule, "skewsecondgone")
	require.NoError(t, err)
	tag, err := txA.Exec(ctx, skewRetireDirect, doomed)
	require.NoError(t, err)
	require.EqualValuesf(t, 1, tag.RowsAffected(),
		"строка каталога не помечена снятой — одновременности не из чего строить")

	// ── СТОРОНА B: запись селектора, называющего ту же строку ────────────────
	res := make(chan error, 1)
	go func() { res <- writeSelector(ctx, pool, role, "fp-skew-second", []string{doomed}) }()

	blocked := false
	var werr error
	select {
	case werr = <-res:
	case <-time.After(2 * time.Second):
		blocked = true
	}
	t.Logf("запись селектора дождалась коммита снятия: %v", blocked)

	require.NoError(t, txA.Commit(ctx))
	if blocked {
		werr = <-res
	}

	dangling1, list1 := selectorsNamingDeadTypes(t, ctx, pool)
	t.Logf("перепись: повисших %d %v · отказ записи: %v", dangling1, list1, werr)

	require.Truef(t, blocked, "запись селектора НЕ дождалась снятия — страж живости "+
		"судил по своему снимку, в котором строка ещё жива")
	require.Errorf(t, werr, "запись селектора, называющего снимаемый тип, прошла: "+
		"страж живости прочитал каталог по снимку, в котором строка ещё была жива")
	require.Containsf(t, werr.Error(), doomed,
		"отказ обязан назвать ЭЛЕМЕНТ — автор правила ни одного элемента "+
			"подстановочной строки сам не выбирал: %v", werr)
	require.Truef(t, strings.Contains(werr.Error(), "23514") ||
		strings.Contains(werr.Error(), "not a live platform resource"),
		"отказ пришёл НЕ от стража живости — значит закрыло его что-то другое: %v", werr)
	require.Zerof(t, dangling1, "селектор остался называть снятый тип: %v", list1)
}

// TestSelectorWriteSkew_LoneWriteOfALiveTypeStillPasses — ПАРНЫЙ ПОЛОЖИТЕЛЬНЫЙ
// КОНТРОЛЬ к обеим пробам выше.
//
// Без него «отвергнуто» и «дождалось» были бы неотличимы от замка, который
// держит ВСЯКУЮ запись селектора, — то есть от отобранной у арендатора
// возможности править свои роли.
func TestSelectorWriteSkew_LoneWriteOfALiveTypeStillPasses(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует Postgres")
	}
	ctx, pool := catalogPool(t)
	applier := applierOver(t, pool)

	const alive = applierProbeModule + ".skewcontrolalive"
	_, err := applier.Apply(ctx, probeManifest(probeResource("skewcontrolalive", "get")))
	require.NoError(t, err)

	role := catalogRole(t, ctx, pool, "skew1985control")

	start := time.Now()
	require.NoErrorf(t, upsertSelector(ctx, pool, role, "fp-skew-control", []string{alive}),
		"одиночная запись живого типа отвергнута — замок отобрал законное")
	elapsed := time.Since(start)

	// Повторная запись того же — тот же путь через `ON CONFLICT DO UPDATE`, по
	// которому идут оба производственных писателя.
	require.NoErrorf(t, upsertSelector(ctx, pool, role, "fp-skew-control", []string{alive}),
		"повторная запись живого типа отвергнута")

	var got []string
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT object_types FROM kacho_iam.role_rule_selectors
		 WHERE role_id = $1 AND rule_fp = 'fp-skew-control'`, string(role)).Scan(&got))
	t.Logf("одиночная запись живого типа: %v за %s", got, elapsed)
	require.Equal(t, []string{alive}, got)
	require.Lessf(t, elapsed, 2*time.Second,
		"одиночная запись живого типа ЖДАЛА — замок берётся там, где спорить не с кем")
}
