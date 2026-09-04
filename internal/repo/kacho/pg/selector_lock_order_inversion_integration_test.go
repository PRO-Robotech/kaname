// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// selector_lock_order_inversion_integration_test.go — ПОРЯДОК ВЗЯТИЯ ЗАМКОВ у
// писателя роли (задача продукта #1996, преемник #1985).
//
// # Что здесь утверждается — и почему это переписано, а не ослаблено
//
// Прежняя редакция ЗАКРЕПЛЯЛА сегодняшний исход: инверсия порядка даёт взаимную
// блокировку, и Postgres отвергает СТОРОНУ АРЕНДАТОРА. Она была права о своей
// ревизии и прямо говорила, что при выравнивании порядка её надо переписать под
// решение. Порядок выровнен — она переписана.
//
//	применитель каталога   строка каталога (снятие) → строки селекторов (вырезание)
//	правка правил роли     строка каталога (замок)  → строки селекторов (замена)
//
// # Дублёр стороны арендатора СНЯТ, и это несущее
//
// Прежняя редакция изображала сторону арендатора двумя операторами, написанными
// в самой пробе, и её шапка говорила «дословно порядок `ReplaceRuleSelectors`».
// Копия пережила бы правку оригинала МОЛЧА: выровняй порядок у писателя — проба
// осталась бы красной по своему собственному порядку и обвиняла бы починенный
// код. Здесь зовётся НАСТОЯЩИЙ писатель, и другого способа увидеть его порядок
// нет.
//
// # Отказ остаётся, и он ДРУГОЙ
//
// Выровненный порядок не делает правку успешной: строку каталога сняли, и
// писать селектор, называющий снятый тип, по-прежнему нельзя. Меняется КЛАСС
// отказа, и это единственное, о чём проба утверждает:
//
//	было   ABORTED «conflicting concurrent change, retry the request»
//	стало  INVALID_ARGUMENT — вход негоден, и повтор его годным не сделает
//
// Класс, а не текст: различие машинно читаемо сентинелом, тогда как прозу
// пришлось бы разбирать. И класс здесь несёт РЕШЕНИЕ вызывающего: «повтори»
// на взаимной блокировке советует действие, которое условия не меняет — оно
// от арендатора не зависит вовсе, — а «вход негоден» говорит, что менять надо
// правило.
//
// Замер попутный и назван, потому что расходится с постановкой задачи: сырыми
// операторами взаимная блокировка приходит как `40P01`, а ЧЕРЕЗ ПИСАТЕЛЯ она
// приезжала вызывающему как `ABORTED` — `40P01` относится приведением к
// семейству конфликтов сериализации.
//
// # Найдено по дороге — заведено своей задачей и ЗАКРЫТО (#2011)
//
// Контрактный текст стража живости («object_types: <элемент> is not a live
// platform resource (role <роль>)») до вызывающего не доезжал: у приведения не
// было ветви на имя этого ограничения, и арендатор получал общее «Illegal
// argument: value violates a constraint» — без элемента и без роли. Ветвь
// заведена, текст производителя доезжает дословно; утверждают это
// `pgmaperr_selector_liveness_lane_test.go` (приведение) и
// `selector_liveness_refusal_reaches_the_caller_integration_test.go` (вся
// цепочка). Здесь по-прежнему утверждается КЛАСС отказа, а не его текст: два
// места об одном предмете разошлись бы молча.
//
// # Чего проба НЕ утверждает
//
// Она не утверждает ничего о порядке, в котором берёт замки ПРИМЕНИТЕЛЬ: её
// сторона применителя — два оператора, написанные в самой пробе, то есть модель
// состояния, а не он сам. Перекрёстный порядок по нескольким типам закрыт
// СВОЕЙ задачей (#2012) и утверждается своей пробой
// (`catalog_applier_lock_order_integration_test.go`), где обе стороны —
// настоящие.

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

// replaceSelectorsOutcome — исход правки правил роли НАСТОЯЩИМ писателем,
// исполненной в своей транзакции записи.
//
// Транзакция открывается писателем репозитория, а не пробой: предмет
// утверждения — порядок, в котором замки берёт ОН, и своя транзакция вокруг
// чужого метода этот порядок не воспроизвела бы.
type replaceSelectorsOutcome struct {
	err error
}

// TestSelectorWriteTakesTheCatalogRowLockBeforeTheSelectorRows — НЕСУЩЕЕ
// утверждение (#1996): правка правил роли, идущая одновременно со снятием
// строки каталога, которую называют её селекторы, БОЛЬШЕ НЕ даёт взаимной
// блокировки.
//
// Три утверждения вместе, и порознь каждое выполнимо мимо предмета:
//
//  1. сторона применителя доходит до конца — иначе «нет блокировки» выполнимо
//     тем, что применитель просто не дошёл до спорных строк;
//  2. сторона арендатора НЕ получает `40P01` — собственно предмет;
//  3. она получает КОНТРАКТНЫЙ отказ стража живости — иначе п. 2 выполним
//     писателем, который перестал писать вовсе, и снятый тип уехал бы в
//     селектор молча.
func TestSelectorWriteTakesTheCatalogRowLockBeforeTheSelectorRows(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует Postgres")
	}
	ctx, pool := catalogPool(t)
	applier := applierOver(t, pool)
	repo := kachopg.New(pool, nil)

	const doomed = applierProbeModule + ".lockordergone"
	_, err := applier.Apply(ctx, probeManifest(probeResource("lockordergone", "get")))
	require.NoError(t, err)

	role := catalogRole(t, ctx, pool, "lockorder1996")
	require.NoError(t, upsertSelector(ctx, pool, role, "fp-lockorder", []string{doomed}),
		"ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: живой тип обязан записаться")

	// ── СТОРОНА A: строка каталога помечена снятой (замок на строке каталога) ──
	txA, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = txA.Rollback(ctx) }()
	_, err = txA.Exec(ctx, skewRetireVerbsDirect, applierProbeModule, "lockordergone")
	require.NoError(t, err)
	_, err = txA.Exec(ctx, skewRetireDirect, doomed)
	require.NoError(t, err)

	// ── СТОРОНА B: НАСТОЯЩАЯ правка правил роли ───────────────────────────────
	bres := make(chan replaceSelectorsOutcome, 1)
	go func() {
		w, werr := repo.Writer(ctx)
		if werr != nil {
			bres <- replaceSelectorsOutcome{err: werr}
			return
		}
		rerr := w.RolesW().ReplaceRuleSelectors(ctx, role, []domain.RuleSelector{{
			RuleFP: "fp-lockorder", Arm: domain.ArmAnchor, ObjectTypes: []string{doomed},
		}})
		if rerr != nil {
			_ = w.Rollback(ctx)
			bres <- replaceSelectorsOutcome{err: rerr}
			return
		}
		bres <- replaceSelectorsOutcome{err: w.Commit(ctx)}
	}()

	// ПРЕДПОСЫЛКА: B встала на строке каталога, которую держит A. Без неё всё
	// ниже вакуумно — стороны разошлись бы во времени и не встретились вовсе.
	select {
	case out := <-bres:
		t.Fatalf("правка роли НЕ встала на строке каталога (%v) — предпосылка пробы "+
			"нарушена, и утверждение о порядке замков беспредметно", out.err)
	case <-time.After(time.Second):
	}

	// ── A идёт за строками селекторов той же роли ────────────────────────────
	_, aerr := txA.Exec(ctx,
		`DELETE FROM kacho_iam.role_rule_selectors WHERE role_id = $1 AND rule_fp = 'fp-lockorder'`,
		string(role))
	require.NoErrorf(t, aerr,
		"сторона ПРИМЕНИТЕЛЯ отвергнута (%v) — при выровненном порядке она обязана "+
			"доходить до конца: замка на строках селекторов у правки роли в этот момент нет",
		aerr)
	require.NoError(t, txA.Commit(ctx), "сторона применителя не закоммичена")

	out := <-bres
	t.Logf("исход инверсии: сторона применителя <nil> · сторона правки роли %v", out.err)

	require.Errorf(t, out.err,
		"правка роли записала селектор, называющий СНЯТЫЙ тип %q: страж живости перестал "+
			"отвергать, и снятый тип уехал бы в селектор молча", doomed)
	require.Falsef(t, errors.Is(out.err, iamerr.ErrAborted),
		"правка правил роли отвергнута КОНФЛИКТОМ, а не входом (%v) — так приезжает "+
			"взаимная блокировка (`40P01` относится приведением к семейству конфликтов "+
			"сериализации): порядок взятия замков у писателя роли по-прежнему обратен "+
			"порядку применителя, и цену за инверсию платит арендатор", out.err)
	require.Falsef(t, strings.Contains(out.err.Error(), "retry"),
		"отказ советует ПОВТОР (%v): условие наступления от арендатора не зависит, и "+
			"повтор его не меняет", out.err)
	require.Truef(t, errors.Is(out.err, iamerr.ErrInvalidArg),
		"отказ правки роли не отнесён к негодному входу (%v): страж живости обязан "+
			"отвергнуть селектор, называющий снятый тип, — и отвергнуть так, чтобы "+
			"вызывающий знал, что менять надо правило", out.err)
}

// TestLoneSelectorWriteAgainstALiveCatalogPasses — ПАРНЫЙ ПОЛОЖИТЕЛЬНЫЙ: без
// соперника правка правил роли по ЖИВОМУ типу проходит и не ждёт.
//
// Без него отрицание выше зеленело бы на писателе, который блокируется всегда
// либо отвергает всё: «не взаимная блокировка, а контрактный отказ» верно и для
// писателя, отвергающего каждую запись.
func TestLoneSelectorWriteAgainstALiveCatalogPasses(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует Postgres")
	}
	ctx, pool := catalogPool(t)
	applier := applierOver(t, pool)
	repo := kachopg.New(pool, nil)

	const alive = applierProbeModule + ".lockorderstay"
	_, err := applier.Apply(ctx, probeManifest(probeResource("lockorderstay", "get")))
	require.NoError(t, err)

	role := catalogRole(t, ctx, pool, "lockorder1996ok")

	done := make(chan error, 1)
	go func() {
		w, werr := repo.Writer(ctx)
		if werr != nil {
			done <- werr
			return
		}
		if rerr := w.RolesW().ReplaceRuleSelectors(ctx, role, []domain.RuleSelector{{
			RuleFP: "fp-lockorder-ok", Arm: domain.ArmAnchor, ObjectTypes: []string{alive},
		}}); rerr != nil {
			_ = w.Rollback(ctx)
			done <- rerr
			return
		}
		done <- w.Commit(ctx)
	}()

	select {
	case werr := <-done:
		require.NoError(t, werr, "одиночная правка правил роли по ЖИВОМУ типу отвергнута")
	case <-time.After(10 * time.Second):
		t.Fatal("одиночная правка правил роли ЖДЁТ при живом каталоге и без соперника — " +
			"взятый замок стоит, а не держит")
	}

	var stored []string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT object_types FROM kacho_iam.role_rule_selectors
		  WHERE role_id = $1 AND rule_fp = 'fp-lockorder-ok'`, string(role)).Scan(&stored))
	require.Equalf(t, []string{alive}, stored,
		"селектор записан не тем, что просили (%v) — «прошло» зеленело бы на писателе, "+
			"который ничего не пишет", stored)
}
