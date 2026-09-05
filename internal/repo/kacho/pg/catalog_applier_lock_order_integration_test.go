// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// catalog_applier_lock_order_integration_test.go — ПОРЯДОК ВЗЯТИЯ ЗАМКОВ на
// строки каталога у ПРИМЕНИТЕЛЯ (задача продукта #2012, преемник #1996).
//
// # Что #1996 закрыл и что осталось
//
// #1996 выровнял порядок у ПИСАТЕЛЯ РОЛИ: он берёт замки на строки каталога
// одним оператором и в порядке, который назначает БАЗА (`ORDER BY dotted`),
// прежде чем трогать строки селекторов. Пара, спорящая за ОДИН тип, взаимной
// блокировки больше не даёт.
//
// # Постановка #2012 назвала не тот механизм, и это перемерено
//
// Задача утверждала, что порядок операторов снятия задаёт «разница манифестов».
// Это НЕВЕРНО: снимаемые строки приходят из `ReadModule` (`ORDER BY resource`) и
// фильтруются `Withdrawn` С СОХРАНЕНИЕМ ПОРЯДКА, а объявленные — из `RowsOf`,
// который сортирует их по имени. Обе последовательности возрастающие, и внутри
// каждой инверсии нет.
//
// Инверсия живёт МЕЖДУ НИМИ. Применитель трогает строки каталога ДВАЖДЫ и в
// таком порядке:
//
//	шаг 4  UpsertResource  по ОБЪЯВЛЕННЫМ     (возрастающе)
//	шаг 7  RetireResource  по СНИМАЕМЫМ       (возрастающе)
//
// Объявленные и снимаемые не пересекаются, но их КОНКАТЕНАЦИЯ возрастающей не
// является: если снимается имя, которое сортируется РАНЬШЕ сохраняемого, замок
// на него берётся ПОЗЖЕ. Модуль с живыми `aaa` и `zzz`, манифест которого
// оставляет только `zzz`, даёт порядок `zzz → aaa` — обратный тому, в котором
// эти же две строки берёт писатель роли.
//
// `INSERT … ON CONFLICT DO UPDATE` держит замок на конфликтующей строке ДАЖЕ
// когда `WHERE` ветви `DO UPDATE` ложен и строка не меняется, поэтому шаг 4
// берёт замок на КАЖДУЮ объявленную строку, а не только на изменяемые.
//
// # Почему проба, а не чтение
//
// Порядок взятия замков прочитать нельзя: он есть свойство ИСПОЛНЕНИЯ, и обе
// стороны здесь — НАСТОЯЩИЕ (`modulecatalog.Applier` и `roleWriter`), а не их
// дублёры. Дублёр пережил бы правку оригинала молча.

import (
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho-iam/internal/errors"
	kachopg "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg"
)

// crossLockEarly / crossLockLate — два типа ОДНОГО модуля, названные так, чтобы
// порядок между ними задавала база, а не наша догадка: `aaa` < `zzz` при любой
// сортировке текста. Снимается РАННИЙ, сохраняется ПОЗДНИЙ — именно эта пара и
// даёт применителю обратный порядок.
const (
	crossEarlyName = "aaa"
	crossLateName  = "zzz"
	crossLockEarly = applierProbeModule + "." + crossEarlyName
	crossLockLate  = applierProbeModule + "." + crossLateName
)

// isDeadlock — взаимная блокировка в ЛЮБОМ из двух видов, в каких она доезжает
// до вызывающего.
//
// Сырым оператором это `40P01`; через писателя роли — `iamerr.ErrAborted`:
// приведение относит `40P01` к семейству конфликтов сериализации, и имени
// SQLSTATE в тексте уже нет. Проверяются ОБА вида — проба, знающая один,
// зеленела бы на той стороне, где приезжает другой.
func isDeadlock(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, iamerr.ErrAborted) {
		return true
	}
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "40P01"
}

// TestCatalogApplierTakesCatalogRowLocksInTheSameOrderAsTheRoleWriter — НЕСУЩЕЕ
// утверждение #2012.
//
// Три утверждения вместе, и порознь каждое выполнимо мимо предмета:
//
//  1. применитель ВСТАЁТ на строке каталога — иначе стороны разошлись во времени
//     и не встретились, а «взаимной блокировки нет» получено даром;
//  2. ни одна сторона не отвергнута взаимной блокировкой — собственно предмет;
//  3. обе стороны доходят до конца — иначе п. 2 выполним стороной, которая
//     перестала работать вовсе.
func TestCatalogApplierTakesCatalogRowLocksInTheSameOrderAsTheRoleWriter(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует Postgres")
	}
	ctx, pool := catalogPool(t)
	applier := applierOver(t, pool)
	repo := kachopg.New(pool, nil)

	// ── ВХОД: два живых типа одного модуля ────────────────────────────────────
	_, err := applier.Apply(ctx, probeManifest(
		probeResource(crossEarlyName, "get"),
		probeResource(crossLateName, "get"),
	))
	require.NoError(t, err)

	role := catalogRole(t, ctx, pool, "crosslock2012")
	require.NoError(t,
		upsertSelector(ctx, pool, role, "fp-crosslock", []string{crossLockEarly, crossLockLate}),
		"ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: оба типа живы и селектор, называющий их, записывается")

	// ── ДЕРЖАТЕЛЬ раннего имени: задерживает применителя, пропускает роль ─────
	//
	// `FOR KEY SHARE`, а не `FOR UPDATE`, и это несущее: держатель обязан
	// ЗАДЕРЖАТЬ применителя (тот меняет `live`, входящий в ключ, — значит берёт
	// `FOR UPDATE`) и НЕ задержать писателя роли (тот берёт ровно `FOR KEY
	// SHARE`, а два таких замка совместимы). Держатель `FOR UPDATE` остановил бы
	// обе стороны, и встретиться им было бы негде.
	holder, err := pool.Begin(ctx)
	require.NoError(t, err)
	holderDone := false
	defer func() {
		if !holderDone {
			_ = holder.Rollback(ctx)
		}
	}()
	var held int
	require.NoError(t, holder.QueryRow(ctx, `
		SELECT count(*) FROM (
		  SELECT 1 FROM kacho_iam.catalog_resource
		   WHERE dotted = $1 AND live
		     FOR KEY SHARE) s`, crossLockEarly).Scan(&held))
	require.Equalf(t, 1, held, "ПРЕДПОСЫЛКА: живой строки %s нет — держать нечего", crossLockEarly)

	// ── СТОРОНА A: НАСТОЯЩИЙ применитель, снимающий РАННЕЕ имя ────────────────
	ares := make(chan error, 1)
	go func() {
		_, aerr := applier.Apply(ctx, probeManifest(probeResource(crossLateName, "get")))
		ares <- aerr
	}()

	// ПРЕДПОСЫЛКА п. 1: применитель встал на строке каталога. Без неё всё ниже
	// вакуумно — стороны не встретились бы вовсе.
	select {
	case aerr := <-ares:
		t.Fatalf("применитель НЕ встал на строке каталога (%v) — предпосылка пробы нарушена, "+
			"и утверждение о порядке замков беспредметно", aerr)
	case <-time.After(2 * time.Second):
	}

	// ── СТОРОНА B: НАСТОЯЩАЯ правка правил роли по ОБОИМ типам ────────────────
	bres := make(chan error, 1)
	go func() {
		w, werr := repo.Writer(ctx)
		if werr != nil {
			bres <- werr
			return
		}
		if rerr := w.RolesW().ReplaceRuleSelectors(ctx, role, []domain.RuleSelector{{
			RuleFP: "fp-crosslock", Arm: domain.ArmAnchor,
			ObjectTypes: []string{crossLockEarly, crossLockLate},
		}}); rerr != nil {
			_ = w.Rollback(ctx)
			bres <- rerr
			return
		}
		bres <- w.Commit(ctx)
	}()

	// Держатель отпускается: дальше стороны разбираются между собой, и если их
	// порядки обратны — Postgres обнаружит пару и отвергнет одну из них.
	time.Sleep(2 * time.Second)
	require.NoError(t, holder.Rollback(ctx))
	holderDone = true

	var aerr, berr error
	for i := 0; i < 2; i++ {
		select {
		case aerr = <-ares:
		case berr = <-bres:
		case <-time.After(30 * time.Second):
			t.Fatalf("сторона не завершилась за 30с: применитель=%v правка роли=%v", aerr, berr)
		}
	}
	t.Logf("исход: применитель %v · правка роли %v", aerr, berr)

	require.Falsef(t, isDeadlock(aerr),
		"ПРИМЕНИТЕЛЬ отвергнут взаимной блокировкой (%v): его порядок взятия замков на "+
			"строки каталога обратен порядку писателя роли — объявленные он берёт на шаге "+
			"upsert, снимаемые на шаге retire, и снимаемое имя, сортирующееся раньше "+
			"сохраняемого, достаётся ему последним", aerr)
	require.Falsef(t, isDeadlock(berr),
		"ПРАВКА РОЛИ отвергнута взаимной блокировкой (%v): цену за инверсию, которую "+
			"создаёт выкатка, платит арендатор, и повтор её не меняет — условие "+
			"наступления от него не зависит", berr)

	require.NoErrorf(t, aerr, "применитель не дошёл до конца (%v) — тогда «блокировки нет» "+
		"выполнимо тем, что он не добрался до спорных строк", aerr)
	require.NoErrorf(t, berr, "правка правил роли отвергнута (%v) — тогда «блокировки нет» "+
		"выполнимо писателем, который перестал писать", berr)

	// Обе работы ЛЕГЛИ: раннее имя снято, селектор приведён к каталожному факту.
	var liveEarly int
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*) FROM kacho_iam.catalog_resource WHERE dotted = $1 AND live`,
		crossLockEarly).Scan(&liveEarly))
	require.Zerof(t, liveEarly, "строка %s не снята — применитель отчитался успехом впустую",
		crossLockEarly)
}

// TestLoneCatalogApplyAgainstAnIdleCatalogPasses — ПАРНЫЙ ПОЛОЖИТЕЛЬНЫЙ:
// одиночное снятие проходит и НЕ ЖДЁТ.
//
// Без него отрицание выше зеленело бы на применителе, который блокируется всегда
// либо отказывает всегда: «взаимной блокировки нет» верно и для того, кто не
// доходит до строк вовсе.
func TestLoneCatalogApplyAgainstAnIdleCatalogPasses(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует Postgres")
	}
	ctx, pool := catalogPool(t)
	applier := applierOver(t, pool)

	_, err := applier.Apply(ctx, probeManifest(
		probeResource("loneearly", "get"),
		probeResource("lonelate", "get"),
	))
	require.NoError(t, err)

	done := make(chan error, 1)
	go func() {
		_, aerr := applier.Apply(ctx, probeManifest(probeResource("lonelate", "get")))
		done <- aerr
	}()
	select {
	case aerr := <-done:
		require.NoError(t, aerr, "одиночное применение отвергнуто на свободном каталоге")
	case <-time.After(20 * time.Second):
		t.Fatal("одиночное применение ЖДЁТ при свободном каталоге и без соперника — " +
			"взятый замок стоит, а не держит")
	}

	var live int
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*) FROM kacho_iam.catalog_resource
		 WHERE dotted = $1 AND live`, applierProbeModule+".loneearly").Scan(&live))
	require.Zero(t, live, "строка не снята — применение отчиталось успехом впустую")
}
