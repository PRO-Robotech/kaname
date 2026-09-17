// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// baseline_rollback_test.go — обратный ход, который снёс бы СВОД, отвергается
// средством миграций, и отвергается ДО того, как оно откроет базу.
//
// # Почему страж стоит здесь, а не в откатной половине свода
//
// В откатной половине свода он уже стоит — и у него есть окно: перепись живых
// удостоверений и `DROP SCHEMA … CASCADE` суть ДВА оператора, а замка между ними
// нет. Удостоверение, зафиксированное в промежутке, уничтожается, а откат
// проходит успехом. Закрыть окно на том же месте нельзя: свод ПРИМЕНЁН, а
// применённую миграцию не правят (запрет #5).
//
// Поэтому окно закрывается там, где разрушительный путь ещё достижим, — у
// средства миграций. Отказ наступает до единого оператора, значит окна нет
// вовсе, а не «оно стало уже».
//
// # Почему отказ безусловный, а не «с одобрения»
//
// Одобрение окна НЕ закрывает: одобривший попадает ровно в тот же промежуток
// между переписью и сносом. Оно лишь передвигает окно за лишний шаг оператора.
// Снос схемы — не продуктовая операция службы; тот, кому он нужен осознанно,
// сносит базу средствами базы, а не глаголом, который рядом стоит в штатной
// процедуре отката выкатки.
package main

import (
	"bytes"
	"context"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/migrations"
)

// neverAsked — читатель головы цепочки, который звать НЕЛЬЗЯ. Названная цель
// решается без базы; вызов здесь означал бы, что страж открывает соединение там,
// где вопроса к базе нет.
func neverAsked(t *testing.T) func(context.Context) (int64, error) {
	t.Helper()
	return func(context.Context) (int64, error) {
		t.Fatal("цель названа — голова цепочки у базы не спрашивается")
		return 0, nil
	}
}

// TestGuardRefusesTheTargetBelowTheBaseline — ОТРИЦАНИЕ.
func TestGuardRefusesTheTargetBelowTheBaseline(t *testing.T) {
	err := refuseRollbackOfTheBaseline(context.Background(), migrations.FS, "0", neverAsked(t))
	require.Error(t, err,
		"`down --target 0` откатывает свод: его откатная половина сносит схему целиком")
}

// TestGuardRefusalNamesWhatItProtectsAndTheWayOut — отказ обязан назвать четыре
// РАЗНЫХ слагаемых, иначе оператор прочитает «нельзя» и пойдёт в обход.
func TestGuardRefusalNamesWhatItProtectsAndTheWayOut(t *testing.T) {
	err := refuseRollbackOfTheBaseline(context.Background(), migrations.FS, "0", neverAsked(t))
	require.Error(t, err)
	msg := strings.ToLower(err.Error())
	for want, why := range map[string]string{
		"--target":           "названа РУЧКА, которой оператор это набрал",
		"baseline version 1": "названа версия свода — иначе непонятно, что считается «ниже»",
		"schema":             "названо последствие: сносится схема целиком",
		"irrevers":           "названа необратимость — иначе отказ читается как придирка",
		"way out":            "назван выход, иначе страж обходят",
	} {
		require.Contains(t, msg, want, "отказ обязан нести %s: %v", why, err)
	}
}

// TestGuardLetsThroughATargetAtTheBaseline — ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ.
//
// Без него отрицание выше выполняется тождественно: страж, отвергающий ВСЁ,
// прошёл бы обе пробы и сломал бы штатный откат выкатки.
func TestGuardLetsThroughATargetAtTheBaseline(t *testing.T) {
	require.NoError(t,
		refuseRollbackOfTheBaseline(context.Background(), migrations.FS, "1", neverAsked(t)),
		"`--target 1` оставляет свод применённым — откатывается только то, что легло поверх")
}

// TestGuardLetsThroughATargetAboveTheBaseline — второй положительный контроль:
// штатная форма процедуры отката выкатки.
func TestGuardLetsThroughATargetAboveTheBaseline(t *testing.T) {
	require.NoError(t,
		refuseRollbackOfTheBaseline(context.Background(), migrations.FS, "20260913114722", neverAsked(t)),
		"откат до версии поверх свода — штатная процедура, страж её не касается")
}

// TestGuardRefusesTheBareStepBackWhenTheHeadIsTheBaseline — вторая форма того же
// пути. `down` без цели откатывает РОВНО ОДНУ, самую позднюю: когда самая поздняя
// и есть свод, шаг назад сносит схему. Страж, знающий только про `--target`, был
// бы половиной стража.
func TestGuardRefusesTheBareStepBackWhenTheHeadIsTheBaseline(t *testing.T) {
	err := refuseRollbackOfTheBaseline(context.Background(), migrations.FS, "",
		func(context.Context) (int64, error) { return 1, nil })
	require.Error(t, err,
		"голова цепочки — свод: шаг назад снёс бы схему")
}

// TestGuardLetsThroughTheBareStepBackAboveTheBaseline — ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ
// к предыдущей.
func TestGuardLetsThroughTheBareStepBackAboveTheBaseline(t *testing.T) {
	require.NoError(t,
		refuseRollbackOfTheBaseline(context.Background(), migrations.FS, "",
			func(context.Context) (int64, error) { return 20260914120000, nil }),
		"поверх свода лежат миграции — шаг назад откатывает ИХ, и это штатно")
}

// TestGuardRefusesWhenTheHeadCannotBeRead — «не смог спросить» НЕ есть «можно».
func TestGuardRefusesWhenTheHeadCannotBeRead(t *testing.T) {
	err := refuseRollbackOfTheBaseline(context.Background(), migrations.FS, "",
		func(context.Context) (int64, error) { return 0, context.DeadlineExceeded })
	require.Error(t, err, "голова цепочки не прочитана — отказ, а не молчаливый откат")
}

// TestBaselineVersionIsDerivedFromTheChain — версия свода ВЫВОДИТСЯ из цепочки,
// а не выписывается числом: выписанное разошлось бы с деревом молча.
func TestBaselineVersionIsDerivedFromTheChain(t *testing.T) {
	v, err := migrations.BaselineVersion(migrations.FS)
	require.NoError(t, err)
	require.EqualValues(t, 1, v, "свод этой цепочки — 0001_initial.sql")

	synthetic, err := migrations.BaselineVersion(fstest.MapFS{
		"20260101000000_second.sql": &fstest.MapFile{},
		"0042_squashed.sql":         &fstest.MapFile{},
		"README.md":                 &fstest.MapFile{},
	})
	require.NoError(t, err)
	require.EqualValues(t, 42, synthetic,
		"свод — НАИМЕНЬШАЯ версия цепочки, какой бы ни была её запись")
}

// TestBaselineVersionRefusesAnEmptyChain — пустой обход есть отказ, а не ноль:
// «версий не нашлось» иначе неотличимо от «версий нет».
func TestBaselineVersionRefusesAnEmptyChain(t *testing.T) {
	_, err := migrations.BaselineVersion(fstest.MapFS{"README.md": &fstest.MapFile{}})
	require.Error(t, err)
}

// TestDownCommandWiresTheGuardBeforeItOpensTheDatabase — провязка. Адрес
// указывает в никуда: дойди исполнение до открытия базы, проба ждала бы её и
// отказ пришёл бы о соединении, а не о своде.
func TestDownCommandWiresTheGuardBeforeItOpensTheDatabase(t *testing.T) {
	_, _, err := runCommandFS(t, migrations.FS,
		[]string{"down", "--target", "0", "--dsn", "postgres://u:p@127.0.0.1:1/nodb?sslmode=disable"}, nil)
	require.Error(t, err)
	require.Contains(t, strings.ToLower(err.Error()), "way out",
		"отказ обязан прийти ОТ СТРАЖА и ДО базы: %v", err)
}

// runCommandFS — тот же разбор дерева команд, что и `runCommand`, но с НАСТОЯЩЕЙ
// цепочкой: страж выводит версию свода из неё, и на пустой цепочке предмета у
// него нет.
func runCommandFS(t *testing.T, fsys fs.FS, args []string, env map[string]string) (stdout, stderr string, err error) {
	t.Helper()
	for k, v := range env {
		t.Setenv(k, v)
	}
	cmd := newRootCmd(fsys)
	var sout, serr bytes.Buffer
	cmd.SetOut(&sout)
	cmd.SetErr(&serr)
	cmd.SetArgs(args)
	err = cmd.Execute()
	return sout.String(), serr.String(), err
}
