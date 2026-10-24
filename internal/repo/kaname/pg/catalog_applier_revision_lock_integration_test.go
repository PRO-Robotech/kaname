// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// catalog_applier_revision_lock_integration_test.go — ЗАМОК ШАГА 2р в порядке
// замков применителя каталога (kaname#865).
//
// # Что изменилось и что утверждается
//
// До kaname#865 первым строчным замком транзакции применения был шаг 2а
// (`catalogWriter.LockModuleResources`: строки `catalog_resource` модуля,
// `FOR UPDATE`, `ORDER BY dotted`). Шаг 2р (`catalogWriter.AdvanceRevision`)
// встал ПЕРЕД ним: его `INSERT … ON CONFLICT (module) DO UPDATE` берёт строку
// `catalog_module` модуля раньше строк ресурсов. Режим — `FOR NO KEY UPDATE`:
// присваиваются `applied_revision` и `applied_digest`, а ни одна из них в
// уникальные ключи строки не входит.
//
// С kaname#913 шаг 2а начинается со строки модуля (`catalogWriter.LockModuleRow`,
// `FOR UPDATE`) — раньше строк ресурсов. Значит место, где применитель ЖДЁТ
// другого писателя первым, — строка модуля шага 2а, и замок 2р к этому моменту
// уже взят.
//
// Новое ребро в графе ожиданий замок 2р дал бы, если бы с ним конфликтовал
// замок, который берёт на той же строке ДРУГОЙ писатель. Остальные писатели
// берут строку `catalog_module` только ключевым замком — проверкой внешнего
// ключа либо `roleWriter.LockOwnerModule`, то есть `FOR KEY SHARE`, — а он с
// `FOR NO KEY UPDATE` совместим. Утверждается это здесь исполнением, а не
// чтением. Держатель берёт строку модуля `FOR KEY SHARE` — так её держит
// транзакция ролей модуля, — и применитель встаёт за ним на строке модуля шага
// 2а. В этот момент:
//
//  1. строка модуля УЖЕ взята шагом 2р — `FOR NO KEY UPDATE NOWAIT` отказывает
//     `55P03` (с ключевым замком держателя этот режим совместим, отказ даёт
//     только замок 2р);
//  2. `FOR KEY SHARE NOWAIT` проходит — замок 2р с ключевым замком совместим;
//  3. близнец без ключа `revision` меняет ровно один факт и даёт обратное
//     п. 1: оператор 2р не записал пары и строки не взял, и проба отличает
//     одно от другого.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/manifest"
)

// revLockDoc — документ синтетического модуля с ресурсами `names` и ключом
// `revision: rev`; rev == 0 — без ключа. Разбирается ЗАГРУЗЧИКОМ: у манифеста,
// собранного структурой, редакции нет by construction (поля закрыты), и шаг 2р
// на нём не пишет ничего.
func revLockDoc(t *testing.T, rev int64, names ...string) *manifest.Manifest {
	t.Helper()
	var b strings.Builder
	b.WriteString("apiVersion: iam/v1\nmodule: " + applierProbeModule + "\n")
	if rev > 0 {
		fmt.Fprintf(&b, "revision: %d\n", rev)
	}
	b.WriteString("resources:\n")
	for _, n := range names {
		fmt.Fprintf(&b, "  - name: %s\n    objectType: %s_%s\n    parents: [project]\n"+
			"    producer: derived\n    verbs: [get]\n", n, applierProbeModule, n)
	}
	m, err := manifest.Load([]byte(b.String()))
	require.NoError(t, err, "фикстура: документ синтетического модуля обязан загружаться")
	if rev > 0 {
		got, declared := m.Revision()
		require.True(t, declared, "фикстура: ключ revision не прочитан загрузчиком")
		require.Equal(t, rev, got)
	}
	return m
}

// TestCatalogApplierRevisionWriteKeepsTheLockOrderOfTheRoleWriter — гонка
// kacho#2012 (применитель против писателя роли на двух типах в обратном
// порядке) при ОБЪЯВЛЕННОЙ редакции: шаг 2р пишет пару, то есть держит строку
// модуля всё время гонки. Взаимной блокировки нет, и пара записана.
func TestCatalogApplierRevisionWriteKeepsTheLockOrderOfTheRoleWriter(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует Postgres")
	}
	ctx, pool := raceApplierAgainstRoleWriter(t, "revlock865",
		revLockDoc(t, 1, crossEarlyName, crossLateName),
		revLockDoc(t, 2, crossLateName))

	// Без этого утверждения гонка выше выполнима мимо предмета: применитель,
	// не записавший пары, не держал бы строки модуля вовсе.
	rev, _ := rev865Applied(t, ctx, pool)
	require.NotNil(t, rev, "пара редакции не записана — замок шага 2р в гонке не участвовал")
	require.Equal(t, int64(2), *rev, "применённая редакция — не та, что объявлена снимающим манифестом")
}

// TestRevisionStepHoldsTheModuleRowCompatiblyWhileTheApplierWaitsOnTheModuleRow —
// пп. 1–2 шапки: замок 2р взят РАНЬШЕ замков 2а и совместим с ключевым замком.
func TestRevisionStepHoldsTheModuleRowCompatiblyWhileTheApplierWaitsOnTheModuleRow(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует Postgres")
	}
	forNoKeyUpdate, forKeyShare := probeModuleRowWhileApplierWaits(t, true)
	require.Truef(t, isLockNotAvailable(forNoKeyUpdate),
		"строка модуля не взята шагом 2р, пока применитель стоит на строке модуля шага 2а (%v): "+
			"шаг 2р не взял её раньше шага 2а — порядок, названный в шапке apply.go, ложен", forNoKeyUpdate)
	require.NoErrorf(t, forKeyShare,
		"FOR KEY SHARE на строке модуля отвергнут, пока её держит шаг 2р (%v): режим 2р "+
			"конфликтует с проверкой внешнего ключа — у писателей ролей и ресурсов появилось ребро "+
			"ожидания на применителя", forKeyShare)
}

// TestWithoutRevisionTheModuleRowStaysFreeWhileTheApplierWaitsOnTheModuleRow —
// близнец п. 3: тот же ход без ключа `revision`. Оператор 2р пары не пишет и
// строки не берёт — `FOR NO KEY UPDATE NOWAIT` проходит. Без близнеца п. 1
// зеленел бы и на пробе, где строку держит что-то другое.
func TestWithoutRevisionTheModuleRowStaysFreeWhileTheApplierWaitsOnTheModuleRow(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует Postgres")
	}
	forNoKeyUpdate, forKeyShare := probeModuleRowWhileApplierWaits(t, false)
	require.NoErrorf(t, forNoKeyUpdate, "без объявленной редакции строка модуля взята до шага 2а (%v)", forNoKeyUpdate)
	require.NoError(t, forKeyShare)
}

// probeModuleRowWhileApplierWaits ставит применителя на строку модуля шага 2а
// (держатель `FOR KEY SHARE` на строке модуля — применитель берёт её
// `FOR UPDATE`) и в этот момент пробует строку модуля двумя режимами с `NOWAIT`.
// Отдаёт исходы обеих попыток; применитель доводится до конца и обязан успеть.
func probeModuleRowWhileApplierWaits(t *testing.T, withRevision bool) (forNoKeyUpdate, forKeyShare error) {
	t.Helper()
	ctx, pool := catalogPool(t)
	applier := applierOver(t, pool)

	var rev1, rev2 int64
	if withRevision {
		rev1, rev2 = 1, 2
	}
	_, err := applier.Apply(ctx, revLockDoc(t, rev1, crossEarlyName, crossLateName))
	require.NoError(t, err)

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
		  SELECT 1 FROM kaname.catalog_module
		   WHERE module = $1 AND live
		     FOR KEY SHARE) s`, applierProbeModule).Scan(&held))
	require.Equalf(t, 1, held, "ПРЕДПОСЫЛКА: живой строки модуля %s нет — держать нечего", applierProbeModule)

	ares := make(chan error, 1)
	go func() {
		_, aerr := applier.Apply(ctx, revLockDoc(t, rev2, crossEarlyName, crossLateName))
		ares <- aerr
	}()
	select {
	case aerr := <-ares:
		t.Fatalf("применитель НЕ встал на строке модуля (%v) — момент «стоит на шаге 2а» не наступил", aerr)
	case <-time.After(2 * time.Second):
	}
	// ПРЕДПОСЫЛКА: применитель стоит именно на замке строки модуля шага 2а, а
	// не где-то ещё — его ожидание называет держатель.
	waitsOnHolder := 0
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*) FROM pg_stat_activity
		 WHERE $1 = ANY (pg_blocking_pids(pid))
		   AND query LIKE '%catalog_module%FOR UPDATE%'`, holderPID(t, ctx, holder)).Scan(&waitsOnHolder))
	require.Equal(t, 1, waitsOnHolder,
		"ПРЕДПОСЫЛКА: применитель стоит не на строке модуля шага 2а за держателем")

	forNoKeyUpdate = tryModuleRow(ctx, pool, "FOR NO KEY UPDATE NOWAIT")
	forKeyShare = tryModuleRow(ctx, pool, "FOR KEY SHARE NOWAIT")

	require.NoError(t, holder.Rollback(ctx))
	holderDone = true
	select {
	case aerr := <-ares:
		require.NoError(t, aerr, "применитель не дошёл до конца после снятия держателя")
	case <-time.After(30 * time.Second):
		t.Fatal("применитель не завершился за 30с после снятия держателя")
	}
	return forNoKeyUpdate, forKeyShare
}

// tryModuleRow — одна попытка взять строку модуля режимом mode в своей
// транзакции, откатываемой сразу.
func tryModuleRow(ctx context.Context, pool *pgxpool.Pool, mode string) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var one int
	return tx.QueryRow(ctx, `SELECT 1 FROM kaname.catalog_module WHERE module = $1 `+mode,
		applierProbeModule).Scan(&one)
}

// holderPID — номер серверного процесса транзакции держателя.
func holderPID(t *testing.T, ctx context.Context, tx pgx.Tx) int {
	t.Helper()
	var pid int
	require.NoError(t, tx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid))
	return pid
}

// isLockNotAvailable — отказ `NOWAIT` на занятой строке (`55P03`).
func isLockNotAvailable(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "55P03"
}
