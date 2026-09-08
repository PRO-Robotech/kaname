// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// schema_guard_integration_test.go — страж прежней схемы против ЖИВОГО
// Postgres: три состояния базы, три исхода.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ЖИВАЯ БАЗА, А НЕ ТОЛЬКО СОСТАВ ОТКАЗА
//
// Проба состава (`schema_guard_test.go`) зовёт составитель отказа величинами,
// которые подаёт сама, — и о том, УВИДИТ ЛИ страж схему у настоящей базы, не
// утверждает ничего. Между «отказ составлен верно» и «состояние базы прочитано
// верно» лежит запрос: неверный предикат, неверное имя каталога, схема,
// невидимая под этой ролью, — каждое даёт стража, который молчит всегда.
//
// А молчащий страж неотличим от исправного: чистая установка проходит и там, и
// там. Поэтому предмет здесь — ИСХОД на базе, состояние которой заведено
// нарочно.
//
// ─────────────────────────────────────────────────────────────────────────────
// ТРИ СОСТОЯНИЯ ЗАВОДЯТСЯ, А НЕ ОБЪЯВЛЯЮТСЯ
//
//  1. только отставленная схема — пустая база плюс `CREATE SCHEMA kacho_iam`:
//     ровно то, что видит служба, поднятая поверх прежней установки;
//  2. только схема продукта — база, на которой проиграна цепь миграций;
//  3. обе — цепь миграций плюс заведённая рядом отставленная схема.
//
// Соединение во ВСЕХ трёх строится тем же помощником `search_path`, каким его
// строит композиционный корень: несуществующая схема в `search_path` молча
// пропускается, поэтому состояние (1) для драйвера ничем не отличается от
// исправного — и отличить его обязан именно страж.
package main

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/pgtest"

	"github.com/PRO-Robotech/kaname/internal/testsupport/iampgtest"
)

// poolOn открывает пул на названной базе с тем же `search_path`, что у службы.
func poolOn(t *testing.T, dsn string) *pgxpool.Pool {
	t.Helper()
	pool, err := pgxpool.New(context.Background(), iampgtest.AppendIAMSearchPath(dsn))
	require.NoError(t, err)
	// Закрытие С ПРЕДЕЛОМ: проба, упавшая внутри открытой транзакции,
	// соединение не вернёт, и отложенное закрытие унесло бы вердикт пакета.
	pgtest.ClosePoolAtEnd(t, pool)
	return pool
}

// (1) Прежняя установка — старт отвергнут, и отказ называет предмет.
func TestIntegration_SchemaGuard_RefusesAPreviousInstall(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres: проба заводит состояние базы")
	}
	ctx := context.Background()

	// Пустая база — цепь миграций НЕ проиграна, схемы продукта нет.
	pool := poolOn(t, pgtest.NewEmptyDB(t))
	_, err := pool.Exec(ctx, `CREATE SCHEMA `+retiredSchemaName)
	require.NoError(t, err, "не удалось завести состояние прежней установки")

	// Предпосылка мира пробы: схемы продукта тут действительно нет. Без неё
	// «отказ пришёл» было бы неотличимо от отказа по другому поводу.
	var canonical bool
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = $1)`,
		canonicalSchemaName).Scan(&canonical))
	require.Falsef(t, canonical, "предпосылка пробы нарушена: схема %q в пустой базе есть",
		canonicalSchemaName)

	guardErr := assertNoRetiredSchema(ctx, pool)
	require.Errorf(t, guardErr,
		"база несёт схему %q, а служба стартовала: пустая схема %q завелась бы рядом, и "+
			"прежние строки остались бы невидимыми", retiredSchemaName, canonicalSchemaName)
	require.Containsf(t, guardErr.Error(), retiredSchemaName,
		"отказ не назвал обнаруженную схему — оператор не узнает, что именно найдено:\n%v", guardErr)
	require.Contains(t, guardErr.Error(), installDocPath,
		"отказ не отослал к порядку установки")

	t.Logf("перепись: схем в базе — отставленная есть, продуктовой нет; страж отверг старт")
}

// (2) ЗАКОННЫЙ БЛИЗНЕЦ — чистая установка. Без него отрицание выше зеленело бы
// на страже, отвергающем любую базу.
func TestIntegration_SchemaGuard_LetsACleanInstallStart(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres: проба поднимает схему цепью миграций")
	}
	ctx := context.Background()

	// Цепь миграций проиграна — схема продукта есть, отставленной нет.
	pool := poolOn(t, pgtest.NewDB(t))

	var retired bool
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = $1)`,
		retiredSchemaName).Scan(&retired))
	require.Falsef(t, retired, "предпосылка пробы нарушена: цепь миграций завела схему %q",
		retiredSchemaName)

	require.NoError(t, assertNoRetiredSchema(ctx, pool),
		"страж отверг чистую установку — он ломает штатный старт, а не защищает данные")

	t.Logf("перепись: схема продукта поднята цепью, отставленной нет; страж пропустил старт")
}

// (3) Обе схемы рядом — отказ, и он называет ОБЕ.
func TestIntegration_SchemaGuard_RefusesBothSchemasSideBySide(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres: проба заводит состояние базы")
	}
	ctx := context.Background()

	pool := poolOn(t, pgtest.NewDB(t))
	_, err := pool.Exec(ctx, `CREATE SCHEMA `+retiredSchemaName)
	require.NoError(t, err, "не удалось завести состояние «обе схемы рядом»")

	guardErr := assertNoRetiredSchema(ctx, pool)
	require.Error(t, guardErr,
		"обе схемы рядом, а служба стартовала: какую из них она читает, решил бы порядок "+
			"search_path — данные выбирались бы молча")
	// installDocPath стоит в перечне НАМЕРЕННО, и это не украшение: отказ
	// fail-closed («спросить не удалось») тоже называет обе схемы, поэтому без
	// координаты, которой у него НЕТ, эта проба зеленела бы на сломанном
	// запросе — то есть на страже, который базу не читает вовсе. Проверено
	// инъекцией: с испорченным запросом соседние пробы краснеют, а эта без
	// данного пункта — нет.
	for _, want := range []string{retiredSchemaName, canonicalSchemaName, installDocPath} {
		require.Containsf(t, guardErr.Error(), want,
			"отказ на две схемы рядом не назвал %q:\n%v", want, guardErr)
	}

	t.Logf("перепись: обе схемы в базе; страж отверг старт и назвал обе")
}

// Страж FAIL-CLOSED: не сумев прочитать состояние, он отказывает, а не
// пропускает. «Не прочитано» не есть «нет» — иначе первая же сетевая заминка
// открывала бы ровно тот путь, который страж закрывает.
func TestIntegration_SchemaGuard_FailsClosedWhenItCannotAsk(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres: проба закрывает пул на живой базе")
	}
	ctx := context.Background()

	pool := poolOn(t, pgtest.NewDB(t))
	pool.Close() // спросить больше нечем — ровно то состояние, о котором речь

	err := assertNoRetiredSchema(ctx, pool)
	require.Error(t, err,
		"страж не смог спросить базу и разрешил старт: «не прочитано» стало бы означать «нет»")
	require.True(t, strings.Contains(err.Error(), "не прочитано") ||
		strings.Contains(err.Error(), "не прочитан"),
		"отказ по неответившей базе не отличим от отказа по найденной схеме:\n%v", err)
}
