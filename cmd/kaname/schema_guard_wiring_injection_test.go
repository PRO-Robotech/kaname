// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// schema_guard_wiring_injection_test.go — доказательство, что гейт провязки
// стража прежней схемы СПОСОБЕН упасть и СПОСОБЕН смолчать.
//
// Пара «красное до · зелёное после» снята и на ЖИВОМ дереве: до провязки гейт
// печатал отсутствие вызова, после — смещения обоих. Здесь то же свойство
// закреплено воспроизводимо, на синтетике: доказательство, требующее вынуть
// провязку из рабочей копии, в конвейере не исполняется никогда.
//
// # Инъекция роняет ТОЛЬКО проверяемое
//
// Каждый случай отличается от законного близнеца РОВНО одним фактом: снят
// вызов · переставлены два вызова. Инъекция вида «завести ещё один элемент»
// здесь невозможна by construction — предмет гейта не перечень, а порядок двух
// вызовов.

import "testing"

// ЗАКОННЫЙ БЛИЗНЕЦ всех инъекций ниже: провязка на месте и в верном порядке.
const guardWiredBeforeTheWriter = `package main

func serve() error {
	pool, err := coredb.NewPool(ctx, cfg.DSN())
	if err != nil {
		return err
	}
	if err := assertNoRetiredSchema(ctx, pool); err != nil {
		return err
	}
	if err := assertConnBudgetFits(ctx, pool, budget); err != nil {
		return err
	}
	operations.StartRetentionSweep(ctx, opsRepo, cfg, logger)
	return nil
}
`

// ИНЪЕКЦИЯ 1 — вызов снят. Всё остальное на месте.
const guardNotWiredAtAll = `package main

func serve() error {
	pool, err := coredb.NewPool(ctx, cfg.DSN())
	if err != nil {
		return err
	}
	if err := assertConnBudgetFits(ctx, pool, budget); err != nil {
		return err
	}
	operations.StartRetentionSweep(ctx, opsRepo, cfg, logger)
	return nil
}
`

// ИНЪЕКЦИЯ 2 — вызов есть, но ПОСЛЕ писателя. Отличается от близнеца ровно
// перестановкой: путь старта успевает записать до отказа.
const guardWiredAfterTheWriter = `package main

func serve() error {
	pool, err := coredb.NewPool(ctx, cfg.DSN())
	if err != nil {
		return err
	}
	operations.StartRetentionSweep(ctx, opsRepo, cfg, logger)
	if err := assertNoRetiredSchema(ctx, pool); err != nil {
		return err
	}
	return nil
}
`

func TestSchemaGuardWiringGate_SilentOnAProperlyWiredRoot(t *testing.T) {
	at, calls := callOffsets(t, guardWiredBeforeTheWriter, "synthetic.go", schemaGuardCall, firstBootWriterCall)
	if calls == 0 {
		t.Fatal("обход синтетики пуст — доказательство беспредметно")
	}
	if at[schemaGuardCall] < 0 {
		t.Fatal("гейт не увидел провязанного стража: он не способен смолчать на верном корне, " +
			"то есть краснел бы всегда и был бы снят первым")
	}
	if at[schemaGuardCall] > at[firstBootWriterCall] {
		t.Fatal("гейт объявил верный порядок нарушенным")
	}
}

func TestSchemaGuardWiringGate_RedWhenTheGuardIsNotWired(t *testing.T) {
	at, calls := callOffsets(t, guardNotWiredAtAll, "synthetic.go", schemaGuardCall, firstBootWriterCall)
	if calls == 0 {
		t.Fatal("обход синтетики пуст — доказательство беспредметно")
	}
	if at[schemaGuardCall] >= 0 {
		t.Error("снятая провязка гейтом НЕ замечена: мёртвый страж прошёл бы как живой")
	}
	// Точка отсчёта при этом на месте — значит краснеет именно снятый вызов, а
	// не развалившаяся синтетика.
	if at[firstBootWriterCall] < 0 {
		t.Error("в инъекции пропал и писатель — она роняет больше проверяемого")
	}
}

func TestSchemaGuardWiringGate_RedWhenTheGuardRunsAfterTheWriter(t *testing.T) {
	at, calls := callOffsets(t, guardWiredAfterTheWriter, "synthetic.go", schemaGuardCall, firstBootWriterCall)
	if calls == 0 {
		t.Fatal("обход синтетики пуст — доказательство беспредметно")
	}
	if at[schemaGuardCall] < 0 || at[firstBootWriterCall] < 0 {
		t.Fatal("инъекция перестановки потеряла один из вызовов — она роняет больше проверяемого")
	}
	if at[schemaGuardCall] < at[firstBootWriterCall] {
		t.Error("перестановка гейтом НЕ замечена: страж, отработавший после первой записи, " +
			"прошёл бы за исправную провязку")
	}
}
