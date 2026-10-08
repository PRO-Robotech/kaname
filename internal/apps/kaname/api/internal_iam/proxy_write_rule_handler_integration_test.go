// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// proxy_write_rule_handler_integration_test.go — правило проксируемой записи на
// обработчике: снятие объекта и набор кортежей события судятся владением ТИПОМ
// объекта и отношением каждого кортежа, и отказ не пишет ничего.
//
// # Что судится
//
// Две проверки обработчика `InternalIAMService`, у каждой своя проба:
//
//   - `UnregisterResource` — право снять объект есть право поставить на нём
//     иерархический кортеж (validateObjectWithdrawal). Модуль с дверью
//     `fga_writer`, снимающий объект ЧУЖОГО типа, унёс бы все его кортежи,
//     строку зеркала и публикацию и оставил бы надгробие с высоким поколением,
//     отвергающее повторную регистрацию владельцем;
//   - `RegisterResource` — правило применяется к КАЖДОМУ кортежу набора
//     события: набор, в котором один кортеж правилу не подчиняется, отвергается
//     целиком, а не применяется без него.
//
// Отказ — `PERMISSION_DENIED` с фиксированным текстом `permission denied` и без
// записи: состояние схемы `kaname` (каждая её таблица, отпечатком содержимого)
// после отказа то же, что до него.
//
// # Близнецы
//
// У каждого отказа близнец по одному факту: тот же вызов от модуля, которому тип
// принадлежит (снятие, регистрация), либо тот же набор без отвергаемого кортежа
// (набор события) — применён. Без близнеца отказ зеленел бы на обработчике,
// отвергающем всё.
//
// Пропускается под `go test -short`.
package internal_iam_test

import (
	"context"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// schemaState — отпечаток содержимого каждой таблицы схемы `kaname`: имя таблицы
// → md5 её строк в каноническом порядке. Отказ, не записавший ничего, оставляет
// его неизменным; запись в ЛЮБУЮ таблицу — голову, кортежи, журналы, зеркало,
// публикацию — его меняет.
func (e *eventHarness) schemaState(t *testing.T) map[string]string {
	t.Helper()
	ctx := context.Background()
	rows, err := e.pool.Query(ctx,
		`SELECT table_name FROM information_schema.tables
		  WHERE table_schema = 'kaname' AND table_type = 'BASE TABLE' ORDER BY table_name`)
	require.NoError(t, err)
	var tables []string
	for rows.Next() {
		var name string
		require.NoError(t, rows.Scan(&name))
		tables = append(tables, name)
	}
	require.NoError(t, rows.Err())
	rows.Close()
	// Предпосылка: обход видит таблицы, которые судит проба. Пустой обход дал бы
	// равные пустые отпечатки на любом исходе.
	require.Contains(t, tables, "object_head", "обход схемы kaname не видит головы объекта")
	require.Contains(t, tables, "relation_fact", "обход схемы kaname не видит кортежей")
	require.Contains(t, tables, "resource_mirror", "обход схемы kaname не видит зеркала")

	out := make(map[string]string, len(tables))
	for _, name := range tables {
		var sum string
		require.NoError(t, e.pool.QueryRow(ctx,
			`SELECT md5(coalesce(string_agg(r::text, E'\n' ORDER BY r::text), '')) FROM kaname.`+name+` r`).Scan(&sum),
			"отпечаток таблицы kaname.%s", name)
		out[name] = sum
	}
	return out
}

// requireUnchanged — отказ не записал ничего: отпечаток каждой таблицы прежний.
func (e *eventHarness) requireUnchanged(t *testing.T, before map[string]string, why string) {
	t.Helper()
	after := e.schemaState(t)
	var changed []string
	for name, sum := range before {
		if after[name] != sum {
			changed = append(changed, name)
		}
	}
	sort.Strings(changed)
	require.Empty(t, changed, "%s: отказ записал в таблицы схемы kaname", why)
	require.Len(t, after, len(before), "%s: число таблиц схемы kaname изменилось", why)
}

// requireProxyRefusal — отказ правила проксируемой записи, как его наблюдает
// вызывающий: код и фиксированный текст без причины.
func requireProxyRefusal(t *testing.T, err error, why string) {
	t.Helper()
	require.Error(t, err, "%s: вызов принят", why)
	require.Equal(t, codes.PermissionDenied, status.Code(err), "%s: %v", why, err)
	require.Equal(t, "permission denied", status.Convert(err).Message(), "%s: текст отказа", why)
}

// TestUnregisterResource_ObjectOfAnotherModuleTypeIsRefusedAndWritesNothing —
// объект `registry_repository` зарегистрирован модулем registry и опубликован;
// снятие от модуля storage: PERMISSION_DENIED, голова, кортежи, зеркало,
// публикация и журналы не изменены. Близнец по одному факту — то же снятие от
// модуля registry: надгробие поколения 2, кортежей и зеркала нет.
func TestUnregisterResource_ObjectOfAnotherModuleTypeIsRefusedAndWritesNothing(t *testing.T) {
	if testing.Short() {
		t.Skip("integration (Postgres)")
	}
	e := newEventHarness(t)
	const name = "pub"

	require.NoError(t, e.register(t, evReg(t, name, []evTuple{evParent, evOwner}, 1)))
	require.NoError(t, e.publish(t, pubReq(t, repo(name), true, pubT1, 1)))
	e.requirePublished(t, name, true, pubT1, "положительный контроль: объект опубликован до снятия")
	require.Len(t, e.facts(t, name), 3, "положительный контроль: два кортежа события и кортеж публикации")
	require.True(t, e.mirrorPresent(t, name), "положительный контроль: строка зеркала до снятия")
	before := e.schemaState(t)

	e.gate.domain = "storage"
	requireProxyRefusal(t, e.unregister(t, evUnreg(name, 1<<40)), "снятие объекта чужого типа")
	e.requireUnchanged(t, before, "снятие объекта чужого типа")
	e.requireHead(t, name, 1, false, "снятие объекта чужого типа")

	e.gate.domain = "registry"
	require.NoError(t, e.unregister(t, evUnreg(name, 2)), "близнец: снятие модулем-владельцем типа")
	e.requireHead(t, name, 2, true, "близнец: надгробие снятия владельцем")
	require.Empty(t, factKeys(e.facts(t, name)), "близнец: снятие уносит все кортежи объекта")
	require.False(t, e.mirrorPresent(t, name), "близнец: живой строки зеркала нет")
	e.requireNoPublication(t, name, "близнец: снятие уносит публикацию")
}

// TestRegisterResource_ObjectOfAnotherModuleTypeIsRefusedAndWritesNothing —
// объект `registry_repository` зарегистрирован модулем registry поколением 1;
// регистрация поколения 2 от модуля storage: PERMISSION_DENIED, ничего не
// записано. Близнец по одному факту — та же регистрация от модуля registry:
// голова 2.
func TestRegisterResource_ObjectOfAnotherModuleTypeIsRefusedAndWritesNothing(t *testing.T) {
	if testing.Short() {
		t.Skip("integration (Postgres)")
	}
	e := newEventHarness(t)
	const name = "pub"

	require.NoError(t, e.register(t, evReg(t, name, []evTuple{evParent}, 1)))
	before := e.schemaState(t)

	e.gate.domain = "storage"
	requireProxyRefusal(t, e.register(t, evReg(t, name, []evTuple{evParent, evOwner}, 2)),
		"регистрация объекта чужого типа")
	e.requireUnchanged(t, before, "регистрация объекта чужого типа")
	e.requireHead(t, name, 1, false, "регистрация объекта чужого типа")

	e.gate.domain = "registry"
	require.NoError(t, e.register(t, evReg(t, name, []evTuple{evParent, evOwner}, 2)),
		"близнец: регистрация модулем-владельцем типа")
	e.requireHead(t, name, 2, false, "близнец: регистрация владельцем")
	require.Equal(t, []string{keyOf(evParent), keyOf(evOwner)}, factKeys(e.facts(t, name)),
		"близнец: набор события применён")
}

// TestRegisterResource_SetWithOneRefusedTupleIsRefusedAsAWhole — набор события
// поколения 2 от модуля-владельца типа, в котором законные кортежи соседствуют с
// одним кортежем отношения, которое правило проксируемой записи не пропускает
// (не иерархическое и не пара публикации): PERMISSION_DENIED, ничего не записано
// — ни законные кортежи набора, ни голова. Отвергаемый кортеж стоит в наборе
// ПОСЛЕДНИМ: правило, применённое к одному первому кортежу, его не увидело бы.
// Близнец по одному факту — тот же набор без отвергаемого кортежа: применён.
func TestRegisterResource_SetWithOneRefusedTupleIsRefusedAsAWhole(t *testing.T) {
	if testing.Short() {
		t.Skip("integration (Postgres)")
	}
	e := newEventHarness(t)
	const name = "pub"

	require.NoError(t, e.register(t, evReg(t, name, []evTuple{evParent}, 1)))
	before := e.schemaState(t)

	for _, rel := range []string{"system_admin", "editor", "v_get"} {
		t.Run(rel, func(t *testing.T) {
			set := []evTuple{evParent, evOwner, {"user:usr-Y", rel}}
			requireProxyRefusal(t, e.register(t, evReg(t, name, set, 2)), "набор с кортежем #"+rel)
			e.requireUnchanged(t, before, "набор с кортежем #"+rel)
			e.requireHead(t, name, 1, false, "набор с кортежем #"+rel)
		})
	}

	require.NoError(t, e.register(t, evReg(t, name, []evTuple{evParent, evOwner}, 2)),
		"близнец: тот же набор без отвергаемого кортежа")
	e.requireHead(t, name, 2, false, "близнец: набор без отвергаемого кортежа")
	require.Equal(t, []string{keyOf(evParent), keyOf(evOwner)}, factKeys(e.facts(t, name)),
		"близнец: законные кортежи набора применены")
}
