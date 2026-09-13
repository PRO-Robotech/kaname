// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package subscriptionjournal

// narrow_test.go — сценарии GWT-6а и GWT-6б APPROVED-приёмки.
//
// Предмет — РАЗВИЛКА клиента: живой предмет спрашивается как у списков, снятый —
// и сам, и по каждой захваченной области. Обе половины утверждаются в одном
// прогоне: проба, знающая только первую, зеленела бы на клиенте, который не
// спрашивает области вовсе, а знающая только вторую — на клиенте, который
// спрашивает их ВСЕГДА, то есть расширяет доступ к живому.

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/listnarrow"
)

// doorStub — дверь решения, отвечающая по объявленному множеству разрешённых.
//
// Она НЕ снисходительнее настоящей в том, что решает: неизвестный объект — отказ,
// а не пропуск. Что она не воспроизводит, названо здесь прямо: условный контекст,
// срок вызова и стоимость страницы. Ни одно из трёх предметом этих проб не
// является.
type doorStub struct {
	allow map[string]bool // "<subject>|<relation>|<type>:<id>" → да
	asked []string
	fail  error
}

func (d *doorStub) BatchCheckWithContext(
	_ context.Context, subject, relation string, objects []string, _ map[string]any,
) ([]bool, error) {
	if d.fail != nil {
		return nil, d.fail
	}
	out := make([]bool, len(objects))
	for i, obj := range objects {
		k := subject + "|" + relation + "|" + obj
		d.asked = append(d.asked, k)
		out[i] = d.allow[k]
	}
	return out, nil
}

// removalsStub — журнал: предмет присутствует в карте тогда и только тогда,
// когда его строка журнала есть снятие.
type removalsStub struct {
	byKind map[string]map[string][]Scope
	asked  int
}

func (r *removalsStub) CapturedScopes(
	_ context.Context, kind string, _ []string,
) (map[string][]Scope, error) {
	r.asked++
	return r.byKind[kind], nil
}

func checkOf(subject, objectType, id string) listnarrow.Check {
	return listnarrow.Check{
		Subject: subject, ResourceType: objectType, ResourceID: id,
		Action: "iam.groups.list", RequiredRelation: "v_get",
	}
}

// TestRemovedSubjectIsJudgedByItsCapturedScope — GWT-6а.
func TestRemovedSubjectIsJudgedByItsCapturedScope(t *testing.T) {
	door := &doorStub{allow: map[string]bool{
		// Предмет не виден: звено вместимости ушло вместе со строкой.
		// Аккаунт виден — по предикату чтения аккаунта.
		"user:reader|v_get|account:acc-1": true,
	}}
	removals := &removalsStub{byKind: map[string]map[string][]Scope{
		"iam_group": {"grp-gone": {{Type: "account", ID: "acc-1"}}},
	}}

	got, err := NewNarrowClient(door, removals).BatchCheck(context.Background(),
		[]listnarrow.Check{checkOf("user:reader", "iam_group", "grp-gone")})
	require.NoError(t, err)
	assert.Equal(t, []bool{true}, got,
		"снятый предмет судится по захваченной области: иначе подписчик, "+
			"снявший опрос, держал бы снятую строку вечно, и держал бы молча")

	// ОТРИЦАТЕЛЬНЫЙ БЛИЗНЕЦ: кому не виден ни предмет, ни аккаунт — «нет».
	got, err = NewNarrowClient(door, removals).BatchCheck(context.Background(),
		[]listnarrow.Check{checkOf("user:stranger", "iam_group", "grp-gone")})
	require.NoError(t, err)
	assert.Equal(t, []bool{false}, got,
		"без этой половины проба зеленела бы на клиенте, отвечающем «да» всем")
}

// TestEveryCapturedScopeIsAsked — область есть НАБОР: годится любая из них.
func TestEveryCapturedScopeIsAsked(t *testing.T) {
	door := &doorStub{allow: map[string]bool{
		// Виден только ВТОРОЙ аккаунт человека.
		"user:reader|v_get|account:acc-2": true,
	}}
	removals := &removalsStub{byKind: map[string]map[string][]Scope{
		"iam_user": {"usr-gone": {
			{Type: "account", ID: "acc-1"},
			{Type: "account", ID: "acc-2"},
		}},
	}}

	got, err := NewNarrowClient(door, removals).BatchCheck(context.Background(),
		[]listnarrow.Check{checkOf("user:reader", "iam_user", "usr-gone")})
	require.NoError(t, err)
	assert.Equal(t, []bool{true}, got,
		"захват одной принадлежности из N оставил бы держателей выдач на "+
			"остальные аккаунты без события снятия")
}

// TestLiveSubjectNeverReachesTheScopeBranch — GWT-6б, первая половина.
//
// Это проба того, что §3.3 НЕ расширил доступ к живым предметам.
func TestLiveSubjectNeverReachesTheScopeBranch(t *testing.T) {
	door := &doorStub{allow: map[string]bool{
		// Аккаунт виден, предмет — нет. Предмет ЖИВ: снятия по нему в журнале нет.
		"user:reader|v_get|account:acc-1": true,
	}}
	removals := &removalsStub{byKind: map[string]map[string][]Scope{
		"iam_group": {}, // живому предмету область не захватывалась
	}}

	got, err := NewNarrowClient(door, removals).BatchCheck(context.Background(),
		[]listnarrow.Check{checkOf("user:reader", "iam_group", "grp-alive")})
	require.NoError(t, err)
	assert.Equal(t, []bool{false}, got,
		"живой предмет, который вызывающему не виден, остаётся невидимым: "+
			"иначе всякий, кому виден аккаунт, получил бы каждый предмет в нём")

	for _, asked := range door.asked {
		assert.NotContains(t, asked, "account:acc-1",
			"про область живого предмета дверь спрашиваться НЕ должна вовсе")
	}
}

// TestVerdictsKeepRequestOrderAndLength — контракт порта.
func TestVerdictsKeepRequestOrderAndLength(t *testing.T) {
	door := &doorStub{allow: map[string]bool{
		"user:reader|v_get|iam_group:b": true,
	}}
	checks := []listnarrow.Check{
		checkOf("user:reader", "iam_group", "a"),
		checkOf("user:reader", "iam_group", "b"),
		checkOf("user:reader", "iam_group", "c"),
	}

	got, err := NewNarrowClient(door, &removalsStub{}).BatchCheck(context.Background(), checks)
	require.NoError(t, err)
	assert.Equal(t, []bool{false, true, false}, got,
		"вердикт пишется в СВОЙ индекс: переставленный отфильтровал бы поток "+
			"чужим ответом, и заметить это вызывающий не может")
}

// TestDoorFailureAbortsTheBatch — «не смог спросить» не есть «доступа нет».
func TestDoorFailureAbortsTheBatch(t *testing.T) {
	boom := errors.New("дверь недоступна")
	door := &doorStub{fail: boom}

	_, err := NewNarrowClient(door, &removalsStub{}).BatchCheck(context.Background(),
		[]listnarrow.Check{checkOf("user:reader", "iam_group", "a")})
	assert.ErrorIs(t, err, boom,
		"отказ двери обязан прекратить партию: представление его отказом сделало бы "+
			"недоступность базы неотличимой от законного «нет»")
}

// TestUnnamedCallerIsRefusedUnconditionally — безымянный вызывающий отсекается
// БЕЗУСЛОВНО: за этим методом нет пообъектной проверки на крае.
func TestUnnamedCallerIsRefusedUnconditionally(t *testing.T) {
	door := &doorStub{allow: map[string]bool{"|v_get|iam_group:a": true}}
	removals := &removalsStub{byKind: map[string]map[string][]Scope{
		"iam_group": {"a": {{Type: "account", ID: "acc-1"}}},
	}}

	got, err := NewNarrowClient(door, removals).BatchCheck(context.Background(),
		[]listnarrow.Check{checkOf("", "iam_group", "a")})
	require.NoError(t, err)
	assert.Equal(t, []bool{false}, got)
	assert.Empty(t, door.asked, "про безымянного дверь не спрашивается вовсе")
}

// TestClientSatisfiesTheFoundationPort — точка расширения, ради которой клиент и
// существует: сужатель строится ИЗ НЕГО, оставаясь штатным типом фундамента.
func TestClientSatisfiesTheFoundationPort(t *testing.T) {
	n := listnarrow.New(NewNarrowClient(&doorStub{}, &removalsStub{}), listnarrow.Config{
		Relations: map[string][]string{"": {"v_get"}},
	})
	require.NotNil(t, n)
	assert.True(t, n.Narrows(),
		"сужатель обязан СУЖАТЬ: за глаголом подписки нет пообъектной проверки "+
			"на крае, и откатываться не на что")
}
