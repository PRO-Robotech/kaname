// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package reconcile

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	"github.com/PRO-Robotech/kacho-iam/internal/testsupport/catalogfixture"
)

// sizeSpy — двойник приёмника размера материализации.
type sizeSpy struct {
	calls   int
	objects []int
	tuples  []int
}

func (s *sizeSpy) ObserveBindingMaterialization(objects, tuples int) {
	s.calls++
	s.objects = append(s.objects, objects)
	s.tuples = append(s.tuples, tuples)
}

// sizeFixture собирает выдачу, чьё правило отбирает n объектов по метке.
func sizeFixture(n int, verbs ...string) *fakeStore {
	if len(verbs) == 0 {
		verbs = []string{"get"}
	}
	fp := domain.Rule{
		Module: "compute", Resources: []string{"instance"}, Verbs: verbs,
		MatchLabels: map[string]string{"env": "prod"},
	}.Fingerprint()
	objs := make([]domain.MirrorObject, 0, n+1)
	for i := 0; i < n; i++ {
		objs = append(objs, domain.MirrorObject{
			ObjectType: "compute.instance", ObjectID: fmt.Sprintf("i-%03d", i),
			ParentProjectID: "prj-1", Labels: map[string]string{"env": "prod"},
		})
	}
	// Объект, который правило НЕ отбирает: без него проба не отличала бы «счёт
	// отобранных» от «счёт всех, что лежат в зеркале».
	objs = append(objs, domain.MirrorObject{
		ObjectType: "compute.instance", ObjectID: "i-not-selected",
		ParentProjectID: "prj-1", Labels: map[string]string{"env": "staging"},
	})
	return &fakeStore{
		scope:       domain.ScopeAnchor{Type: "project", ID: "prj-1"},
		subjectType: "user", subjectID: "usr-1", active: true,
		selectors: []domain.RuleSelector{{
			Arm: domain.ArmLabels, RuleFP: fp,
			ObjectTypes: []string{"compute.instance"},
			MatchLabels: map[string]string{"env": "prod"},
			Verbs:       verbs,
		}},
		mirror: map[string][]domain.MirrorObject{"compute.instance": objs},
	}
}

// Размер материализации растёт вместе с числом ОТОБРАННЫХ объектов.
//
// Проба нагружена намеренно: прибор, который заводят «чтобы было», обычно и
// проверяют утверждением «его позвали» — а такое утверждение остаётся зелёным на
// приборе, всегда докладывающем ноль, то есть ровно на том состоянии, ради
// исключения которого прибор и нужен. Поэтому здесь сравниваются ТРИ разные
// нагрузки, и каждая обязана дать своё число.
//
// В зеркале рядом лежит объект, которого правило не отбирает: без него проба не
// отличала бы «отобранных» от «сколько всего лежит в зеркале».
func TestBindingMaterializationSizeGrowsWithMatchedObjects(t *testing.T) {
	t.Parallel()

	for _, n := range []int{1, 3, 12} {
		spy := &sizeSpy{}
		f := sizeFixture(n)
		rec := New(fakeRunner{s: f}, nil, catalogfixture.Source()).WithSizeRecorder(spy)
		require.NoError(t, rec.ReconcileBinding(context.Background(), "acb-1"))

		require.Equal(t, 1, spy.calls, "один проход выдачи — одно наблюдение")
		assert.Equalf(t, n, spy.objects[0],
			"отобранных объектов доложено %d при %d подошедших (и одном неподошедшем рядом)",
			spy.objects[0], n)
		assert.Positivef(t, spy.tuples[0], "при %d отобранных объектах кортежей доложено 0 — "+
			"прибор докладывает ноль там, где материализация есть", n)
		assert.GreaterOrEqualf(t, spy.tuples[0], n,
			"кортежей (%d) меньше, чем объектов (%d): каждый отобранный объект несёт "+
				"хотя бы один кортеж", spy.tuples[0], n)
	}
}

// Число кортежей растёт с числом ГЛАГОЛОВ правила при неизменном числе объектов.
//
// Это вторая ось стоимости выдачи и та, которую легче упустить: объектов столько
// же, а материализуется больше. Проба фиксирует, что величина зависит именно от
// набора кортежей, а не подменена числом объектов.
func TestBindingMaterializationTuplesGrowWithVerbs(t *testing.T) {
	t.Parallel()

	const objects = 4

	narrow := &sizeSpy{}
	fNarrow := sizeFixture(objects, "get")
	require.NoError(t, New(fakeRunner{s: fNarrow}, nil, catalogfixture.Source()).WithSizeRecorder(narrow).
		ReconcileBinding(context.Background(), "acb-1"))

	wide := &sizeSpy{}
	fWide := sizeFixture(objects, "get", "list", "update", "delete")
	require.NoError(t, New(fakeRunner{s: fWide}, nil, catalogfixture.Source()).WithSizeRecorder(wide).
		ReconcileBinding(context.Background(), "acb-1"))

	assert.Equal(t, objects, narrow.objects[0])
	assert.Equal(t, objects, wide.objects[0], "объектов столько же")
	assert.Greater(t, wide.tuples[0], narrow.tuples[0],
		"более широкое правило материализует больше кортежей на том же числе объектов "+
			"(%d против %d) — если величины равны, докладывается не набор кортежей",
		wide.tuples[0], narrow.tuples[0])
}

// Проход, не отобравший ничего, докладывается НУЛЁМ, а не пропускается.
//
// Отрицание здесь стоит в паре с положительными выше: пропуск сделал бы
// «селектор перестал отбирать» неотличимым от «выдачу никто не пересчитывает» —
// то самое неразличение, ради снятия которого величина и меряется.
func TestBindingMaterializationEmptyPassIsReportedAsZero(t *testing.T) {
	t.Parallel()

	spy := &sizeSpy{}
	f := sizeFixture(0)
	require.NoError(t, New(fakeRunner{s: f}, nil, catalogfixture.Source()).WithSizeRecorder(spy).
		ReconcileBinding(context.Background(), "acb-1"))

	require.Equal(t, 1, spy.calls, "пустой проход тоже наблюдается")
	assert.Zero(t, spy.objects[0])
	assert.Zero(t, spy.tuples[0])
}

// Непровязанный приёмник не меняет проход: величина — измерение, не решение.
func TestBindingMaterializationRecorderIsOptional(t *testing.T) {
	t.Parallel()

	f := sizeFixture(2)
	require.NoError(t, New(fakeRunner{s: f}, nil, catalogfixture.Source()).ReconcileBinding(context.Background(), "acb-1"))
	require.Len(t, f.upserts, 2, "проход без приёмника материализует то же самое")
}

// Размер материализации меряется и на СОЗДАНИИ выдачи — том самом моменте, ради
// которого величина заводилась.
//
// Почему это отдельная проба, а не повтор верхней. Создание привязки идёт НЕ полным
// проходом: аддитивный форвард — это и есть штатный путь выдачи (у новой привязки
// материализованных членов нет), а полный проход остаётся за правкой роли и
// периодическим сведением. Обе ветки считают ОДНУ И ТУ ЖЕ желаемую выборку тем же
// `desiredMembers`, поэтому величина на создании доступна ровно так же — разница
// только в том, докладывается ли она.
//
// Без этой пробы прибор оставался бы зелёным по всем своим утверждениям и при этом
// молчал на самой частой выдаче: показания приходили бы только с правки роли и
// сведения, то есть распределение описывало бы не то, что администратор выдаёт, а то,
// что позже пересчитал фон. «Величина не растёт» стало бы неотличимо от «этой выдачи
// прибор не видел».
//
// Проба нагружена: три разные нагрузки обязаны дать три разных числа. Утверждение
// «приёмник позван» осталось бы зелёным на приборе, всегда докладывающем ноль.
func TestBindingMaterializationSizeObservedOnCreateForwardPath(t *testing.T) {
	t.Parallel()

	for _, n := range []int{1, 3, 12} {
		spy := &sizeSpy{}
		f := sizeFixture(n) // current: nil — новая привязка, горячий путь создания
		rec := New(fakeRunner{s: f}, nil, catalogfixture.Source()).WithSizeRecorder(spy)
		require.NoError(t, rec.ReconcileBindingForward(context.Background(), "acb-new"))

		require.Equalf(t, 1, spy.calls,
			"создание выдачи (аддитивный форвард) при %d подошедших объектах доложено "+
				"%d раз — путь, которым выдаётся право, прибором не виден", n, spy.calls)
		assert.Equalf(t, n, spy.objects[0],
			"отобранных объектов доложено %d при %d подошедших (и одном неподошедшем рядом)",
			spy.objects[0], n)
		assert.GreaterOrEqualf(t, spy.tuples[0], n,
			"кортежей (%d) меньше, чем объектов (%d): каждый отобранный объект несёт "+
				"хотя бы один кортеж", spy.tuples[0], n)
	}
}

// Делегирование форварда полному проходу даёт РОВНО ОДНО наблюдение, а не два.
//
// Отрицание в паре с положительными выше. Форвард, увидев у привязки уже
// материализованных членов, передаёт проход полному пути — и если бы величину
// докладывали обе ветки, одна выдача попадала бы в распределение дважды. Гистограмма
// от этого не «слегка шумит»: удваивается вес именно тех привязок, которые
// пересчитываются чаще прочих, то есть перекос ложится на хвост — на ту самую часть
// распределения, ради которой величина и меряется.
func TestBindingMaterializationObservedOnceWhenForwardDelegatesToFull(t *testing.T) {
	t.Parallel()

	fp := domain.Rule{
		Module: "compute", Resources: []string{"instance"}, Verbs: []string{"get"},
		MatchLabels: map[string]string{"env": "prod"},
	}.Fingerprint()
	f := sizeFixture(2)
	// У привязки уже есть материализованный член ⇒ форвард обязан передать проход
	// полному пути (он один умеет снимать отпавшее).
	f.current = []domain.TargetMember{{
		BindingID: "acb-1", RuleFP: fp,
		ObjectType: "compute.instance", ObjectID: "i-000",
		VerificationStatus: domain.VerificationActive,
	}}

	spy := &sizeSpy{}
	rec := New(fakeRunner{s: f}, nil, catalogfixture.Source()).WithSizeRecorder(spy)
	require.NoError(t, rec.ReconcileBindingForward(context.Background(), "acb-1"))

	require.Equalf(t, 1, spy.calls,
		"одна выдача — одно наблюдение; доложено %d (обе ветки докладывают одну и ту же "+
			"выборку ⇒ хвост распределения удваивается)", spy.calls)
	assert.Equal(t, 2, spy.objects[0], "доложена желаемая выборка, а не изменённые строки")
}
