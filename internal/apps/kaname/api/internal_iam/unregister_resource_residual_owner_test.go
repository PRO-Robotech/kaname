// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_iam

// unregister_resource_residual_owner_test.go — снятие проверяется ИСХОДОМ: после отзыва
// доступа не должно БЫТЬ. Не «событие эмитировано», не «метод вызван», не «строка
// отправлена» — именно «форма отвечает DENY».
//
// Почему проба именно такой формы. Регистрация ресурса пишет ТРИ вида отношения, а не
// два: указатель объекта на его проект, per-object глаголы (их выводит реконсайлер из
// выдач) и — у тех потребителей, кто это делает — прямой `owner` создателя. Снятие
// называло только первый. Второй снимает реконсайлер. Третий не снимал НИКТО.
//
// Дефект невидим для любого утверждения вида «вызвали»: намерение эмитируется,
// доезжает, помечается отправленным, ошибок ноль. Замер на стенде (2026-08-04): из
// 180 снятых регистраций реестра `owner` пережил снятие в 180 случаях из 180, и на
// удалённом объекте `v_delete` отвечал allowed. Поэтому проба ниже держит СОСТОЯНИЕ
// прямых фактов и спрашивает его так же, как спросил бы enforcement, а не считает вызовы.
//
// ЧТО ИЗМЕНИЛОСЬ СО СНЯТИЕМ ВНЕШНЕГО ДВИЖКА — и почему проба от этого только точнее.
//
// Прежде дублёр играл ЧУЖОЕ хранилище, в которое отдельный применитель складывал
// кортежи после коммита. Применителя больше нет, и ускорять нечего: намерение,
// положенное строкой журнала (`kaname.fga_outbox`) в ту же транзакцию, порождает
// прямой факт (`kaname.relation_fact`) ТРИГГЕРОМ — в обе стороны, в момент коммита.
// Поэтому дублёр ниже моделирует именно это: журнал копит намерения на транзакции, а
// прямые факты меняются при `Commit`. Ни одного звена, которого нет у настоящего.
//
// Форма выводит все пять глаголов из `owner`, поэтому уцелевший `owner` — это не
// мусорная строка, а действующий полный доступ.

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/service"
)

// factStore — ПРЯМЫЕ ФАКТЫ, а не журнал вызовов. Он отвечает на вопрос «есть ли сейчас
// доступ», и именно этим отличает применённое снятие от эмитированного.
type factStore struct {
	mu sync.Mutex
	// facts — текущее содержимое таблицы прямых фактов.
	facts []service.RelationTuple
	// additive — инъекция дефекта: намерение снятия принимается и НИЧЕГО не убирает.
	// Ровно то поведение, на котором зеленеют утверждения «эмитировали».
	additive bool
	readErr  error
}

// applyWrite / applyDelete — то, что делает триггер в момент коммита.
func (s *factStore) applyWrite(tuples []service.RelationTuple) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, want := range tuples {
		if !s.hasLocked(want) {
			s.facts = append(s.facts, want)
		}
	}
}

func (s *factStore) applyDelete(tuples []service.RelationTuple) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.additive {
		// Инъекция: намерение принято, исход не наступил.
		return
	}
	for _, drop := range tuples {
		kept := s.facts[:0]
		for _, have := range s.facts {
			if have != drop {
				kept = append(kept, have)
			}
		}
		s.facts = kept
	}
}

// ObjectTuplesTx — что СЕЙЧАС стоит на объекте (порт читателя снимаемого).
func (s *factStore) ObjectTuplesTx(_ context.Context, _ service.Tx, object string) ([]service.RelationTuple, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.readErr != nil {
		return nil, s.readErr
	}
	var out []service.RelationTuple
	for _, t := range s.facts {
		if t.Object == object {
			out = append(out, t)
		}
	}
	return out, nil
}

func (s *factStore) hasLocked(want service.RelationTuple) bool {
	for _, have := range s.facts {
		if have == want {
			return true
		}
	}
	return false
}

// resolveVerb — минимальный резолвер правила формы «глагол выводится из owner».
// Отвечает на тот же вопрос, что enforcement: есть ли у субъекта глагол на объекте.
func (s *factStore) resolveVerb(subject, verb, object string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, t := range s.facts {
		if t.Object != object || t.User != subject {
			continue
		}
		// Прямой глагол ИЛИ вывод из owner — обе ветви правила формы.
		if t.Relation == verb || t.Relation == "owner" {
			return true
		}
	}
	return false
}

// factTx — транзакция, копящая намерения журнала и применяющая их ТРИГГЕРОМ на коммите.
// Откат не применяет ничего: несостоявшаяся транзакция не порождает фактов.
type factTx struct {
	store     *factStore
	committed bool
	writes    []service.RelationTuple
	deletes   []service.RelationTuple
}

func (t *factTx) Commit(context.Context) error {
	t.committed = true
	t.store.applyWrite(t.writes)
	t.store.applyDelete(t.deletes)
	return nil
}

func (t *factTx) Rollback(context.Context) error { return nil }

type factTxBeginner struct {
	store *factStore
	tx    *factTx
}

func (b *factTxBeginner) Begin(context.Context) (service.Tx, error) {
	b.tx = &factTx{store: b.store}
	return b.tx, nil
}

// ApplyTx — порт публикации в этом дублёре: публикация ложится строкой журнала в
// транзакцию и меняет факты на ФИКСАЦИИ, как триггер проекции в базе. Порядок версий
// и воплощение дублёр не судит (их держат пробы с базой): предмет проб этого файла —
// что снятие объекта ДОВОДИТ публикацию, а не в каком порядке пришли доставки.
func (s *factStore) ApplyTx(_ context.Context, tx service.Tx, in service.PublicReadIntent) (bool, error) {
	tuple := publicTuple(in.ObjectType, in.ObjectID)
	if in.Published {
		tx.(*factTx).writes = append(tx.(*factTx).writes, tuple)
	} else {
		tx.(*factTx).deletes = append(tx.(*factTx).deletes, tuple)
	}
	return true, nil
}

// WithdrawTx — снятие объекта уносит его публикацию.
func (s *factStore) WithdrawTx(_ context.Context, tx service.Tx, objectType, objectID string) error {
	tx.(*factTx).deletes = append(tx.(*factTx).deletes, publicTuple(objectType, objectID))
	return nil
}

// DropStaleIncarnationTx — в дублёре воплощений нет: прежнего воплощения не бывает.
func (s *factStore) DropStaleIncarnationTx(context.Context, service.Tx, string, string, string) error {
	return nil
}

func publicTuple(objectType, objectID string) service.RelationTuple {
	return service.RelationTuple{User: "user:*", Relation: "v_get", Object: objectType + ":" + objectID}
}

// eventReq — событие объекта с набором кортежей: одна регистрация — один вызов.
type eventReq struct {
	object string
	set    [][2]string
}

func (r *eventReq) GetObject() string { return r.object }
func (r *eventReq) GetTuples() []*iamv1.RegisteredTuple {
	out := make([]*iamv1.RegisteredTuple, 0, len(r.set))
	for _, t := range r.set {
		out = append(out, &iamv1.RegisteredTuple{SubjectId: t[0], Relation: t[1]})
	}
	return out
}
func (r *eventReq) GetGeneration() int64         { return 1 }
func (r *eventReq) GetLabels() map[string]string { return nil }
func (r *eventReq) GetParentProjectId() string   { return "" }
func (r *eventReq) GetParentAccountId() string   { return "" }
func (r *eventReq) GetParentChain() []string     { return nil }

// journalEmitter — порт журнала намерений. Он ничего не применяет сам: применение —
// свойство коммита, как и в базе.
type journalEmitter struct{}

func (journalEmitter) EmitWriteTx(_ context.Context, tx service.Tx, tuples []service.RelationTuple) error {
	tx.(*factTx).writes = append(tx.(*factTx).writes, tuples...)
	return nil
}

func (journalEmitter) EmitDeleteTx(_ context.Context, tx service.Tx, tuples []service.RelationTuple) error {
	tx.(*factTx).deletes = append(tx.(*factTx).deletes, tuples...)
	return nil
}

func newRegUCWithStore(t *testing.T, s *factStore) (*RegisterResourceUseCase, *factTxBeginner) {
	t.Helper()
	txb := &factTxBeginner{store: s}
	uc := NewRegisterResourceUseCase(journalEmitter{}, mirrorAdapter{}, txb, seededCatalogTypes{}, s, s)
	return uc, txb
}

// registerRegistryWithOwner воспроизводит то, что делает потребитель, пишущий `owner`:
// одно событие создания с набором из иерархического кортежа и кортежа создателя.
func registerRegistryWithOwner(t *testing.T, uc *RegisterResourceUseCase, object, project, owner string) {
	t.Helper()
	require.NoError(t, uc.Register(context.Background(), &eventReq{
		object: object, set: [][2]string{{project, "project"}, {owner, "owner"}},
	}))
}

// TestUnregisterResource_OwnerAccessIsActuallyGoneAfterWithdrawal — ГЛАВНАЯ проба.
//
// Утверждает ИСХОД: после снятия регистрации объекта форма отвечает DENY владельцу.
// Положительный контроль в первой половине не даёт отрицанию зеленеть на всём сломанном:
// если бы доступа не было и ДО снятия, вторая половина ничего бы не проверяла.
//
// RED до фикса: снятие называло только иерархический указатель, `owner` оставался, и
// resolveVerb отвечал true — тот самый исход, ради предотвращения которого снятие и
// делается.
func TestUnregisterResource_OwnerAccessIsActuallyGoneAfterWithdrawal(t *testing.T) {
	const (
		object = "registry_registry:reg_doomed"
		owner  = "service_account:sva_creator"
		proj   = "project:prj_home"
	)
	store := &factStore{}
	uc, _ := newRegUCWithStore(t, store)

	registerRegistryWithOwner(t, uc, object, proj, owner)

	// Положительный контроль: доступ действительно БЫЛ — иначе отрицание ниже пусто.
	require.True(t, store.resolveVerb(owner, "v_delete", object),
		"положительный контроль: до снятия владелец обязан иметь глагол, иначе проверка ниже ничего не утверждает")

	require.NoError(t, uc.Unregister(context.Background(), &unregReq{object: object, generation: 2}))

	assert.False(t, store.resolveVerb(owner, "v_delete", object),
		"после снятия регистрации доступа быть НЕ ДОЛЖНО: уцелевший owner выводит все пять глаголов, "+
			"то есть создатель сохраняет полный доступ к удалённому ресурсу")
	assert.False(t, store.resolveVerb(owner, "v_get", object),
		"то же для чтения — вывод из owner покрывает весь набор глаголов")
}

// TestUnregisterResource_ProbeCatchesAdditiveWithdrawal — доказательство, что проба выше
// РАЗЛИЧАЕТ, а не зеленеет по построению.
//
// Инъекция: журнал принимает намерение снятия, а прямой факт не убирается — канонический
// «аддитивный» путь. Все утверждения вида «вызвали / эмитировали / отправили» на нём
// остаются зелёными; утверждение об ИСХОДЕ обязано покраснеть. Здесь мы фиксируем именно
// это: при аддитивном поведении доступ СОХРАНЯЕТСЯ, значит главная проба на нём падает.
func TestUnregisterResource_ProbeCatchesAdditiveWithdrawal(t *testing.T) {
	const (
		object = "registry_registry:reg_doomed"
		owner  = "service_account:sva_creator"
		proj   = "project:prj_home"
	)
	store := &factStore{additive: true}
	uc, _ := newRegUCWithStore(t, store)

	registerRegistryWithOwner(t, uc, object, proj, owner)
	require.NoError(t, uc.Unregister(context.Background(), &unregReq{object: object, generation: 2}))

	assert.True(t, store.resolveVerb(owner, "v_delete", object),
		"инъекция аддитивного снятия обязана СОХРАНИТЬ доступ — иначе главная проба не различала бы "+
			"применённое снятие от эмитированного и была бы зелёной на дефекте")
}

// TestUnregisterResource_WithdrawsThePublicReadGrantOfATornDownObject — публичное чтение
// удалённого репозитория тоже обязано исчезнуть.
//
// Отдельного снятия публикации у снимаемого объекта нет (приёмка NTF-3, Р30): перечень
// того, что стоит на объекте, знает принимающая сторона, она и обязана довести снятие до
// конца.
func TestUnregisterResource_WithdrawsThePublicReadGrantOfATornDownObject(t *testing.T) {
	const (
		object = "registry_repository:reg_x/app"
		proj   = "registry_registry:reg_x"
	)
	store := &factStore{}
	uc, _ := newRegUCWithStore(t, store)

	require.NoError(t, uc.Register(context.Background(), &regReq{
		subject: proj, relation: "parent", object: object,
	}))
	require.NoError(t, uc.Publish(context.Background(), &pubReq{
		object: object, published: true, version: time.Now(), objectGeneration: 1,
	}))
	require.True(t, store.resolveVerb("user:*", "v_get", object), "положительный контроль")

	require.NoError(t, uc.Unregister(context.Background(), &unregReq{object: object, generation: 2}))

	assert.False(t, store.resolveVerb("user:*", "v_get", object),
		"снесённый объект не может оставаться публично читаемым")
}

// TestPublish_ClosingLeavesTheLivingObjectIntact — закрытие публикации не есть снос
// объекта.
//
// Законный близнец той же формы: если бы доведение снятия срабатывало на закрытии
// публикации, отзыв публичного чтения у ЖИВОГО репозитория снёс бы заодно доступ его
// владельца. Гейт обязан молчать здесь и краснеть выше.
func TestPublish_ClosingLeavesTheLivingObjectIntact(t *testing.T) {
	const (
		object = "registry_repository:reg_x/app"
		owner  = "service_account:sva_creator"
		parent = "registry_registry:reg_x"
	)
	store := &factStore{}
	uc, _ := newRegUCWithStore(t, store)
	v := time.Now()

	require.NoError(t, uc.Register(context.Background(), &eventReq{
		object: object, set: [][2]string{{parent, "parent"}, {owner, "owner"}},
	}))
	require.NoError(t, uc.Publish(context.Background(), &pubReq{object: object, published: true, version: v, objectGeneration: 1}))
	require.True(t, store.resolveVerb("user:*", "v_get", object), "положительный контроль")

	// Репозиторий стал приватным — объект жив.
	require.NoError(t, uc.Publish(context.Background(), &pubReq{object: object, published: false, version: v.Add(time.Second), objectGeneration: 1}))

	assert.False(t, store.resolveVerb("user:*", "v_get", object),
		"публичное чтение снято")
	assert.True(t, store.resolveVerb(owner, "v_delete", object),
		"владелец ЖИВОГО репозитория обязан сохранить доступ: закрытие публикации — не снос объекта")
}

// TestUnregisterResource_ResidualReadFailure_FailsClosed — отказ чтения остатка не может
// пройти мягко.
//
// Мягкий проход здесь означал бы ровно исходный дефект, только теперь молча и навсегда:
// снятие вернуло бы успех, а доступ остался бы. Намерение снятия durable в очереди
// потребителя, повтор идемпотентен, поэтому отказ — правильный исход: он будет
// переспрошен. Классификация — временный отказ (Unavailable), а не отказ в правах.
func TestUnregisterResource_ResidualReadFailure_FailsClosed(t *testing.T) {
	store := &factStore{readErr: errors.New("store unreachable")}
	uc, _ := newRegUCWithStore(t, store)

	err := uc.Unregister(context.Background(), &unregReq{object: "registry_registry:reg_doomed", generation: 2})
	require.Error(t, err,
		"нечитаемый остаток обязан отказать: тихий успех оставил бы доступ стоять, а повтор снятия идемпотентен")
}
