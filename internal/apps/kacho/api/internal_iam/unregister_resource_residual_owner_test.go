// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package internal_iam

// unregister_resource_residual_owner_test.go — снятие проверяется ИСХОДОМ: после отзыва
// доступа не должно БЫТЬ. Не «событие эмитировано», не «метод вызван», не «строка
// отправлена» — именно «модель отвечает DENY».
//
// Почему проба именно такой формы. Регистрация ресурса пишет ТРИ вида отношения, а не
// два: указатель объекта на его проект, per-object глаголы (их выводит реконсайлер из
// выдач) и — у тех потребителей, кто это делает — прямой `owner` создателя. Снятие
// называло только первый. Второй снимает реконсайлер. Третий не снимал НИКТО.
//
// Дефект невидим для любого утверждения вида «вызвали»: намерение эмитируется,
// доезжает, помечается отправленным, ошибок ноль. Замер на стенде (2026-08-04): из
// 180 снятых регистраций реестра `owner` пережил снятие в 180 случаях из 180, и модель
// на удалённом объекте отвечала на `v_delete` — allowed. Поэтому проба ниже держит
// СОСТОЯНИЕ хранилища и спрашивает его так же, как спросил бы enforcement, а не считает
// вызовы.
//
// Модель (proto/kacho/cloud/iam/v1/fga_model.fga) выводит все пять глаголов из `owner`:
//
//	define v_delete: [user, service_account, group#member] or owner or super_admin
//
// поэтому уцелевший `owner` — это не мусорная строка, а действующий полный доступ.

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

// fakeTupleStore — хранилище отношений, а не журнал вызовов. Оно отвечает на вопрос
// «есть ли сейчас доступ», и именно этим отличает применённое снятие от эмитированного.
type fakeTupleStore struct {
	mu sync.Mutex
	// tuples — текущее содержимое хранилища.
	tuples []service.RelationTuple
	// additive — инъекция дефекта: снятие принимается и НИЧЕГО не удаляет. Ровно то
	// поведение, на котором зеленеют утверждения «вызвали».
	additive bool
	readErr  error
	delErr   error
}

func (s *fakeTupleStore) WriteTuples(_ context.Context, t []service.RelationTuple) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, want := range t {
		if !s.hasLocked(want) {
			s.tuples = append(s.tuples, want)
		}
	}
	return nil
}

func (s *fakeTupleStore) DeleteTuples(_ context.Context, t []service.RelationTuple) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.delErr != nil {
		return s.delErr
	}
	if s.additive {
		// Инъекция: вызов принят, исход не наступил.
		return nil
	}
	for _, drop := range t {
		kept := s.tuples[:0]
		for _, have := range s.tuples {
			if have != drop {
				kept = append(kept, have)
			}
		}
		s.tuples = kept
	}
	return nil
}

// ObjectTuples — что СЕЙЧАС стоит на объекте.
func (s *fakeTupleStore) ObjectTuples(_ context.Context, object string) ([]service.RelationTuple, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.readErr != nil {
		return nil, s.readErr
	}
	var out []service.RelationTuple
	for _, t := range s.tuples {
		if t.Object == object {
			out = append(out, t)
		}
	}
	return out, nil
}

func (s *fakeTupleStore) hasLocked(want service.RelationTuple) bool {
	for _, have := range s.tuples {
		if have == want {
			return true
		}
	}
	return false
}

// resolveVerb — минимальный резолвер правила модели «глагол выводится из owner».
// Отвечает на тот же вопрос, что enforcement: есть ли у субъекта глагол на объекте.
func (s *fakeTupleStore) resolveVerb(subject, verb, object string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, t := range s.tuples {
		if t.Object != object || t.User != subject {
			continue
		}
		// Прямой глагол ИЛИ вывод из owner — обе ветви правила модели.
		if t.Relation == verb || t.Relation == "owner" {
			return true
		}
	}
	return false
}

func newRegUCWithStore(t *testing.T, s *fakeTupleStore) (*RegisterResourceUseCase, *smTxBeginner) {
	t.Helper()
	txb := &smTxBeginner{}
	uc := NewRegisterResourceUseCase(smEmitter{}, mirrorAdapter{}, txb).
		WithTupleApplier(s, nil).
		WithResidualTupleReader(s)
	return uc, txb
}

// registerRegistryWithOwner воспроизводит то, что делает потребитель, пишущий `owner`:
// две регистрации на один объект — иерархическая и creator'ская.
func registerRegistryWithOwner(t *testing.T, uc *RegisterResourceUseCase, object, project, owner string) {
	t.Helper()
	require.NoError(t, uc.Register(context.Background(), &regReq{
		subject: project, relation: "project", object: object,
	}))
	require.NoError(t, uc.Register(context.Background(), &regReq{
		subject: owner, relation: "owner", object: object,
	}))
}

// TestUnregisterResource_OwnerAccessIsActuallyGoneAfterWithdrawal — ГЛАВНАЯ проба.
//
// Утверждает ИСХОД: после снятия регистрации объекта модель отвечает DENY владельцу.
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
	store := &fakeTupleStore{}
	uc, _ := newRegUCWithStore(t, store)

	registerRegistryWithOwner(t, uc, object, proj, owner)

	// Положительный контроль: доступ действительно БЫЛ — иначе отрицание ниже пусто.
	require.True(t, store.resolveVerb(owner, "v_delete", object),
		"положительный контроль: до снятия владелец обязан иметь глагол, иначе проверка ниже ничего не утверждает")

	require.NoError(t, uc.Unregister(context.Background(), &unregReq{
		subject: proj, relation: "project", object: object,
	}))

	assert.False(t, store.resolveVerb(owner, "v_delete", object),
		"после снятия регистрации доступа быть НЕ ДОЛЖНО: уцелевший owner выводит все пять глаголов, "+
			"то есть создатель сохраняет полный доступ к удалённому ресурсу")
	assert.False(t, store.resolveVerb(owner, "v_get", object),
		"то же для чтения — вывод из owner покрывает весь набор глаголов")
}

// TestUnregisterResource_ProbeCatchesAdditiveWithdrawal — доказательство, что проба выше
// РАЗЛИЧАЕТ, а не зеленеет по построению.
//
// Инъекция: хранилище принимает снятие и ничего не удаляет — канонический «аддитивный»
// путь. Все утверждения вида «вызвали / эмитировали / отправили» на нём остаются
// зелёными; утверждение об ИСХОДЕ обязано покраснеть. Здесь мы фиксируем именно это:
// при аддитивном поведении доступ СОХРАНЯЕТСЯ, значит главная проба на нём падает.
func TestUnregisterResource_ProbeCatchesAdditiveWithdrawal(t *testing.T) {
	const (
		object = "registry_registry:reg_doomed"
		owner  = "service_account:sva_creator"
		proj   = "project:prj_home"
	)
	store := &fakeTupleStore{additive: true}
	uc, _ := newRegUCWithStore(t, store)

	registerRegistryWithOwner(t, uc, object, proj, owner)
	require.NoError(t, uc.Unregister(context.Background(), &unregReq{
		subject: proj, relation: "project", object: object,
	}))

	assert.True(t, store.resolveVerb(owner, "v_delete", object),
		"инъекция аддитивного снятия обязана СОХРАНИТЬ доступ — иначе главная проба не различала бы "+
			"применённое снятие от эмитированного и была бы зелёной на дефекте")
}

// TestUnregisterResource_WithdrawsThePublicReadGrantOfATornDownObject — публичное чтение
// удалённого репозитория тоже обязано исчезнуть.
//
// Потребитель сегодня снимает его отдельным намерением, но полагаться на то, что каждый
// потребитель вспомнит про каждое отношение, — это и есть источник исходного дефекта:
// перечень отношений знает принимающая сторона, она и обязана довести снятие до конца.
func TestUnregisterResource_WithdrawsThePublicReadGrantOfATornDownObject(t *testing.T) {
	const (
		object = "registry_repository:reg_x/app"
		proj   = "registry_registry:reg_x"
	)
	store := &fakeTupleStore{}
	uc, _ := newRegUCWithStore(t, store)

	require.NoError(t, uc.Register(context.Background(), &regReq{
		subject: proj, relation: "parent", object: object,
	}))
	require.NoError(t, uc.Register(context.Background(), &regReq{
		subject: "user:*", relation: "v_get", object: object,
	}))
	require.True(t, store.resolveVerb("user:*", "v_get", object), "положительный контроль")

	require.NoError(t, uc.Unregister(context.Background(), &unregReq{
		subject: proj, relation: "parent", object: object,
	}))

	assert.False(t, store.resolveVerb("user:*", "v_get", object),
		"снесённый объект не может оставаться публично читаемым")
}

// TestUnregisterResource_PureGrantWithdrawal_LeavesTheLivingObjectIntact — снятие ОДНОЙ
// выдачи не есть снос объекта.
//
// Законный близнец той же формы: если бы доведение снятия срабатывало на любом снятии,
// отзыв публичного чтения у ЖИВОГО репозитория снёс бы заодно доступ его владельца.
// Гейт обязан молчать здесь и краснеть выше.
func TestUnregisterResource_PureGrantWithdrawal_LeavesTheLivingObjectIntact(t *testing.T) {
	const (
		object = "registry_repository:reg_x/app"
		owner  = "service_account:sva_creator"
		parent = "registry_registry:reg_x"
	)
	store := &fakeTupleStore{}
	uc, _ := newRegUCWithStore(t, store)

	require.NoError(t, uc.Register(context.Background(), &regReq{
		subject: parent, relation: "parent", object: object,
	}))
	require.NoError(t, uc.Register(context.Background(), &regReq{
		subject: owner, relation: "owner", object: object,
	}))
	require.NoError(t, uc.Register(context.Background(), &regReq{
		subject: "user:*", relation: "v_get", object: object,
	}))

	// Репозиторий стал приватным — объект жив.
	require.NoError(t, uc.Unregister(context.Background(), &unregReq{
		subject: "user:*", relation: "v_get", object: object,
	}))

	assert.False(t, store.resolveVerb("user:*", "v_get", object),
		"публичное чтение снято")
	assert.True(t, store.resolveVerb(owner, "v_delete", object),
		"владелец ЖИВОГО репозитория обязан сохранить доступ: снятие одной выдачи — не снос объекта")
}

// TestUnregisterResource_ResidualReadFailure_FailsClosed — отказ чтения остатка не может
// пройти мягко.
//
// Мягкий проход здесь означал бы ровно исходный дефект, только теперь молча и навсегда:
// снятие вернуло бы успех, а доступ остался бы. Намерение снятия durable в очереди
// потребителя, повтор идемпотентен, поэтому отказ — правильный исход: он будет
// переспрошен. Классификация — временный отказ (Unavailable), а не отказ в правах.
func TestUnregisterResource_ResidualReadFailure_FailsClosed(t *testing.T) {
	store := &fakeTupleStore{readErr: errors.New("store unreachable")}
	uc, _ := newRegUCWithStore(t, store)

	err := uc.Unregister(context.Background(), &unregReq{
		subject: "project:prj_home", relation: "project", object: "registry_registry:reg_doomed",
	})
	require.Error(t, err,
		"нечитаемый остаток обязан отказать: тихий успех оставил бы доступ стоять, а повтор снятия идемпотентен")
}

// TestUnregisterResource_ResidualReaderUnwired_KeepsPreviousBehaviour — непровязанный
// читатель остатка оставляет прежний путь (очередь), но не ломает снятие.
func TestUnregisterResource_ResidualReaderUnwired_KeepsPreviousBehaviour(t *testing.T) {
	txb := &smTxBeginner{}
	uc := NewRegisterResourceUseCase(smEmitter{}, mirrorAdapter{}, txb) // без WithResidualTupleReader
	require.NoError(t, uc.Unregister(context.Background(), &unregReq{
		subject: "project:prj_home", relation: "project", object: "registry_registry:reg_doomed",
	}))
	require.True(t, txb.tx.committed)
}
