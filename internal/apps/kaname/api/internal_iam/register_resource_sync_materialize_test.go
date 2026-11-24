// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_iam

// register_resource_sync_materialize_test.go — приёмка Design-B (завершённая плоская
// авторизация с глаголами) VBC-15 (мгновенная видимость). RegisterResource (путь создания
// прокси FGA vpc/compute/nlb) совместно коммитит кортеж владельца, строку зеркала и
// событие сверки, затем ведёт СИНХРОННЫЙ ReconcileObject после коммита, чтобы
// v_get владельца по объекту материализовался ДО того, как операция создания потребителя
// сообщит о завершении: создание и немедленный GET получают ALLOW, не ожидая
// асинхронной выгрузки очереди сверки. Безопасно при nil, ошибка нефатальна: непровязанный сверщик (или
// ошибка сверки) не роняет Register (выгрузка outbox и периодический обход —
// страховка).
//
// КРАСНЫЙ, пока RegisterResourceUseCase.WithObjectReconciler не запускает
// ReconcileObject после коммита.

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/PRO-Robotech/kaname/internal/testsupport/registrationwriterfixture"
)

// ── Модульные дублёры (Tx / отправитель / зеркало / сверщик объекта) ──────────────────

type smTx struct{ committed bool }

func (t *smTx) Commit(context.Context) error   { t.committed = true; return nil }
func (t *smTx) Rollback(context.Context) error { return nil }

type smTxBeginner struct{ tx *smTx }

func (b *smTxBeginner) Begin(context.Context) (service.Tx, error) {
	b.tx = &smTx{}
	return b.tx, nil
}

type smEmitter struct{}

func (smEmitter) EmitOrderedWriteTx(context.Context, service.Tx, []service.RelationTuple, time.Time) error {
	return nil
}
func (smEmitter) EmitOrderedDeleteTx(context.Context, service.Tx, []service.RelationTuple, time.Time) error {
	return nil
}

type mirrorAdapter struct{ noDescendants }

// UpsertTx всегда сообщает `applied` и никогда `projectionUnchanged`: эти случаи
// проверяют путь материализации, а не страж повторной доставки (которым владеет
// register_resource_redelivery_test.go) и не вердикт маршрутизации (которым владеет
// register_resource_forward_route_test.go). Отсутствие доказательства неустаревания
// оставляет их на защищённой точке входа, то есть в прежнем поведении.
func (mirrorAdapter) UpsertTx(context.Context, service.Tx, service.ResourceMirrorRow) (bool, bool, error) {
	return true, false, nil
}
func (mirrorAdapter) DeleteTx(context.Context, service.Tx, string, string, time.Time) (bool, error) {
	return false, nil
}

// regReq удовлетворяет интерфейсу registerInput (tupleInput, versionedInput,
// метки, родительская область), который сценарий читает на границе обработчика.
type regReq struct {
	subject  string
	relation string
	object   string
	// chain — цепь предков. Поле дублёра, а не заглушка: проба, которой цепь
	// безразлична, оставляет его пустым и получает поведение legacy-вызывающего;
	// проба про цепь задаёт его явно. Дублёр обязан уметь то же, что настоящий
	// запрос, иначе он делает невидимым тот самый вход, ради которого его ставят.
	chain []string
}

func (r *regReq) GetSubjectId() string                     { return r.subject }
func (r *regReq) GetRelation() string                      { return r.relation }
func (r *regReq) GetObject() string                        { return r.object }
func (r *regReq) GetSourceVersion() *timestamppb.Timestamp { return nil }
func (r *regReq) GetLabels() map[string]string             { return nil }
func (r *regReq) GetParentProjectId() string               { return "" }
func (r *regReq) GetParentAccountId() string               { return "" }
func (r *regReq) GetParentChain() []string                 { return r.chain }

// smObjectReconciler записывает прямые вызовы после коммита (быстрый добавляющий
// путь создания, запускаемый сценарием регистрации), независимо от выбранной им точки
// входа: эти случаи проверяют ФАКТ прохода, а не его вид.
type smObjectReconciler struct {
	mu    sync.Mutex
	calls [][2]string // (objectType, objectID)
	err   error
}

func (r *smObjectReconciler) ReconcileObjectForward(_ context.Context, objectType, objectID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, [2]string{objectType, objectID})
	return r.err
}
func (r *smObjectReconciler) ReconcileObjectForwardNoStale(_ context.Context, objectType, objectID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, [2]string{objectType, objectID})
	return r.err
}

func (r *smObjectReconciler) snapshot() [][2]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := make([][2]string, len(r.calls))
	copy(cp, r.calls)
	return cp
}

func newRegUC(t *testing.T, rec *smObjectReconciler) (*RegisterResourceUseCase, *smTxBeginner) {
	t.Helper()
	txb := &smTxBeginner{}
	uc := NewRegisterResourceUseCase(smEmitter{}, mirrorAdapter{}, txb, seededCatalogTypes{}, &recordingPublisher{}, &recordingWithdrawal{}, noAudit{}, unitScopes()).WithRegistrationAuthority(registrationwriterfixture.Authority{Module: "vpc"})
	if rec != nil {
		uc = uc.WithObjectReconciler(rec, nil)
	}
	return uc, txb
}

// TestRegisterResource_VBC15_SyncReconcileAfterCommit — успешный Register запускает
// СИНХРОННЫЙ ReconcileObject зарегистрированного объекта ПОСЛЕ коммита (мгновенная
// видимость: v_get владельца материализуется до завершения Operation потребителя).
func TestRegisterResource_VBC15_SyncReconcileAfterCommit(t *testing.T) {
	rec := &smObjectReconciler{}
	uc, txb := newRegUC(t, rec)

	err := uc.Register(context.Background(), &regReq{
		// Указатель области — единственное, что модуль vpc пишет на сеть по политике
		// записи посева (kaname#982); прежняя форма «создатель с v_get» ею отвергается.
		subject:  "project:" + unitProject,
		relation: "project",
		object:   "vpc_network:vpcn_new",
	})
	require.NoError(t, err)
	require.NotNil(t, txb.tx)
	require.True(t, txb.tx.committed, "register must commit the writer-tx")

	calls := rec.snapshot()
	require.Len(t, calls, 1, "VBC-15: exactly one post-commit ReconcileObjectForward on the registered object")
	assert.Equal(t, [2]string{"vpc.network", "vpcn_new"}, calls[0],
		"VBC-15: post-commit ReconcileObjectForward must target the registered object (dotted type)")
}

// TestRegisterResource_VBC15_NilReconciler_NonFatal — непровязанный сверщик
// не роняет Register (асинхронная выгрузка outbox — страховка).
func TestRegisterResource_VBC15_NilReconciler_NonFatal(t *testing.T) {
	uc, txb := newRegUC(t, nil) // Без WithObjectReconciler.
	err := uc.Register(context.Background(), &regReq{
		subject: "project:" + unitProject, relation: "project", object: "vpc_network:vpcn_new",
	})
	require.NoError(t, err, "VBC-15: nil reconciler must be a non-fatal no-op")
	require.True(t, txb.tx.committed)
}

// TestRegisterResource_VBC15_ReconcileError_NonFatal — ошибка сверки после
// закоммиченной регистрации НЕ фатальна (ресурс надёжно зарегистрирован; выгрузка
// и обход повторяют). Register по-прежнему возвращает успех.
func TestRegisterResource_VBC15_ReconcileError_NonFatal(t *testing.T) {
	rec := &smObjectReconciler{err: errors.New("reconcile transient")}
	uc, txb := newRegUC(t, rec)
	err := uc.Register(context.Background(), &regReq{
		subject: "project:" + unitProject, relation: "project", object: "vpc_network:vpcn_new",
	})
	require.NoError(t, err,
		"VBC-15: a post-commit reconcile error must NOT fail Register (outbox/sweep backstop)")
	require.True(t, txb.tx.committed)
	require.Len(t, rec.snapshot(), 1)
}
