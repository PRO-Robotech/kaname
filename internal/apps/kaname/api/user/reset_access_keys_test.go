// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package user

// reset_access_keys_test.go — сброс ключей доступа администратором облака
// (задача PRO-Robotech/kaname#638; приёмка
// `docs/engineering/acceptance/cloud-administrator-resets-login-methods.md`,
// редакция 5, Р1–Р5, Р7): синхронная полоса — анонимный, негодный id, промах,
// «ключей нет» — отвечает ДО порождения Operation; исполнение — одной
// транзакцией: испытания регистрации сняты раньше ключей, все строки ключей
// сняты, отсечка `now` с причиной `access-keys-reset` и актором, событие с
// обоими акторами без личных данных; гонка двух сбросов — второй завершает
// Operation тем же токеном без отсечки и события.
//
// Настоящая база и порядок операторов под замком — интеграционные пробы
// `internal/handler/loginlanehttp/access_keys_reset_integration_test.go`.

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/corelib/operations"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
	"github.com/PRO-Robotech/kaname/internal/testsupport/momentclock"
)

// rakKeys — дублёр хранилища ключей: число строк ключей человека.
type rakKeys struct {
	mu    sync.Mutex
	n     int
	err   error
	calls int
}

func (k *rakKeys) AccessKeyEnrolled(_ context.Context, _ domain.UserID) (bool, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.calls++
	if k.err != nil {
		return false, k.err
	}
	return k.n > 0, nil
}

// rakStore — дублёр писателя сброса: одна транзакция, оператор снятия
// отвечает числом снятых строк, как адаптер. steps — порядок операторов
// каждого писателя (Р7: испытания раньше ключей).
type rakStore struct {
	mu        sync.Mutex
	keys      *rakKeys
	cutoffs   []domain.UserTokenRevocation
	revokers  []domain.UserID
	audits    []outboxtypes.AuditEvent
	writers   int
	commits   int
	rollbacks int
	steps     [][]string
	failOn    string
}

type rakWriter struct {
	s       *rakStore
	user    domain.UserID
	removed int64
	cutoff  *domain.UserTokenRevocation
	revoker domain.UserID
	audit   *outboxtypes.AuditEvent
	steps   []string
	done    bool
}

func (s *rakStore) ResetWriter(_ context.Context, userID domain.UserID) (AccessKeysResetWriter, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.writers++
	if s.failOn == "writer" {
		return nil, iamerr.Wrapf(iamerr.ErrUnavailable, "database unavailable")
	}
	return &rakWriter{s: s, user: userID}, nil
}

func (w *rakWriter) RetireRegistrationChallenges(_ context.Context, userID domain.UserID) (int64, error) {
	w.steps = append(w.steps, "challenges:"+string(userID))
	if w.s.failOn == "challenges" {
		return 0, iamerr.Wrapf(iamerr.ErrUnavailable, "database unavailable")
	}
	return 0, nil
}

func (w *rakWriter) DeleteAccessKeysOf(_ context.Context, userID domain.UserID) (int64, error) {
	w.steps = append(w.steps, "keys:"+string(userID))
	if w.s.failOn == "delete" {
		return 0, iamerr.Wrapf(iamerr.ErrUnavailable, "database unavailable")
	}
	w.s.keys.mu.Lock()
	defer w.s.keys.mu.Unlock()
	w.removed = int64(w.s.keys.n)
	return w.removed, nil
}

func (w *rakWriter) UpsertCutoff(_ context.Context, u domain.UserTokenRevocation, revokedBy domain.UserID) error {
	w.steps = append(w.steps, "cutoff")
	if err := u.Validate(); err != nil {
		return iamerr.Wrapf(iamerr.ErrInvalidArg, "%s", err.Error())
	}
	w.cutoff, w.revoker = &u, revokedBy
	return nil
}

func (w *rakWriter) EmitAudit(_ context.Context, ev outboxtypes.AuditEvent) error {
	w.steps = append(w.steps, "audit")
	if w.s.failOn == "audit" {
		return iamerr.Wrapf(iamerr.ErrUnavailable, "database unavailable")
	}
	w.audit = &ev
	return nil
}

func (w *rakWriter) Commit(context.Context) error {
	w.s.mu.Lock()
	defer w.s.mu.Unlock()
	if w.s.failOn == "commit" {
		return iamerr.Wrapf(iamerr.ErrUnavailable, "database unavailable")
	}
	w.done = true
	if w.removed > 0 {
		w.s.keys.mu.Lock()
		w.s.keys.n = 0
		w.s.keys.mu.Unlock()
	}
	if w.cutoff != nil {
		w.s.cutoffs = append(w.s.cutoffs, *w.cutoff)
		w.s.revokers = append(w.s.revokers, w.revoker)
	}
	if w.audit != nil {
		w.s.audits = append(w.s.audits, *w.audit)
	}
	w.s.commits++
	w.s.steps = append(w.s.steps, w.steps)
	return nil
}

func (w *rakWriter) Rollback(context.Context) error {
	w.s.mu.Lock()
	defer w.s.mu.Unlock()
	if !w.done {
		w.s.rollbacks++
	}
	return nil
}

func newRAK(keys int) (*rakKeys, *rakStore) {
	k := &rakKeys{n: keys}
	return k, &rakStore{keys: k}
}

func rakUseCase(repo Repo, ops operations.Repo, k *rakKeys, s *rakStore) *ResetAccessKeysUseCase {
	return NewResetAccessKeysUseCase(repo, ops, k, s).WithCutoffClock(momentclock.Func(time.Now))
}

// TestResetAccessKeys_LMR03_SyncRefusalsBeforeTheStore — анонимный, кривой id,
// промах держателя — до чтения ключей и до писателя; Operation не порождена.
func TestResetAccessKeys_LMR03_SyncRefusalsBeforeTheStore(t *testing.T) {
	k, s := newRAK(2)
	ops := newUpdOpsRepo()
	uc := rakUseCase(newUpdUserRepo(), ops, k, s)

	op, err := uc.Execute(context.Background(), domain.UserID(updUserID))
	require.Error(t, err)
	assert.Nil(t, op)
	assert.Equal(t, codes.PermissionDenied, status.Code(err), "анонимный — до всего")

	op, err = uc.Execute(ownerCtx(), "not-a-user-id")
	require.Error(t, err)
	assert.Nil(t, op)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	assert.Equal(t, "invalid user id 'not-a-user-id'", status.Convert(err).Message(), "служба мимо края — свой текст формы (Р2)")

	absentRepo := newUpdUserRepo()
	absentRepo.getErr = iamerr.Wrapf(iamerr.ErrNotFound, "User usr000000000000absnt not found")
	op, err = rakUseCase(absentRepo, ops, k, s).Execute(ownerCtx(), "usr000000000000absnt")
	require.Error(t, err)
	assert.Nil(t, op)
	assert.Equal(t, codes.NotFound, status.Code(err))
	assert.Equal(t, "User usr000000000000absnt not found", status.Convert(err).Message(), "промах держателя — линия прямого чтения (Р2)")

	assert.Zero(t, k.calls, "до чтения ключей ни один отказ выше не доходит")
	assert.Zero(t, s.writers, "писатель не открыт")
	assert.Empty(t, ops.ops, "Operation не порождена")

	// Положительный близнец: тот же вход с законным id доходит до исполнения.
	op, err = uc.Execute(ownerCtx(), domain.UserID(updUserID))
	require.NoError(t, err)
	require.NotNil(t, op)
	require.NoError(t, operations.Wait(context.Background()))
	assert.Equal(t, 1, s.commits)
}

// TestResetAccessKeys_LMR04_NothingToResetIsOneSyncRefusal — ключей нет:
// FAILED_PRECONDITION `ACCESS_KEYS_NOT_ENROLLED` с текстом приёмки; писатель не
// открыт, Operation нет, отсечки и события нет. Близнец — один ключ: исход
// `done`.
func TestResetAccessKeys_LMR04_NothingToResetIsOneSyncRefusal(t *testing.T) {
	k, s := newRAK(0)
	ops := newUpdOpsRepo()
	op, err := rakUseCase(newUpdUserRepo(), ops, k, s).Execute(ownerCtx(), domain.UserID(updUserID))
	require.Error(t, err)
	assert.Nil(t, op, "отказ до порождения Operation")
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	assert.Equal(t, "user has no access key to reset", status.Convert(err).Message())
	assert.Equal(t, "ACCESS_KEYS_NOT_ENROLLED", rsfReason(t, err))
	assert.Equal(t, 1, k.calls)
	assert.Zero(t, s.writers, "писатель не открыт: сбрасывать нечего")
	assert.Empty(t, ops.ops, "Operation не порождена")
	assert.Empty(t, s.cutoffs)
	assert.Empty(t, s.audits)

	k1, s1 := newRAK(1)
	op, err = rakUseCase(newUpdUserRepo(), newUpdOpsRepo(), k1, s1).Execute(ownerCtx(), domain.UserID(updUserID))
	require.NoError(t, err, "близнец по одному факту: у цели есть ключ")
	require.NotNil(t, op)
	require.NoError(t, operations.Wait(context.Background()))
	assert.Equal(t, 1, s1.commits)

	// Ошибка чтения ключей — внутренняя ошибка, а не «ключей нет».
	kErr := &rakKeys{err: iamerr.Wrapf(iamerr.ErrUnavailable, "database unavailable")}
	_, err = rakUseCase(newUpdUserRepo(), newUpdOpsRepo(), kErr, &rakStore{keys: kErr}).Execute(ownerCtx(), domain.UserID(updUserID))
	require.Error(t, err)
	assert.NotEqual(t, codes.FailedPrecondition, status.Code(err), "сбой чтения не выдаётся за «нечего сбрасывать»")
	assert.NotContains(t, status.Convert(err).Message(), "database unavailable", "текст хранилища наружу не течёт")
}

// TestResetAccessKeys_LMR01_ResetIsOneTransaction — все ключи сняты, отсечка
// `now` с причиной и актором, событие с обоими акторами без личных данных —
// одним коммитом; испытания регистрации сняты РАНЬШЕ ключей (Р7).
func TestResetAccessKeys_LMR01_ResetIsOneTransaction(t *testing.T) {
	k, s := newRAK(2)
	repo := newUpdUserRepo()
	ops := newUpdOpsRepo()
	before := time.Now().UTC()
	op, err := rakUseCase(repo, ops, k, s).Execute(ownerCtx(), domain.UserID(updUserID))
	require.NoError(t, err)
	require.NotNil(t, op)
	assert.Contains(t, op.Description, "Reset access keys")
	require.NoError(t, operations.Wait(context.Background()))

	got, err := ops.Get(context.Background(), op.ID)
	require.NoError(t, err)
	require.True(t, got.Done)
	require.Nil(t, got.Error, "сброс исполнен без ошибки")

	assert.Zero(t, k.n, "все строки ключей сняты")
	require.Equal(t, 1, s.commits)
	require.Len(t, s.steps, 1)
	assert.Equal(t, []string{"challenges:" + updUserID, "keys:" + updUserID, "cutoff", "audit"}, s.steps[0],
		"порядок операторов: испытания регистрации, затем ключи (Р7), затем отсечка и событие")

	require.Len(t, s.cutoffs, 1)
	cut := s.cutoffs[0]
	assert.Equal(t, domain.UserID(updUserID), cut.UserID)
	assert.Equal(t, "access-keys-reset", cut.Reason)
	assert.Equal(t, domain.RevokeReasonAccessKeysReset, cut.Reason)
	assert.Equal(t, domain.UserID(updOwnerID), cut.RevokedBy, "актор отсечки — администратор облака")
	assert.Equal(t, domain.UserID(updOwnerID), s.revokers[0])
	assert.False(t, cut.RevokeBefore.Before(before), "отсечка — моментом now")
	assert.False(t, cut.RevokeBefore.After(time.Now().UTC().Add(time.Second)))

	require.Len(t, s.audits, 1)
	ev := s.audits[0]
	assert.Equal(t, "iam.user.access_keys_reset", ev.EventType)
	assert.Equal(t, updAccountID, ev.TenantAccountID)
	assert.Equal(t, updOwnerID, ev.Payload["actor"])
	assert.Equal(t, updUserID, ev.Payload["user_id"], "субъект — человек, чьи ключи сняты")
	assert.Equal(t, "access-keys-reset", ev.Payload["reason"])
	assert.Len(t, ev.Payload, 3, "ни адреса, ни имени, ни числа ключей (Р4)")
	assert.Empty(t, repo.auditSnapshot(), "событие идёт писателем сброса, не зеркалом: одна транзакция со снятием")
}

// TestResetAccessKeys_LMR01_AnyFailedWriteChangesNothing — отказ любой записи
// откатывает всё: ни одна строка не снята, отсечки и события нет, Operation
// несёт ошибку, текст хранилища наружу не течёт (§7 инв. 2, 5).
func TestResetAccessKeys_LMR01_AnyFailedWriteChangesNothing(t *testing.T) {
	for _, step := range []string{"writer", "challenges", "delete", "audit", "commit"} {
		t.Run(step, func(t *testing.T) {
			k, s := newRAK(2)
			s.failOn = step
			ops := newUpdOpsRepo()
			op, err := rakUseCase(newUpdUserRepo(), ops, k, s).Execute(ownerCtx(), domain.UserID(updUserID))
			require.NoError(t, err, "синхронная полоса видела ключи")
			require.NoError(t, operations.Wait(context.Background()))
			got, err := ops.Get(context.Background(), op.ID)
			require.NoError(t, err)
			require.True(t, got.Done)
			require.NotNil(t, got.Error, "Operation несёт отказ")
			assert.NotContains(t, got.Error.Message, "database unavailable", "текст хранилища наружу не течёт")
			assert.Equal(t, 2, k.n, "ни одна строка ключа не снята")
			assert.Zero(t, s.commits)
			assert.Empty(t, s.cutoffs)
			assert.Empty(t, s.audits)
		})
	}
}

// TestResetAccessKeys_LMR07_SecondResetFindsNothing — синхронная сверка видела
// ключи, а к записи их снял первый сброс: оператор снятия отвечает нулём,
// Operation — FAILED_PRECONDITION `ACCESS_KEYS_NOT_ENROLLED`, без отсечки и
// события, транзакция не зафиксирована.
func TestResetAccessKeys_LMR07_SecondResetFindsNothing(t *testing.T) {
	k, s := newRAK(1)
	ops := newUpdOpsRepo()
	uc := rakUseCase(newUpdUserRepo(), ops, k, s)
	op1, err := uc.Execute(ownerCtx(), domain.UserID(updUserID))
	require.NoError(t, err)
	require.NoError(t, operations.Wait(context.Background()))
	require.Equal(t, 1, s.commits)

	// Второй прошёл синхронную сверку до фиксации первого: дублёр сверки
	// возвращает «ключи есть», писатель видит ноль строк.
	k.mu.Lock()
	k.n = 1
	k.mu.Unlock()
	s2 := &rakStore{keys: &rakKeys{n: 0}}
	uc2 := rakUseCase(newUpdUserRepo(), ops, k, s2)
	op2, err := uc2.Execute(ownerCtx(), domain.UserID(updUserID))
	require.NoError(t, err, "синхронная сверка второго видела ключ")
	require.NoError(t, operations.Wait(context.Background()))

	got1, err := ops.Get(context.Background(), op1.ID)
	require.NoError(t, err)
	require.Nil(t, got1.Error, "первый сброс исполнен")
	got2, err := ops.Get(context.Background(), op2.ID)
	require.NoError(t, err)
	require.True(t, got2.Done)
	require.NotNil(t, got2.Error, "второй сброс завершён ошибкой")
	assert.EqualValues(t, codes.FailedPrecondition, got2.Error.Code)
	assert.Equal(t, "user has no access key to reset", got2.Error.Message)
	assert.Len(t, s.cutoffs, 1, "отсечка записана один раз")
	assert.Len(t, s.audits, 1, "событие одно")
	assert.Zero(t, s2.commits, "транзакция второго не зафиксирована")
	assert.Empty(t, s2.cutoffs, "второй сброс отсечки не пишет")
	assert.Empty(t, s2.audits, "второй сброс события не пишет")
}
