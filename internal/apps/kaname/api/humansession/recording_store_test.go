// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package humansession_test

// recording_store_test.go — ЖУРНАЛ РАБОТЫ ХРАНИЛИЩА: обёртки портов,
// записывающие каждое обращение полосы в один ряд (вид операции, её порядок и
// число операторов базы, которое она исполнила). Предмет — «сколько и какой
// работы хранилища полоса сделала до исхода»: полосы, обязанные быть
// неразличимыми по времени, а пробы времени не имеющие, судятся равенством
// этих рядов.
//
// Обращение к порту — ещё не работа базы: вход, который адаптер отвергает
// аргументом, до базы не доходит. Поэтому у каждой записи есть `Trips` —
// разность счётчика операторов дублёра (`fakeStore.trips`) до и после
// обращения; что дублёр считает их как адаптер, держит сверка
// `store_double_parity_integration_test.go`.
//
// Обёртки НЕ встраивают порт: каждый метод написан явно и пишет запись. Метод,
// добавленный в порт, без записи не соберётся — журнал не может молча
// пропустить новый вид работы (встроенный порт отдал бы его мимо записи).

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
)

// storeOp — одно обращение к порту хранилища.
type storeOp struct {
	// Port — какой порт позван: store · writer.
	Port string
	// Name — метод порта; у чтения строки способа входа — с видом строки.
	Name string
	// LoginMethodRead — обращение читает строку способа входа (ось «заведено»
	// места решения о счёте), каким бы портом оно ни шло.
	LoginMethodRead bool
	// Trips — операторов базы, исполненных обращением: 0 — вход отвергнут
	// аргументом, до базы не дойдя.
	Trips int64
}

func (o storeOp) String() string { return fmt.Sprintf("%s.%s/%d", o.Port, o.Name, o.Trips) }

// tripsOf — операторов базы во всём ряду.
func tripsOf(ops []storeOp) int64 {
	var n int64
	for _, op := range ops {
		n += op.Trips
	}
	return n
}

// storeJournal — ряд обращений одной полосы.
type storeJournal struct {
	mu  sync.Mutex
	ops []storeOp
}

func (j *storeJournal) note(op storeOp) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.ops = append(j.ops, op)
}

// take — ряд с последней выемки; журнал после неё пуст.
func (j *storeJournal) take() []storeOp {
	j.mu.Lock()
	defer j.mu.Unlock()
	out := j.ops
	j.ops = nil
	return out
}

// recordingStore — humansession.Store с журналом; meter — счётчик операторов
// базы дублёра под обёрткой.
type recordingStore struct {
	inner humansession.Store
	j     *storeJournal
	meter func() int64
}

var _ humansession.Store = recordingStore{}

// record — запись обращения ПО ЕГО ЗАВЕРШЕНИИ: число операторов — разность
// счётчика до и после. Зовётся `defer rec(...)()`.
func record(j *storeJournal, meter func() int64, op storeOp) func() {
	before := meter()
	return func() {
		op.Trips = meter() - before
		j.note(op)
	}
}

func (s recordingStore) rec(name string) func() {
	return record(s.j, s.meter, storeOp{Port: "store", Name: name})
}

func (s recordingStore) Resolve(ctx context.Context, digest domain.BearerDigest, now time.Time) (humansession.Resolved, humansession.NoSessionReason, error) {
	defer s.rec("Resolve")()
	return s.inner.Resolve(ctx, digest, now)
}

func (s recordingStore) CountFailures(ctx context.Context, scope humansession.FailureScope, key string, since time.Time) (int, error) {
	defer s.rec("CountFailures")()
	return s.inner.CountFailures(ctx, scope, key, since)
}

func (s recordingStore) OldestFailureSince(ctx context.Context, scope humansession.FailureScope, key string, since time.Time) (time.Time, bool, error) {
	defer s.rec("OldestFailureSince")()
	return s.inner.OldestFailureSince(ctx, scope, key, since)
}

func (s recordingStore) FirstAuthentication(ctx context.Context, userID domain.UserID) (time.Time, bool, error) {
	defer s.rec("FirstAuthentication")()
	return s.inner.FirstAuthentication(ctx, userID)
}

func (s recordingStore) RecoveryTarget(ctx context.Context, email domain.Email) (humansession.RecoveryTarget, bool, error) {
	defer s.rec("RecoveryTarget")()
	return s.inner.RecoveryTarget(ctx, email)
}

func (s recordingStore) Writer(ctx context.Context) (humansession.Writer, error) {
	defer s.rec("Writer")()
	w, err := s.inner.Writer(ctx)
	if err != nil {
		return nil, err
	}
	return recordingWriter{inner: w, j: s.j, meter: s.meter}, nil
}

// recordingWriter — humansession.Writer с журналом.
type recordingWriter struct {
	inner humansession.Writer
	j     *storeJournal
	meter func() int64
}

var _ humansession.Writer = recordingWriter{}

func (w recordingWriter) rec(name string) func() {
	return record(w.j, w.meter, storeOp{Port: "writer", Name: name})
}

func (w recordingWriter) InsertSession(ctx context.Context, s domain.HumanSession, digest domain.BearerDigest) error {
	defer w.rec("InsertSession")()
	return w.inner.InsertSession(ctx, s, digest)
}

func (w recordingWriter) RememberFirstAuthentication(ctx context.Context, userID domain.UserID, at time.Time) error {
	defer w.rec("RememberFirstAuthentication")()
	return w.inner.RememberFirstAuthentication(ctx, userID, at)
}

func (w recordingWriter) FirstAuthentication(ctx context.Context, userID domain.UserID) (time.Time, bool, error) {
	defer w.rec("FirstAuthentication")()
	return w.inner.FirstAuthentication(ctx, userID)
}

func (w recordingWriter) EndSession(ctx context.Context, id domain.HumanSessionID, at time.Time, reason string) (bool, error) {
	defer w.rec("EndSession")()
	return w.inner.EndSession(ctx, id, at, reason)
}

func (w recordingWriter) EndOtherSessions(ctx context.Context, userID domain.UserID, keep domain.HumanSessionID, at time.Time, reason string) (int, error) {
	defer w.rec("EndOtherSessions")()
	return w.inner.EndOtherSessions(ctx, userID, keep, at, reason)
}

func (w recordingWriter) RotateBearer(ctx context.Context, id domain.HumanSessionID, digest domain.BearerDigest, presentedAt time.Time) error {
	defer w.rec("RotateBearer")()
	return w.inner.RotateBearer(ctx, id, digest, presentedAt)
}

func (w recordingWriter) PresentInSession(ctx context.Context, id domain.HumanSessionID, methods []string, level string, digest domain.BearerDigest, presentedAt time.Time) error {
	defer w.rec("PresentInSession")()
	return w.inner.PresentInSession(ctx, id, methods, level, digest, presentedAt)
}

func (w recordingWriter) UpsertCutoff(ctx context.Context, u domain.UserTokenRevocation, revokedBy domain.UserID) error {
	defer w.rec("UpsertCutoff")()
	return w.inner.UpsertCutoff(ctx, u, revokedBy)
}

func (w recordingWriter) ReplaceLoginVerifier(ctx context.Context, m domain.LoginMethod) (bool, error) {
	defer w.rec("ReplaceLoginVerifier")()
	return w.inner.ReplaceLoginVerifier(ctx, m)
}

func (w recordingWriter) LoginMethod(ctx context.Context, userID domain.UserID, kind domain.LoginMethodKind) (domain.LoginMethod, error) {
	defer record(w.j, w.meter, storeOp{Port: "writer", Name: "LoginMethod(" + string(kind) + ")", LoginMethodRead: true})()
	return w.inner.LoginMethod(ctx, userID, kind)
}

func (w recordingWriter) RecordFailure(ctx context.Context, scope humansession.FailureScope, key string, at time.Time) error {
	defer w.rec("RecordFailure")()
	return w.inner.RecordFailure(ctx, scope, key, at)
}

func (w recordingWriter) ResetFailures(ctx context.Context, scope humansession.FailureScope, key string) error {
	defer w.rec("ResetFailures")()
	return w.inner.ResetFailures(ctx, scope, key)
}

func (w recordingWriter) EmitAudit(ctx context.Context, ev outboxtypes.AuditEvent) error {
	defer w.rec("EmitAudit")()
	return w.inner.EmitAudit(ctx, ev)
}

func (w recordingWriter) InsertRecoveryCode(ctx context.Context, c domain.RecoveryCode) error {
	defer w.rec("InsertRecoveryCode")()
	return w.inner.InsertRecoveryCode(ctx, c)
}

func (w recordingWriter) SupersedeRecoveryCodes(ctx context.Context, userID domain.UserID) (int, error) {
	defer w.rec("SupersedeRecoveryCodes")()
	return w.inner.SupersedeRecoveryCodes(ctx, userID)
}

func (w recordingWriter) ConsumeRecoveryCode(ctx context.Context, userID domain.UserID, digest domain.CodeDigest, now time.Time) (domain.RecoveryCode, bool, error) {
	defer w.rec("ConsumeRecoveryCode")()
	return w.inner.ConsumeRecoveryCode(ctx, userID, digest, now)
}

func (w recordingWriter) EmitRecoveryMail(ctx context.Context, in humansession.RecoveryMailIntent) error {
	defer w.rec("EmitRecoveryMail")()
	return w.inner.EmitRecoveryMail(ctx, in)
}

func (w recordingWriter) InsertRecoveryCompletion(ctx context.Context, rc domain.RecoveryCompletion) (bool, error) {
	defer w.rec("InsertRecoveryCompletion")()
	return w.inner.InsertRecoveryCompletion(ctx, rc)
}

func (w recordingWriter) UpsertPendingTOTP(ctx context.Context, m domain.LoginMethod) (bool, error) {
	defer w.rec("UpsertPendingTOTP")()
	return w.inner.UpsertPendingTOTP(ctx, m)
}

func (w recordingWriter) ActivateTOTP(ctx context.Context, userID domain.UserID, pendingSince time.Time, step int64, at time.Time) (bool, error) {
	defer w.rec("ActivateTOTP")()
	return w.inner.ActivateTOTP(ctx, userID, pendingSince, step, at)
}

func (w recordingWriter) ReplaceLookupSet(ctx context.Context, m domain.LoginMethod) error {
	defer w.rec("ReplaceLookupSet")()
	return w.inner.ReplaceLookupSet(ctx, m)
}

func (w recordingWriter) LockLookupSet(ctx context.Context, userID domain.UserID) (domain.LoginMethod, bool, error) {
	defer w.rec("LockLookupSet")()
	return w.inner.LockLookupSet(ctx, userID)
}

func (w recordingWriter) ConsumeLookupElement(ctx context.Context, userID domain.UserID, element string) (bool, error) {
	defer w.rec("ConsumeLookupElement")()
	return w.inner.ConsumeLookupElement(ctx, userID, element)
}

func (w recordingWriter) RecordAcceptedStep(ctx context.Context, userID domain.UserID, step int64) (bool, error) {
	defer w.rec("RecordAcceptedStep")()
	return w.inner.RecordAcceptedStep(ctx, userID, step)
}

func (w recordingWriter) RemoveSecondFactor(ctx context.Context, userID domain.UserID) (bool, error) {
	defer w.rec("RemoveSecondFactor")()
	return w.inner.RemoveSecondFactor(ctx, userID)
}

func (w recordingWriter) Commit(ctx context.Context) error {
	defer w.rec("Commit")()
	return w.inner.Commit(ctx)
}

func (w recordingWriter) Rollback(ctx context.Context) error {
	defer w.rec("Rollback")()
	return w.inner.Rollback(ctx)
}
