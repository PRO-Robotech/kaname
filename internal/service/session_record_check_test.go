// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// session_record_check_test.go — доводы условия `mfa_fresh` выводятся из записи
// сессии ВОПРОСА (kaname#133, исход (а); приёмка
// `assurance-level-is-declared-by-our-session.md` §3.4, Ф11-34…44, -48).
//
// Здесь — провязка службы на дублёрах портов: что спрошено у хранилища записей,
// когда оно не спрошено вовсе и что доехало до решающей стороны. Что запись
// годна (жива, личность равна доверенной) — свойство оператора хранилища, и его
// держит интеграционная проба на реальной базе
// (`internal/handler/loginlanehttp/mfa_fresh_condition_integration_test.go`).
package service

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/grpcsrv"
	"github.com/PRO-Robotech/corelib/operations"

	"github.com/PRO-Robotech/kaname/internal/callerorigin"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
)

// fakeSessionRecords — дублёр порта записей сессии: отвечает заданным и
// запоминает, о чём его спросили.
type fakeSessionRecords struct {
	mu    sync.Mutex
	rec   domain.HumanSession
	found bool
	err   error
	calls []sessionRecordCall
}

type sessionRecordCall struct {
	id     domain.HumanSessionID
	person domain.UserID
	at     time.Time
}

func (f *fakeSessionRecords) LiveSessionOf(_ context.Context, id domain.HumanSessionID, person domain.UserID,
	at time.Time) (domain.HumanSession, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, sessionRecordCall{id: id, person: person, at: at})
	return f.rec, f.found, f.err
}

func (f *fakeSessionRecords) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

const (
	srcPerson  = "usr-srcperson0000001"
	srcSession = "hss-0000000000000000a"
)

// srcT0 — момент аутентификации записи; часы службы — srcT0 + 1 мин.
var srcT0 = time.Date(2026, 10, 11, 9, 0, 0, 0, time.UTC)

// edgeAsked — контекст вопроса так, как его задаёт край от имени сессии:
// доверенная личность человека, доверенный уровень и номер записи.
func edgeAsked(person, acr, session string) context.Context {
	ctx := grpcsrv.WithTrustedPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: person}, true)
	ctx = grpcsrv.WithTrustedACR(ctx, acr, true)
	if session != "" {
		ctx = callerorigin.WithSessionID(ctx, session)
	}
	return ctx
}

func sshCheck(subject string) CheckRequest {
	return CheckRequest{
		Subject:          subject,
		Resource:         ResourceRef{Type: "compute_instance", ID: "ins-x"},
		Action:           "compute.instances.ssh",
		RequiredRelation: "ssh",
	}
}

func keySession() domain.HumanSession {
	return domain.HumanSession{
		ID: srcSession, UserID: srcPerson, AuthenticatedAt: srcT0,
		LastPresentedAt: srcT0.Add(14 * time.Minute), ExpiresAt: srcT0.Add(24 * time.Hour),
		AssuranceLevel: "3", PresentedMethods: []string{"webauthn"},
	}
}

func newEvidenceService(m *mockRelations, rec *fakeSessionRecords) *AuthorizeService {
	return NewAuthorizeService(AuthorizeServiceConfig{
		Relations:      m,
		SessionRecords: rec,
		Now:            func() time.Time { return srcT0.Add(time.Minute) },
	})
}

// Ф11-34 на уровне провязки: запись найдена — доводы способов и момента
// доезжают до решающей стороны, и момент — момент АУТЕНТИФИКАЦИИ записи, а не
// последнего предъявления (Ф11-37, Р6).
func TestF11_34_EvidenceComesFromTheRecordOfTheQuestionsSession(t *testing.T) {
	m := &mockRelations{checkResp: true}
	rec := &fakeSessionRecords{rec: keySession(), found: true}
	svc := newEvidenceService(m, rec)

	res, err := svc.Check(edgeAsked(srcPerson, "3", srcSession), sshCheck("user:"+srcPerson))
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !res.Allowed {
		t.Fatalf("дублёр решающей стороны отвечает «да», а служба вернула отказ: %v", res.DenyReasons)
	}
	if got := rec.callCount(); got != 1 {
		t.Fatalf("хранилище записей спрошено %d раз, ожидался один вопрос", got)
	}
	call := rec.calls[0]
	if call.id != srcSession || call.person != srcPerson {
		t.Errorf("спрошено (%s, %s), ожидалось (%s, %s): запись ищется по ссылке вопроса и "+
			"сверяется с ДОВЕРЕННОЙ личностью", call.id, call.person, srcSession, srcPerson)
	}
	if !call.at.Equal(srcT0.Add(time.Minute)) {
		t.Errorf("живость судится на моменте %v, ожидались часы службы %v", call.at, srcT0.Add(time.Minute))
	}
	cc := m.lastCondCtx
	if got, want := cc["mfa_at"], srcT0.Unix(); got != want {
		t.Errorf("mfa_at = %v, ожидался момент аутентификации записи %d — не момент последнего "+
			"предъявления (%d), его двигает и пароль (Ф11-37)", got, want, srcT0.Add(14*time.Minute).Unix())
	}
	amr, _ := cc["amr_claims"].([]string)
	if len(amr) != 1 || amr[0] != "webauthn" {
		t.Errorf("amr_claims = %v, ожидалось множество предъявленного записи [webauthn]", cc["amr_claims"])
	}
	if cc["acr_value"] != "3" {
		t.Errorf("acr_value = %v, ожидался доверенный уровень вопроса «3»", cc["acr_value"])
	}
}

// Ф11-48 на уровне провязки: без ссылки на запись доводов нет, и хранилище не
// спрашивается вовсе — последнюю либо иную сессию личности служба вместо ссылки
// не подставляет.
func TestF11_48_NoSessionReferenceMeansNoEvidence(t *testing.T) {
	m := &mockRelations{checkResp: true}
	rec := &fakeSessionRecords{rec: keySession(), found: true}
	svc := newEvidenceService(m, rec)

	if _, err := svc.Check(edgeAsked(srcPerson, "3", ""), sshCheck("user:"+srcPerson)); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if got := rec.callCount(); got != 0 {
		t.Errorf("без ссылки хранилище спрошено %d раз — так служба подставляла бы сессию личности", got)
	}
	assertNoEvidence(t, m.lastCondCtx)
}

// Ф11-43/-44 на уровне провязки: запись не годна (не жива либо чужая) —
// хранилище отвечает «не найдено», и доводов нет, как у вопроса без сессии.
func TestF11_43_44_UnfitRecordGivesNoEvidence(t *testing.T) {
	m := &mockRelations{checkResp: true}
	rec := &fakeSessionRecords{found: false}
	svc := newEvidenceService(m, rec)

	if _, err := svc.Check(edgeAsked(srcPerson, "3", srcSession), sshCheck("user:"+srcPerson)); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if rec.callCount() != 1 {
		t.Fatalf("хранилище не спрошено — проба не о том")
	}
	assertNoEvidence(t, m.lastCondCtx)
}

// Вопрос о ДРУГОМ субъекте: доводы о сессии вызывающего не описывают
// аутентификацию субъекта вопроса, и хранилище не спрашивается.
func TestSessionEvidence_QuestionAboutAnotherSubjectGetsNone(t *testing.T) {
	m := &mockRelations{checkResp: true}
	rec := &fakeSessionRecords{rec: keySession(), found: true}
	svc := newEvidenceService(m, rec)

	if _, err := svc.Check(edgeAsked(srcPerson, "3", srcSession), sshCheck("user:usr-someoneelse00001")); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if got := rec.callCount(); got != 0 {
		t.Errorf("вопрос о другом субъекте спросил хранилище %d раз", got)
	}
	assertNoEvidence(t, m.lastCondCtx)

	// Близнец: тот же вопрос о себе — хранилище спрошено. Без него отрицание
	// зеленело бы на службе, которая не спрашивает никогда.
	if _, err := svc.Check(edgeAsked(srcPerson, "3", srcSession), sshCheck("user:"+srcPerson)); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if got := rec.callCount(); got != 1 {
		t.Errorf("вопрос о себе спросил хранилище %d раз, ожидался один", got)
	}
}

// Личность не доверена — ссылки как будто нет.
func TestSessionEvidence_UntrustedPrincipalGetsNone(t *testing.T) {
	m := &mockRelations{checkResp: true}
	rec := &fakeSessionRecords{rec: keySession(), found: true}
	svc := newEvidenceService(m, rec)

	ctx := grpcsrv.WithTrustedPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: srcPerson}, false)
	ctx = callerorigin.WithSessionID(ctx, srcSession)
	if _, err := svc.Check(ctx, sshCheck("user:"+srcPerson)); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if got := rec.callCount(); got != 0 {
		t.Errorf("недоверенная личность спросила хранилище %d раз", got)
	}
	assertNoEvidence(t, m.lastCondCtx)
}

// Вопрос об отношении без условия хранилища не спрашивает: доводы способов и
// момента читает только условие, и цена записи на каждом вопросе края была бы
// платой ни за что.
func TestSessionEvidence_UnconditionedQuestionDoesNotReadTheRecord(t *testing.T) {
	m := &mockRelations{checkResp: true}
	rec := &fakeSessionRecords{rec: keySession(), found: true}
	svc := newEvidenceService(m, rec)

	_, err := svc.Check(edgeAsked(srcPerson, "3", srcSession), CheckRequest{
		Subject:  "user:" + srcPerson,
		Resource: ResourceRef{Type: "vpc_network", ID: "vpcn_x"},
		Action:   "vpc.networks.update",
	})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if got := rec.callCount(); got != 0 {
		t.Errorf("вопрос без условия спросил хранилище %d раз", got)
	}
}

// Хранилище не ответило — это незнание, а не отказ: вопрос кончается
// недоступностью, а не «прав нет».
func TestSessionEvidence_StoreFailureIsUnavailableNotDeny(t *testing.T) {
	m := &mockRelations{checkResp: true}
	rec := &fakeSessionRecords{err: errors.New("pool closed")}
	svc := newEvidenceService(m, rec)

	_, err := svc.Check(edgeAsked(srcPerson, "3", srcSession), sshCheck("user:"+srcPerson))
	if !errors.Is(err, iamerr.ErrUnavailable) {
		t.Fatalf("ошибка %v, ожидалась недоступность (iamerr.ErrUnavailable)", err)
	}
	if m.checkCalls != 0 {
		t.Errorf("решающая сторона спрошена %d раз без доводов, которые не удалось прочесть", m.checkCalls)
	}
}

// Ф11-39 на уровне провязки: тело вопроса доводов не даёт и при найденной
// записи — значения записи, а не тела.
func TestF11_39_BodyDoesNotOverrideTheRecord(t *testing.T) {
	m := &mockRelations{checkResp: true}
	rec := &fakeSessionRecords{rec: keySession(), found: true}
	svc := newEvidenceService(m, rec)

	req := sshCheck("user:" + srcPerson)
	req.Context = map[string]any{"amr_claims": []any{"password"}, "mfa_at": srcT0.Add(-time.Hour).Unix()}
	if _, err := svc.Check(edgeAsked(srcPerson, "3", srcSession), req); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if got := m.lastCondCtx["mfa_at"]; got != srcT0.Unix() {
		t.Errorf("mfa_at = %v, ожидался момент записи %d — тело вопроса читаться не должно", got, srcT0.Unix())
	}
}

// Партия: один вопрос к хранилищу на проход, и каждый условный пункт получает
// доводы.
func TestSessionEvidence_BatchReadsTheRecordOnce(t *testing.T) {
	m := &mockRelations{checkResp: true}
	rec := &fakeSessionRecords{rec: keySession(), found: true}
	svc := newEvidenceService(m, rec)

	reqs := []CheckRequest{sshCheck("user:" + srcPerson), sshCheck("user:" + srcPerson)}
	reqs[1].Resource.ID = "ins-y"
	res, err := svc.BatchCheck(edgeAsked(srcPerson, "3", srcSession), reqs)
	if err != nil {
		t.Fatalf("BatchCheck: %v", err)
	}
	for i, r := range res {
		if !r.Allowed {
			t.Errorf("пункт %d: отказ %v", i, r.DenyReasons)
		}
	}
	if got := rec.callCount(); got != 1 {
		t.Errorf("партия спросила хранилище %d раз, ожидался один вопрос на проход", got)
	}
	if got := m.lastCondCtx["mfa_at"]; got != srcT0.Unix() {
		t.Errorf("партия: mfa_at = %v, ожидался %d", got, srcT0.Unix())
	}
}

func assertNoEvidence(t *testing.T, cc map[string]any) {
	t.Helper()
	if cc == nil {
		t.Fatal("решающая сторона не спрошена — проба не о том")
	}
	for _, k := range []string{"amr_claims", "mfa_at"} {
		if v, ok := cc[k]; ok {
			t.Errorf("довод %q = %v доехал без годной записи сессии вопроса", k, v)
		}
	}
}
