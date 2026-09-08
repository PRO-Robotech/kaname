// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// usecase_compensation_durability_test.go — компенсация частично исполненной
// саги «зарегистрировать клиента у провайдера → записать свою строку».
//
// Предмет. Клиент у провайдера создаётся ДО того, как своя строка закоммичена
// (строка обязана нести client_id, который назначает провайдер). Если коммит не
// прошёл, зарегистрированного клиента надо снять — и снять НАДЁЖНО: провал
// самого снятия оставляет у провайдера объект, о котором в нашей БД нет ни
// одной записи, поэтому назвать его потом нечем и убрать некому.
//
// Пробы утверждают ИСХОД, а не факт вызова: после неудачного коммита в дереве
// обязано остаться durable компенсирующее намерение — даже когда прямой вызов
// снятия провалился. Парный положительный контроль: успешная сага не оставляет
// компенсирующего намерения (иначе дренаж снёс бы живого клиента).
package sa_keys

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/clients"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/service"
)

// failingInsertRepo — репозиторий, чей Insert отказывает (канонический повод:
// имя занято). Остальные методы не вызываются на этом пути.
type failingInsertRepo struct {
	stubSAClientRepo
	insertErr error
}

func (r *failingInsertRepo) Insert(
	_ context.Context, _ service.Tx, _ domain.ServiceAccountOAuthClient,
) (domain.ServiceAccountOAuthClient, error) {
	return domain.ServiceAccountOAuthClient{}, r.insertErr
}

// hydraCreateOKDeleteFails — провайдер, у которого регистрация проходит, а
// снятие отказывает (провайдер прилёг ровно в окне компенсации).
type hydraCreateOKDeleteFails struct {
	mu          sync.Mutex
	clientID    string
	deleteCalls int
	deleteErr   error
}

func (h *hydraCreateOKDeleteFails) CreateOAuthClient(
	_ context.Context, _ clients.CreateOAuthClientRequest,
) (clients.HydraOAuthClient, error) {
	return clients.HydraOAuthClient{ClientID: h.clientID}, nil
}

func (h *hydraCreateOKDeleteFails) DeleteOAuthClient(_ context.Context, _ string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.deleteCalls++
	return h.deleteErr
}

func (h *hydraCreateOKDeleteFails) calls() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.deleteCalls
}

// recordingCompensation — durable-приёмник компенсирующих намерений.
type recordingCompensation struct {
	mu      sync.Mutex
	emitted []string
	err     error
}

func (c *recordingCompensation) EmitHydraClientDelete(
	_ context.Context, clientID, _, _ string,
) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return c.err
	}
	c.emitted = append(c.emitted, clientID)
	return nil
}

// EmitTrustGrantDelete — вторая половина порта: намерение снять выданное
// доверие. Записывается в тот же список: пробам важно, ЧТО намерение
// зафиксировано, а предмет каждого называет его же идентификатор.
func (c *recordingCompensation) EmitTrustGrantDelete(
	_ context.Context, grantID, _, _ string,
) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return c.err
	}
	c.emitted = append(c.emitted, grantID)
	return nil
}

func (c *recordingCompensation) snapshot() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.emitted...)
}

// federatedInput — вход, идущий по ветке без генерации ключевого материала
// (ветка та же по составу саги: регистрация у провайдера → коммит своей строки).
func federatedInput() IssueInput {
	return IssueInput{
		ServiceAccountID: "sva_test000000000000",
		CreatedByUserID:  "usr_admin00000000000",
		TrustedSubjects: []domain.TrustedSubject{
			{
				Issuer:         "https://token.actions.githubusercontent.com",
				SubjectPattern: "^repo:acme/infra:ref:refs/heads/main$",
				PublicKeyPEM:   testIssuerPublicKeyPEM,
				KeyAlgorithm:   "ES256",
			},
		},
	}
}

// TestIssueSAKey_CommitFails_AndProviderDeleteFails_LeavesDurableCompensation —
// главное утверждение. Коммит своей строки не прошёл, прямое снятие у
// провайдера тоже не прошло: без durable намерения клиент остаётся у провайдера
// навсегда и его нечем назвать.
func TestIssueSAKey_CommitFails_AndProviderDeleteFails_LeavesDurableCompensation(t *testing.T) {
	repo := &failingInsertRepo{insertErr: errors.New("insert failed")}
	hydra := &hydraCreateOKDeleteFails{
		clientID:  "hydra-cli-orphan",
		deleteErr: errors.New("provider unreachable"),
	}
	comp := &recordingCompensation{}
	ops := &stubOpsRepo{}

	u := NewIssueSAKeyUseCase(repo, &stubTx{}, hydra, ops).
		WithCompensationEmitter(comp).
		WithTrustedIssuerWriter(&fakeTrustedIssuers{})

	if _, err := u.Execute(context.Background(), federatedInput()); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	waitForOp(t, ops)

	got := comp.snapshot()
	if len(got) != 1 {
		t.Fatalf("компенсирующих намерений записано %d, ожидалось 1 "+
			"(клиент %q зарегистрирован у провайдера, своя строка не закоммичена, "+
			"прямое снятие отказало — реклеймить его нечем)", len(got), hydra.clientID)
	}
	if got[0] != hydra.clientID {
		t.Fatalf("намерение записано на %q, ожидалось %q", got[0], hydra.clientID)
	}
}

// TestIssueSAKey_CommitFails_CompensationEmitFails_FallsBackToDirectRelease —
// приёмник намерений сам недоступен: путь обязан деградировать в прямой вызов
// снятия, а не молчать. Хуже прежнего быть нельзя.
func TestIssueSAKey_CommitFails_CompensationEmitFails_FallsBackToDirectRelease(t *testing.T) {
	repo := &failingInsertRepo{insertErr: errors.New("insert failed")}
	hydra := &hydraCreateOKDeleteFails{clientID: "hydra-cli-orphan-2"}
	comp := &recordingCompensation{err: errors.New("outbox unavailable")}
	ops := &stubOpsRepo{}

	u := NewIssueSAKeyUseCase(repo, &stubTx{}, hydra, ops).
		WithCompensationEmitter(comp).
		WithTrustedIssuerWriter(&fakeTrustedIssuers{})

	if _, err := u.Execute(context.Background(), federatedInput()); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	waitForOp(t, ops)

	if hydra.calls() == 0 {
		t.Fatal("приёмник намерений отказал, и прямого снятия у провайдера не было — " +
			"клиент остался и о нём нет ни строки, ни намерения")
	}
}

// TestIssueSAKey_Success_EmitsNoCompensation — парный положительный контроль.
// Успешная сага не оставляет компенсирующего намерения: иначе дренаж снял бы
// живого клиента, и «проверка» была бы вредна, а не бесполезна.
func TestIssueSAKey_Success_EmitsNoCompensation(t *testing.T) {
	repo := &stubSAClientRepo{}
	hydra := &hydraCreateOKDeleteFails{clientID: "hydra-cli-live"}
	comp := &recordingCompensation{}
	ops := &stubOpsRepo{}

	u := NewIssueSAKeyUseCase(repo, &stubTx{}, hydra, ops).
		WithCompensationEmitter(comp).
		WithTrustedIssuerWriter(&fakeTrustedIssuers{})

	if _, err := u.Execute(context.Background(), federatedInput()); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	waitForOp(t, ops)

	if got := comp.snapshot(); len(got) != 0 {
		t.Fatalf("успешная сага записала компенсирующие намерения %v — дренаж снял бы живого клиента", got)
	}
	if hydra.calls() != 0 {
		t.Fatalf("успешная сага звала снятие у провайдера %d раз", hydra.calls())
	}
}
