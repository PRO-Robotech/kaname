// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// check_basic_credential_live_test.go — ГЛАГОЛ ЖИВОСТИ ПО ИДЕНТИФИКАТОРУ
// (задача #1450).
//
// Здесь утверждается то, что видит ВЫЗЫВАЮЩИЙ: код, текст и — отдельно — что по
// различию отказов нельзя узнать про чужое удостоверение ничего. Согласие
// полосы идентификатора с полосой секрета на живых строках утверждает
// интеграционная проба у репозитория; здесь его подделать нечем.

package internal_iam

import (
	"context"
	"errors"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kaname/cloud/iam/v1"
	"github.com/PRO-Robotech/kacho/pkg/credsecret"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// mintedPresentedForTest — предъявляемая строка того же вида, что чеканит
// продукт. Своей копии формата здесь не заводится: второй кодек разошёлся бы с
// первым молча, и проба «полную строку не принимаем» проверяла бы не тот вход.
func mintedPresentedForTest(t *testing.T, credentialID string) string {
	t.Helper()
	presented, _, err := credsecret.Mint(credentialID)
	if err != nil {
		t.Fatalf("чеканка предъявляемой строки не удалась: %v", err)
	}
	return presented
}

// basicAuthorityStub — дублёр авторитета. Считает вызовы: проба стоимости
// обязана видеть, что мусор до соседа не доезжает.
type basicAuthorityStub struct {
	live     error
	liveArg  string
	liveHits int
}

func (s *basicAuthorityStub) ResolveBasic(context.Context, string) (domain.BasicCredential, error) {
	return domain.BasicCredential{}, domain.ErrBasicCredentialRefused
}

func (s *basicAuthorityStub) TouchLastUsed(context.Context, string, time.Duration) error { return nil }

func (s *basicAuthorityStub) CheckBasicLive(_ context.Context, credentialID string) error {
	s.liveHits++
	s.liveArg = credentialID
	return s.live
}

// TestBCL1450_LiveCredentialAnswersOkAndSaysNothingElse — живое даёт `OK`, и
// ответ ПУСТ. Пустота — решение: любое поле здесь было бы сведениями, добытыми
// по идентификатору без предъявления секрета.
func TestBCL1450_LiveCredentialAnswersOkAndSaysNothingElse(t *testing.T) {
	auth := &basicAuthorityStub{live: nil}
	h := (&Handler{}).WithBasicCredentialResolver(auth)

	resp, err := h.CheckBasicCredentialLive(context.Background(),
		&iamv1.CheckBasicCredentialLiveRequest{CredentialId: "uoc_0000000000000live"})
	if err != nil {
		t.Fatalf("живое удостоверение отвергнуто: %v", err)
	}
	if resp == nil {
		t.Fatal("ответ nil при отсутствии ошибки — вызывающий не отличит его от отказа")
	}
	if n := resp.ProtoReflect().Descriptor().Fields().Len(); n != 0 {
		t.Errorf("ответ несёт %d полей: сведения о чужом удостоверении, добытые по одному "+
			"идентификатору, — это оракул; пустота ответа была решением", n)
	}
	if auth.liveHits != 1 || auth.liveArg != "uoc_0000000000000live" {
		t.Errorf("авторитет спрошен %d раз про %q — ожидался один вопрос про названный идентификатор",
			auth.liveHits, auth.liveArg)
	}
}

// TestBCL1450_RefusalIsSingleAndMatchesTheResolveLane — неживое даёт
// UNAUTHENTICATED с ТЕМ ЖЕ текстом, что полоса резолва. Два написания одного
// отказа разошлись бы, и по различию узнавали бы, какой полосой спрашивали.
func TestBCL1450_RefusalIsSingleAndMatchesTheResolveLane(t *testing.T) {
	auth := &basicAuthorityStub{live: domain.ErrBasicCredentialRefused}
	h := (&Handler{}).WithBasicCredentialResolver(auth)

	_, err := h.CheckBasicCredentialLive(context.Background(),
		&iamv1.CheckBasicCredentialLiveRequest{CredentialId: "uoc_0000000000000gone"})
	st, _ := status.FromError(err)
	if st.Code() != codes.Unauthenticated {
		t.Fatalf("код отказа %s, ожидался Unauthenticated", st.Code())
	}
	if st.Message() != refusalText {
		t.Errorf("текст отказа %q, у полосы резолва %q — по различию узнают полосу", st.Message(), refusalText)
	}

	// Пустой идентификатор — ТОТ ЖЕ отказ, и авторитет не спрашивается: мусор не
	// оплачивается вызовом к соседу.
	auth.liveHits = 0
	_, err = h.CheckBasicCredentialLive(context.Background(),
		&iamv1.CheckBasicCredentialLiveRequest{CredentialId: ""})
	st, _ = status.FromError(err)
	if st.Code() != codes.Unauthenticated || st.Message() != refusalText {
		t.Errorf("пустой идентификатор дал %s/%q — отказ перестал быть единым", st.Code(), st.Message())
	}
	if auth.liveHits != 0 {
		t.Errorf("пустой идентификатор доехал до авторитета (%d вызовов) — мусор оплачен вопросом", auth.liveHits)
	}
}

// TestBCL1450_PresentedStringNeverReachesTheAuthority — полная предъявленная
// строка в поле идентификатора отвергается ДО вопроса соседу.
//
// Поле идентификатора не помечено носителем секрета: секрета в нём не бывает.
// Приняв полную строку, глагол сделал бы это утверждение ложным.
func TestBCL1450_PresentedStringNeverReachesTheAuthority(t *testing.T) {
	auth := &basicAuthorityStub{live: nil}
	h := (&Handler{}).WithBasicCredentialResolver(auth)

	// Строка, разбираемая как предъявленная (id + секрет + контрольная сумма).
	presented := mintedPresentedForTest(t, "uoc_0000000000000full")

	_, err := h.CheckBasicCredentialLive(context.Background(),
		&iamv1.CheckBasicCredentialLiveRequest{CredentialId: presented})
	st, _ := status.FromError(err)
	if st.Code() != codes.Unauthenticated || st.Message() != refusalText {
		t.Errorf("предъявленная строка дала %s/%q — ожидался единый отказ", st.Code(), st.Message())
	}
	if auth.liveHits != 0 {
		t.Errorf("предъявленная строка доехала до авторитета (%d вызовов) — секрет уехал дальше поля, "+
			"которое никто не обязан беречь", auth.liveHits)
	}

	// Положительный контроль: голый идентификатор доезжает и проходит.
	if _, err := h.CheckBasicCredentialLive(context.Background(),
		&iamv1.CheckBasicCredentialLiveRequest{CredentialId: "uoc_0000000000000full"}); err != nil {
		t.Fatalf("голый идентификатор отвергнут (%v) — отрицание выше верно и о глаголе, отвергающем всё", err)
	}
}

// TestBCL1450_UnavailableAuthorityIsItsOwnOutcomeAndLeaksNothing — «спросить не
// удалось» НЕ подменяется отказом в удостоверении: вызывающему нечего исправить
// сменой удостоверения. Сырой текст соседа наружу не течёт.
func TestBCL1450_UnavailableAuthorityIsItsOwnOutcomeAndLeaksNothing(t *testing.T) {
	const raw = "dial tcp 10.42.0.7:5432: connect: connection refused (user=kaname db=kaname)"
	auth := &basicAuthorityStub{live: errors.New(raw)}
	h := (&Handler{}).WithBasicCredentialResolver(auth)

	_, err := h.CheckBasicCredentialLive(context.Background(),
		&iamv1.CheckBasicCredentialLiveRequest{CredentialId: "uoc_0000000000000live"})
	st, _ := status.FromError(err)
	if st.Code() != codes.Unavailable {
		t.Fatalf("код %s, ожидался Unavailable: недоступность авторитета — не отказ в удостоверении", st.Code())
	}
	if st.Message() == raw || contains(st.Message(), "5432") || contains(st.Message(), "kaname") {
		t.Errorf("наружу утёк текст соседа: %q", st.Message())
	}
}

// TestBCL1450_UnwiredAuthorityFailsClosed — непровязанный авторитет даёт
// Unavailable, а НЕ «живо». Непровязанный контроль не есть «да».
func TestBCL1450_UnwiredAuthorityFailsClosed(t *testing.T) {
	h := &Handler{}
	_, err := h.CheckBasicCredentialLive(context.Background(),
		&iamv1.CheckBasicCredentialLiveRequest{CredentialId: "uoc_0000000000000live"})
	st, _ := status.FromError(err)
	if st.Code() != codes.Unavailable {
		t.Fatalf("непровязанный авторитет дал %s — ожидался Unavailable (fail-closed)", st.Code())
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
