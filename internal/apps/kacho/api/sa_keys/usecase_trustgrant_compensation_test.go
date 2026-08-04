// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// usecase_trustgrant_compensation_test.go — частично выданное доверие обязано
// быть снято.
//
// # Предмет
//
// Выдача федеративного ключа регистрирует у провайдера доверие к КАЖДОМУ
// доверенному субъекту отдельным вызовом. Понятия «группа» у провайдера нет,
// отката веера — тоже: отказ на k-м обращении оставляет k-1 гранта стоять.
//
// Оставшийся грант — не висящая строка, а ВЫДАННОЕ ДОВЕРИЕ: провайдер
// продолжает принимать внешнее утверждение этого субъекта, хотя ключа, ради
// которого доверие выдавалось, в нашей базе нет — выдача-то провалилась.
//
// Убрать их было нечем дважды: идентификатор, который провайдер присваивает
// гранту, вызывающий выбрасывал, а метода снятия в клиенте провайдера не
// существовало вовсе. Утечка была необратима by construction, и комментарий
// рядом обещал откат, который касался только клиента.
//
// # Что здесь утверждается
//
// ИСХОД у провайдера: после неудачной выдачи ни один грант не остался. Проба на
// «вызвали снятие» осталась бы зелёной на реализации, которая зовёт снятие и
// игнорирует его отказ; проба на «эмитировали намерение» — на реализации,
// которая эмитирует намерение с предметом, которого принимающая сторона не
// поймёт.
package sa_keys

import (
	"context"
	"errors"
	"testing"
)

// TestIssue_Federated_PartialTrustGrantFanOut_WithdrawsWhatItGranted —
// положительный случай: отказ на втором из трёх снимает первый.
func TestIssue_Federated_PartialTrustGrantFanOut_WithdrawsWhatItGranted(t *testing.T) {
	repo := &stubSAClientRepo{}
	hydra := &recordingHydra{}
	tg := &fakeTrustGrants{err: errors.New("provider refused"), failAfter: 1}
	ops := &stubOpsRepo{}

	uc := NewIssueSAKeyUseCase(repo, &stubTx{}, hydra, ops).WithTrustGrantAdmin(tg)

	in := federatedInput()
	in.TrustedSubjects = append(in.TrustedSubjects, in.TrustedSubjects[0], in.TrustedSubjects[0])

	// Выдача асинхронна: Execute отдаёт Operation, а сага идёт в worker'е —
	// поэтому провал ждём на операции, а не на возврате Execute.
	if _, err := uc.Execute(context.Background(), in); err != nil {
		t.Fatalf("Execute (sync): %v", err)
	}
	waitForOp(t, ops)
	if repo.insertOK {
		t.Fatal("предпосылка: строка не смеет быть закоммичена при неполном доверии")
	}

	if len(tg.calls) != 1 {
		t.Fatalf("предпосылка пробы: ровно один грант обязан быть выдан до отказа, выдано %d", len(tg.calls))
	}
	// Ключевое утверждение: у провайдера не осталось ни одного гранта.
	if len(tg.deleted) != 1 || tg.deleted[0] != "grant-1" {
		t.Errorf("выданное доверие обязано быть снято, снято %v: пока грант стоит, "+
			"провайдер принимает внешнее утверждение субъекта при том, что ключа, "+
			"ради которого доверие выдавалось, не существует", tg.deleted)
	}
}

// TestIssue_Federated_SuccessfulFanOut_WithdrawsNothing — отрицание в паре с
// положительным: удачная выдача не смеет снимать ничего.
//
// Без этой пробы «компенсация», снимающая гранты всегда, осталась бы зелёной на
// предыдущей — и отнимала бы доверие у только что выданного рабочего ключа.
func TestIssue_Federated_SuccessfulFanOut_WithdrawsNothing(t *testing.T) {
	repo := &stubSAClientRepo{}
	hydra := &recordingHydra{}
	tg := &fakeTrustGrants{}
	ops := &stubOpsRepo{}

	uc := NewIssueSAKeyUseCase(repo, &stubTx{}, hydra, ops).WithTrustGrantAdmin(tg)

	in := federatedInput()
	in.TrustedSubjects = append(in.TrustedSubjects, in.TrustedSubjects[0])

	if _, err := uc.Execute(context.Background(), in); err != nil {
		t.Fatalf("удачная выдача: %v", err)
	}
	waitForOp(t, ops)
	if len(tg.calls) != 2 {
		t.Fatalf("предпосылка пробы: оба гранта обязаны быть выданы, выдано %d", len(tg.calls))
	}
	if len(tg.deleted) != 0 {
		t.Errorf("удачная выдача не смеет снимать доверие, снято %v", tg.deleted)
	}
	if hydra.deleted {
		t.Error("удачная выдача не смеет снимать клиента у провайдера")
	}
}

// TestIssue_Federated_PartialFanOut_PrefersDurableIntent — снятие идёт
// durable-намерением, а не вызовом «в надежде».
//
// Прямой вызов гарантией не является: отказал провайдер — отказать может и
// снятие, а процесс вправе умереть между отказом и уборкой. Пережившее рестарт
// намерение доставит дренаж. Проба утверждает выбор пути: намерение
// зафиксировано И прямого снятия не было.
func TestIssue_Federated_PartialFanOut_PrefersDurableIntent(t *testing.T) {
	repo := &stubSAClientRepo{}
	hydra := &recordingHydra{}
	tg := &fakeTrustGrants{err: errors.New("provider refused"), failAfter: 1}
	comp := &recordingCompensation{}
	ops := &stubOpsRepo{}

	uc := NewIssueSAKeyUseCase(repo, &stubTx{}, hydra, ops).
		WithTrustGrantAdmin(tg).
		WithCompensationEmitter(comp)

	in := federatedInput()
	in.TrustedSubjects = append(in.TrustedSubjects, in.TrustedSubjects[0])

	if _, err := uc.Execute(context.Background(), in); err != nil {
		t.Fatalf("Execute (sync): %v", err)
	}
	waitForOp(t, ops)

	emitted := comp.snapshot()
	var sawGrant bool
	for _, subject := range emitted {
		if subject == "grant-1" {
			sawGrant = true
		}
	}
	if !sawGrant {
		t.Errorf("намерение снять выданное доверие обязано быть durable, записано %v", emitted)
	}
	if len(tg.deleted) != 0 {
		t.Errorf("при записанном намерении прямое снятие излишне: доставит дренаж, снято %v", tg.deleted)
	}
}

// TestIssue_Federated_IntentUnrecordable_FallsBackToDirectWithdrawal — запасной
// путь. Намерение записать не удалось ⇒ снимаем прямо здесь.
//
// Без запасного пути отказ durable-приёмника означал бы, что доверие не снимет
// НИКТО, и это был бы тот же исход, что до всей правки, — только с ощущением,
// что механизм есть.
func TestIssue_Federated_IntentUnrecordable_FallsBackToDirectWithdrawal(t *testing.T) {
	repo := &stubSAClientRepo{}
	hydra := &recordingHydra{}
	tg := &fakeTrustGrants{err: errors.New("provider refused"), failAfter: 1}
	comp := &recordingCompensation{err: errors.New("outbox down")}
	ops := &stubOpsRepo{}

	uc := NewIssueSAKeyUseCase(repo, &stubTx{}, hydra, ops).
		WithTrustGrantAdmin(tg).
		WithCompensationEmitter(comp)

	in := federatedInput()
	in.TrustedSubjects = append(in.TrustedSubjects, in.TrustedSubjects[0])

	if _, err := uc.Execute(context.Background(), in); err != nil {
		t.Fatalf("Execute (sync): %v", err)
	}
	waitForOp(t, ops)
	if len(tg.deleted) != 1 || tg.deleted[0] != "grant-1" {
		t.Errorf("при незаписанном намерении снятие обязано пойти прямым вызовом, снято %v", tg.deleted)
	}
}
