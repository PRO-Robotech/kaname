// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// usecase_own_issuance_test.go — выдача ключа служебной учётки на ПЕРЕВЕДЁННОМ
// контуре не заводит зеркала клиента у прежнего издателя (задача #1120,
// подфаза Ф4б эпика #896).
//
// # Предмет
//
// Зеркало нужно ровно затем, чтобы выданный ключ можно было обменять У
// ПРЕЖНЕГО ИЗДАТЕЛЯ. Своя полоса обмена клиента по зеркальному значению не
// ищет: реестр утверждений резолвит строку по НАШЕМУ идентификатору, и
// зеркальная колонка на том пути не участвует вовсе
// (`repo/kacho/pg/assertion_client_repo.go`).
//
// Значит на переведённом контуре зеркало — запись у постороннего, которую
// никто не читает, при живой административной дороге к нему.
//
// # Что здесь утверждается
//
// ИСХОД, а не факт вызова: у прежнего издателя не заведено НИЧЕГО, а
// идентификатор, которым клиент себя называет, — наш. Проба «функция не
// вызвана» осталась бы зелёной на реализации, которая зовёт издателя другим
// путём; проба «поле не пусто» — на реализации, положившей туда что угодно.
//
// Рядом ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ на каждой оси: непереведённый контур заводит
// зеркало ровно как прежде. Без него отрицание зеленело бы на сборке, снявшей
// зеркало со ВСЕХ посадок, — а пока подписант не подключён, прежний издатель
// остаётся единственным производителем токена для этого ключа.
package sa_keys

import (
	"context"
	"errors"
	"testing"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
)

// TestIssue_OwnIssuance_RegistersNothingAtTheProvider — главное утверждение.
func TestIssue_OwnIssuance_RegistersNothingAtTheProvider(t *testing.T) {
	repo := &stubSAClientRepo{}
	hydra := &stubHydra{}
	ops := &stubOpsRepo{}

	uc := NewIssueSAKeyUseCase(repo, &stubTx{}, hydra, ops).WithOwnIssuance()

	in := IssueInput{ServiceAccountID: "sva_test", CreatedByUserID: "usr_admin"}
	if _, err := uc.Execute(context.Background(), in); err != nil {
		t.Fatalf("Execute (sync): %v", err)
	}
	waitForOp(t, ops)

	if ops.lastErr != nil {
		t.Fatalf("выдача обязана состояться без прежнего издателя, получено: %v", ops.lastErr)
	}
	if hydra.created {
		t.Error("переведённый контур завёл зеркало у прежнего издателя: запись у постороннего, " +
			"которую своя полоса обмена не читает, при живой административной дороге к нему")
	}
	if !repo.insertOK {
		t.Fatal("предпосылка: своя строка обязана быть закоммичена")
	}

	// Идентификатор, которым клиент себя называет, — НАШ. Именно им подписанное
	// утверждение назовёт себя (`iss`/`sub`), и именно его резолвит реестр.
	if got, want := string(repo.inserted.OAuthClientID), string(repo.inserted.ID); got != want {
		t.Errorf("строка называет клиента %q, а наш идентификатор %q: второе имя у клиента "+
			"переведённого контура не появляется — его некому назначить", got, want)
	}

	var resp iamv1.IssueSAKeyResponse
	if err := anyUnmarshalTo(ops.lastResp, &resp); err != nil {
		t.Fatalf("ответ операции: %v", err)
	}
	if resp.GetClientId() != resp.GetKeyId() {
		t.Errorf("ответ называет клиента %q при ключе %q: предъявитель подписывает утверждение "+
			"ИМЕНЕМ КЛИЕНТА, и разойдись эти две величины — он назвал бы себя тем, чего в реестре нет",
			resp.GetClientId(), resp.GetKeyId())
	}
	if resp.GetPrivateKeyPem() == "" {
		t.Error("ключевой материал обязан быть выдан ровно как прежде")
	}
}

// TestIssue_ProviderContour_StillRegistersAtTheProvider — положительный
// контроль. Пока подписант не подключён, прежний издатель — ЕДИНСТВЕННЫЙ
// производитель токена на этом ключе, и зеркало обязано заводиться.
func TestIssue_ProviderContour_StillRegistersAtTheProvider(t *testing.T) {
	repo := &stubSAClientRepo{}
	hydra := &stubHydra{}
	ops := &stubOpsRepo{}

	uc := NewIssueSAKeyUseCase(repo, &stubTx{}, hydra, ops)

	in := IssueInput{ServiceAccountID: "sva_test", CreatedByUserID: "usr_admin"}
	if _, err := uc.Execute(context.Background(), in); err != nil {
		t.Fatalf("Execute (sync): %v", err)
	}
	waitForOp(t, ops)

	if !hydra.created {
		t.Fatal("непереведённый контур не завёл зеркала — обменять этот ключ станет негде")
	}
	if got := string(repo.inserted.OAuthClientID); got != "hydra-cli-fake" {
		t.Errorf("строка обязана нести идентификатор, назначенный издателем, несёт %q", got)
	}
}

// TestIssue_OwnIssuance_CommitFailure_CompensatesNothing — снимать у прежнего
// издателя нечего, потому что там ничего не заводили.
//
// Это не косметика: компенсирующее намерение доставляется дренажом и адресует
// СНЯТИЕ. Записанное на несуществующий предмет, оно занимает партию очереди и
// уходит к постороннему с просьбой снять то, чего он не заводил.
func TestIssue_OwnIssuance_CommitFailure_CompensatesNothing(t *testing.T) {
	repo := &failingInsertRepo{insertErr: errors.New("insert failed")}
	hydra := &hydraCreateOKDeleteFails{clientID: "hydra-cli-orphan"}
	comp := &recordingCompensation{}
	ops := &stubOpsRepo{}

	uc := NewIssueSAKeyUseCase(repo, &stubTx{}, hydra, ops).
		WithCompensationEmitter(comp).
		WithOwnIssuance()

	in := IssueInput{ServiceAccountID: "sva_test", CreatedByUserID: "usr_admin"}
	if _, err := uc.Execute(context.Background(), in); err != nil {
		t.Fatalf("Execute (sync): %v", err)
	}
	waitForOp(t, ops)

	if got := comp.snapshot(); len(got) != 0 {
		t.Errorf("записаны компенсирующие намерения %v при том, что у прежнего издателя "+
			"ничего не заводили", got)
	}
	if hydra.calls() != 0 {
		t.Errorf("прямое снятие у прежнего издателя звалось %d раз при том, что "+
			"регистрации не было", hydra.calls())
	}
}

// TestIssue_ProviderContour_CommitFailure_StillCompensates — парный
// положительный контроль к предыдущей: непереведённый контур по-прежнему
// снимает то, что успел завести.
func TestIssue_ProviderContour_CommitFailure_StillCompensates(t *testing.T) {
	repo := &failingInsertRepo{insertErr: errors.New("insert failed")}
	hydra := &hydraCreateOKDeleteFails{clientID: "hydra-cli-orphan"}
	comp := &recordingCompensation{}
	ops := &stubOpsRepo{}

	uc := NewIssueSAKeyUseCase(repo, &stubTx{}, hydra, ops).WithCompensationEmitter(comp)

	in := IssueInput{ServiceAccountID: "sva_test", CreatedByUserID: "usr_admin"}
	if _, err := uc.Execute(context.Background(), in); err != nil {
		t.Fatalf("Execute (sync): %v", err)
	}
	waitForOp(t, ops)

	got := comp.snapshot()
	if len(got) != 1 || got[0] != hydra.clientID {
		t.Fatalf("компенсирующих намерений записано %v, ожидалось ровно одно на %q",
			got, hydra.clientID)
	}
}

// TestIssue_OwnIssuance_FederatedStillRegistersAtTheProvider — ГРАНИЦА ЗАДАЧИ,
// названная пробой, а не умолчанием.
//
// Федеративный ключ не несёт ключевого материала вовсе, и наш проверяющий
// утверждения отвергает такого клиента отдельным исходом своего закрытого
// словаря («клиент не располагает зарегистрированным ключевым материалом»).
// Своей полосы обмена у него нет BY CONSTRUCTION, поэтому прежний издатель
// остаётся его единственной дорогой к токену — вместе с перечнем доверенных
// издателей, который сегодня ведёт он же.
//
// Перевод этой полосы — задача #1124 (перечень доверенных издателей становится
// нашей таблицей). Пока он не сделан, снятие зеркала здесь означало бы снять
// возможность целиком; проба держит границу, чтобы её сняли РЕШЕНИЕМ, а не
// правкой соседней ветки.
func TestIssue_OwnIssuance_FederatedStillRegistersAtTheProvider(t *testing.T) {
	repo := &stubSAClientRepo{}
	hydra := &stubHydra{}
	tg := &fakeTrustGrants{}
	ops := &stubOpsRepo{}

	uc := NewIssueSAKeyUseCase(repo, &stubTx{}, hydra, ops).
		WithTrustGrantAdmin(tg).
		WithOwnIssuance()

	if _, err := uc.Execute(context.Background(), federatedInput()); err != nil {
		t.Fatalf("Execute (sync): %v", err)
	}
	waitForOp(t, ops)

	if !hydra.created {
		t.Fatal("федеративный ключ остался без зеркала: обменять его негде — своей полосы " +
			"обмена у клиента без ключевого материала не существует (см. #1124)")
	}
	if len(tg.calls) != 1 {
		t.Fatalf("доверие издателю обязано быть зарегистрировано ровно как прежде, выдано %d", len(tg.calls))
	}
}
