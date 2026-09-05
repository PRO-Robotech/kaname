// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

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

	in := IssueInput{ServiceAccountID: "sva_test000000000000", CreatedByUserID: "usr_admin00000000000"}
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

	in := IssueInput{ServiceAccountID: "sva_test000000000000", CreatedByUserID: "usr_admin00000000000"}
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

	in := IssueInput{ServiceAccountID: "sva_test000000000000", CreatedByUserID: "usr_admin00000000000"}
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

	in := IssueInput{ServiceAccountID: "sva_test000000000000", CreatedByUserID: "usr_admin00000000000"}
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

// TestIssue_OwnIssuance_FederatedLeavesTheProviderToo — ГРАНИЦА СНЯТА РЕШЕНИЕМ
// (задача #1124), и проба перевёрнута вслед за ним.
//
// # Что здесь стояло раньше и почему это было верно
//
// Прежняя редакция утверждала обратное: федеративный ключ ОБЯЗАН заводить
// зеркало у прежнего издателя и регистрировать у него доверие. Довод был
// такой — ключевого материала федеративный ключ не несёт, своей полосы обмена у
// него нет by construction, а перечень доверенных издателей ведёт поставщик;
// снять зеркало значило снять возможность целиком. Проба держала границу
// намеренно, «чтобы её сняли решением, а не правкой соседней ветки».
//
// # Почему она перевёрнута
//
// Оба довода истекли вместе со своим предметом. Полоса обмена появилась:
// проверяющий утверждение получил федеративную полосу, которая берёт ключ у
// ЗАПИСИ ДОВЕРИЯ, а не у строки клиента. Перечень стал нашей таблицей и
// пишется в той же транзакции, что строка ключа. Значит на переведённом контуре
// федеративному ключу зеркало не нужно ровно так же, как ключу с ключевым
// материалом.
//
// Проба утверждает ОБЕ стороны: переведённый контур зеркала не заводит,
// непереведённый — заводит, как прежде. Односторонняя зеленела бы на выдаче, не
// обращающейся к поставщику ни при какой посадке.
func TestIssue_OwnIssuance_FederatedLeavesTheProviderToo(t *testing.T) {
	// (а) контур ПЕРЕВЕДЁН — зеркала нет, имя клиента наше.
	repo := &stubSAClientRepo{}
	hydra := &stubHydra{}
	ops := &stubOpsRepo{}
	uc := NewIssueSAKeyUseCase(repo, &stubTx{}, hydra, ops).
		WithTrustedIssuerWriter(&fakeTrustedIssuers{}).
		WithOwnIssuance()

	if _, err := uc.Execute(context.Background(), trustedIssuerInput()); err != nil {
		t.Fatalf("Execute (sync): %v", err)
	}
	waitForOp(t, ops)

	if hydra.created {
		t.Error("переведённый контур завёл зеркало федеративного ключа: обменивать его " +
			"у прежнего издателя больше не требуется — утверждение проверяет наша полоса")
	}
	if !repo.insertOK {
		t.Fatal("строка ключа обязана быть записана")
	}
	if string(repo.inserted.OAuthClientID) != string(repo.inserted.ID) {
		t.Errorf("клиент назван %q, а строка — %q: на переведённом контуре имя назначаем мы",
			repo.inserted.OAuthClientID, repo.inserted.ID)
	}

	// (б) контур НЕ переведён — зеркало заводится ровно как прежде. Без этой
	// половины утверждение выше зеленело бы на выдаче, сломанной целиком.
	repo2 := &stubSAClientRepo{}
	hydra2 := &stubHydra{}
	ops2 := &stubOpsRepo{}
	uc2 := NewIssueSAKeyUseCase(repo2, &stubTx{}, hydra2, ops2).
		WithTrustedIssuerWriter(&fakeTrustedIssuers{})

	if _, err := uc2.Execute(context.Background(), trustedIssuerInput()); err != nil {
		t.Fatalf("Execute (sync): %v", err)
	}
	waitForOp(t, ops2)

	if !hydra2.created {
		t.Error("непереведённый контур обязан заводить зеркало ровно как прежде")
	}
}
