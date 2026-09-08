// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// usecase_provider_mirror_test.go — выдача персонального токена не заводит
// зеркала у поставщика (задача #1121, подфаза Ф4б-3 эпика #896).
//
// # ЧТО ЗДЕСЬ УТВЕРЖДАЕТСЯ — И ЧЕГО НАМЕРЕННО НЕ УТВЕРЖДАЕТСЯ
//
// «Функция не вызвана» утверждением НЕ является: она зелена на реализации,
// которая зовёт поставщика другим способом, и краснеет на переименовании порта.
// Утверждается НАБЛЮДАЕМОЕ — то, что вызывающий получает на руки:
//
//   - идентификатор клиента в ответе выдачи ЕСТЬ идентификатор строки нашего
//     реестра. Именно им подписывается `client_assertion`, и именно его
//     разрешает наш реестр (`AssertionClientRepo`, разрешение идёт по `c.id`).
//     Пока в этом поле стоял идентификатор поставщика, вызывающий получал имя,
//     которое наш издатель не разрешает НИ ПРИ КАКОМ входе;
//   - у выданного токена нет зеркала: поле зеркала в ответе пусто, и пусто оно
//     в строке, которую положила запись.
//
// Положительный контроль стоит рядом с каждым отрицанием: пустое зеркало зелено
// и на реализации, которая не выдала вообще ничего, поэтому те же пробы
// требуют непустого приватного ключа, непустого идентификатора и совпадения
// `key_id` со строкой реестра.
package user_tokens

import (
	"context"
	"testing"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kaname/cloud/iam/v1"
)

// newIssueUCForTest — сборка use-case выдачи для проб этого файла. Существует
// затем, чтобы УТВЕРЖДЕНИЯ ниже были дословно одни и те же до правки и после:
// правка сняла у выдачи порт администрирования клиентов поставщика, то есть
// изменила форму сборки, а не то, что проверяется. Красный прогон до правки
// собирался этой же функцией с прежней сигнатурой.
func newIssueUCForTest(repo *stubUserClientRepo, ops *stubOpsRepo) *IssueUserTokenUseCase {
	return NewIssueUserTokenUseCase(repo, &stubTx{}, ops)
}

// TestIssue_CredentialCarriesOneName — у выданного удостоверения ОДНО имя, и
// это имя строки нашего реестра.
func TestIssue_CredentialCarriesOneName(t *testing.T) {
	repo := &stubUserClientRepo{}
	ops := &stubOpsRepo{}
	uc := newIssueUCForTest(repo, ops)

	_, err := uc.Execute(context.Background(), IssueInput{
		UserID:          "usr00000000000000001",
		Description:     "laptop CLI",
		CreatedByUserID: "usr00000000000000001",
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	waitForOp(t, ops)
	if ops.lastErr != nil {
		t.Fatalf("worker error: %v", ops.lastErr)
	}

	var resp iamv1.IssueUserTokenResponse
	if err := ops.lastResp.UnmarshalTo(&resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	tok := resp.GetToken()
	if tok == nil {
		t.Fatal("response carries no token")
	}
	// Положительный контроль: выдача действительно состоялась.
	if resp.GetPrivateKeyPem() == "" {
		t.Fatal("private_key_pem пуст — выдачи не было, и всё нижеследующее зелено вакуумно")
	}
	if tok.GetId() == "" {
		t.Fatal("token.id пуст — сравнивать не с чем")
	}
	if got, want := resp.GetClientId(), tok.GetId(); got != want {
		t.Errorf("client_id = %q, ожидается идентификатор строки реестра %q: "+
			"этим именем подписывается client_assertion, и только его разрешает наш реестр", got, want)
	}
	if got, want := resp.GetKeyId(), tok.GetId(); got != want {
		t.Errorf("key_id = %q, ожидается %q", got, want)
	}
}

// TestIssue_LeavesNoProviderMirror — зеркала у поставщика нет ни в ответе, ни в
// строке, которую положила запись.
func TestIssue_LeavesNoProviderMirror(t *testing.T) {
	repo := &stubUserClientRepo{}
	ops := &stubOpsRepo{}
	uc := newIssueUCForTest(repo, ops)

	_, err := uc.Execute(context.Background(), IssueInput{
		UserID:          "usr00000000000000001",
		CreatedByUserID: "usr00000000000000001",
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	waitForOp(t, ops)
	if ops.lastErr != nil {
		t.Fatalf("worker error: %v", ops.lastErr)
	}

	// Положительный контроль: строка вообще была положена.
	if repo.inserted.ID == "" {
		t.Fatal("запись не положила строку — утверждение о пустом зеркале было бы вакуумным")
	}
	if repo.inserted.PublicKeyPEM == "" {
		t.Fatal("в строке нет открытого ключа — удостоверение не заведено")
	}
	if got := string(repo.inserted.OAuthClientID); got != "" {
		t.Errorf("строка несёт зеркало поставщика %q — выдача завела клиента там, где его быть не должно", got)
	}

	var resp iamv1.IssueUserTokenResponse
	if err := ops.lastResp.UnmarshalTo(&resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if got := resp.GetToken().GetHydraClientId(); got != "" {
		t.Errorf("ответ объявляет зеркало поставщика %q — его не существует", got)
	}
}
