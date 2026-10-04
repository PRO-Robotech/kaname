// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// usecase_one_client_name_test.go — у выданного персонального токена ОДНО имя
// клиента, и это идентификатор строки нашего реестра (задачи #1121, kaname#362).
//
// # ЧТО ЗДЕСЬ УТВЕРЖДАЕТСЯ
//
// «Функция не вызвана» утверждением НЕ является. Утверждается НАБЛЮДАЕМОЕ — то,
// что вызывающий получает на руки: идентификатор клиента в ответе выдачи ЕСТЬ
// идентификатор строки нашего реестра. Именно им подписывается
// `client_assertion`, и именно его разрешает наш реестр (`AssertionClientRepo`,
// разрешение идёт по `c.id`).
//
// Второго имени — у внешнего поставщика — у токена нет by construction:
// столбец, где оно лежало, и поле контракта сняты. Проба «зеркало пусто» снята
// вместе с ними: пустоту того, чего нет, утверждать нечем.
//
// Положительный контроль стоит рядом с утверждением: пробы требуют непустого
// приватного ключа, непустого идентификатора и совпадения `key_id` со строкой
// реестра.
package user_tokens

import (
	"context"
	"testing"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// newIssueUCForTest — сборка use-case выдачи для проб этого файла. Существует
// затем, чтобы УТВЕРЖДЕНИЯ ниже были дословно одни и те же до правки и после:
// правка сняла у выдачи порт администрирования клиентов поставщика, то есть
// изменила форму сборки, а не то, что проверяется. Красный прогон до правки
// собирался этой же функцией с прежней сигнатурой.
func newIssueUCForTest(repo *stubUserClientRepo, ops *stubOpsRepo) *IssueUserTokenUseCase {
	return NewIssueUserTokenUseCase(repo, &stubTx{}, ops).WithOwnIssuance()
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
