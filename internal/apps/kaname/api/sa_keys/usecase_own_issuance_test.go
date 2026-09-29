// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// usecase_own_issuance_test.go — выданный ключ служебной учётки называется
// ОДНИМ именем — идентификатором своей строки (задачи kacho#1120, kaname#362).
//
// # Предмет
//
// Подписанное утверждение называет клиента (`iss`/`sub`), наш токен-эндпоинт
// резолвит его по идентификатору строки реестра, докерная полоса и отзыв
// адресуют ключ им же. Второго имени — назначенного прежним внешним издателем —
// у ключа нет: регистрация у него снята вместе со столбцом, где это имя лежало.
//
// # Что здесь утверждается
//
// ИСХОД, а не факт вызова: ответ называет клиента идентификатором строки, и то
// же значение несёт `key_id`; ключевой материал выдан; для каждого из двух
// обмениваемых видов. Отказ записи оставляет отказ операции, а не выдачу.
package sa_keys

import (
	"context"
	"errors"
	"testing"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/service"
)

// failingInsertRepo — репозиторий, чей Insert отказывает. Остальные методы на
// этом пути отвечают дублёром по умолчанию.
type failingInsertRepo struct {
	stubSAClientRepo
	insertErr error
}

func (r *failingInsertRepo) Insert(
	_ context.Context, _ service.Tx, _ domain.ServiceAccountOAuthClient,
) (domain.ServiceAccountOAuthClient, error) {
	return domain.ServiceAccountOAuthClient{}, r.insertErr
}

// TestIssue_OwnIssuance_ClientIsNamedByItsRowID — ключевая пара и федеративный
// ключ называются идентификатором своей строки.
func TestIssue_OwnIssuance_ClientIsNamedByItsRowID(t *testing.T) {
	for name, in := range map[string]IssueInput{
		"KEYPAIR":   {ServiceAccountID: "sva_test000000000000", CreatedByUserID: "usr_admin00000000000"},
		"FEDERATED": trustedIssuerInput(),
	} {
		t.Run(name, func(t *testing.T) {
			repo := &stubSAClientRepo{}
			ops := &stubOpsRepo{}
			uc := newOwnIssueUC(repo, ops)

			if _, err := uc.Execute(context.Background(), in); err != nil {
				t.Fatalf("Execute (sync): %v", err)
			}
			waitForOp(t, ops)
			if ops.lastErr != nil {
				t.Fatalf("выдача обязана состояться, получено: %v", ops.lastErr)
			}
			if !repo.insertOK {
				t.Fatal("предпосылка: своя строка обязана быть закоммичена")
			}

			var resp iamv1.IssueSAKeyResponse
			if err := anyUnmarshalTo(ops.lastResp, &resp); err != nil {
				t.Fatalf("ответ операции: %v", err)
			}
			if resp.GetClientId() == "" || resp.GetClientId() != string(repo.inserted.ID) {
				t.Errorf("ответ называет клиента %q, а строка ключа — %q: клиент называется "+
					"идентификатором строки, и второго имени у него нет", resp.GetClientId(), repo.inserted.ID)
			}
			if resp.GetClientId() != resp.GetKeyId() {
				t.Errorf("ответ называет клиента %q при ключе %q: предъявитель подписывает утверждение "+
					"ИМЕНЕМ КЛИЕНТА, и разойдись эти две величины — он назвал бы себя тем, чего в реестре нет",
					resp.GetClientId(), resp.GetKeyId())
			}
			if name == "KEYPAIR" && resp.GetPrivateKeyPem() == "" {
				t.Error("ключевой материал обязан быть выдан")
			}
		})
	}
}

// TestIssue_OwnIssuance_CommitFailure_FailsTheOperation — отказ записи строки
// ключа — отказ операции: ответа с ключом нет, и снимать снаружи нечего —
// выдача ничего вне службы не заводит.
func TestIssue_OwnIssuance_CommitFailure_FailsTheOperation(t *testing.T) {
	repo := &failingInsertRepo{insertErr: errors.New("insert failed")}
	ops := &stubOpsRepo{}
	uc := newOwnIssueUC(repo, ops)

	in := IssueInput{ServiceAccountID: "sva_test000000000000", CreatedByUserID: "usr_admin00000000000"}
	if _, err := uc.Execute(context.Background(), in); err != nil {
		t.Fatalf("Execute (sync): %v", err)
	}
	waitForOp(t, ops)

	if ops.lastErr == nil {
		t.Fatal("отказ записи обязан стать отказом операции")
	}
	if ops.lastResp != nil {
		t.Error("отказавшая выдача не вправе нести ответ с ключом")
	}
}
