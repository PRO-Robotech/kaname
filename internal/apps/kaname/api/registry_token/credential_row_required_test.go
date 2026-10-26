// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// credential_row_required_test.go — полоса базового секрета не выпускает
// токен, который отзыв удостоверения не снял бы (kaname#947).
//
// Ключ отсечки токена — идентификатор строки удостоверения, который называет
// авторитет. Авторитет, признавший удостоверение и строки не назвавший, —
// неисправен; выпуск по такому ответу дал бы токен, живущий до срока при любом
// отзыве. Исход — недоступность издателя: предъявитель ни при чём.
package registry_token

import (
	"context"
	"errors"
	"testing"

	"github.com/PRO-Robotech/corelib/credsecret"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// rowlessResolver — авторитет, признающий секрет и не называющий его строки.
type rowlessResolver struct{ live string }

func (r rowlessResolver) ResolveBasic(_ context.Context, presented string) (domain.BasicCredential, error) {
	if presented != r.live {
		return domain.BasicCredential{}, domain.ErrBasicCredentialRefused
	}
	return domain.BasicCredential{PrincipalType: "service_account", PrincipalID: "sva_0000000000000row1"}, nil
}

func TestBasicLaneRefusesToMintWhenTheAuthorityNamesNoCredentialRow(t *testing.T) {
	const credID = "soc_0000000000000row1"
	secret, _, err := credsecret.Mint(credID)
	if err != nil {
		t.Fatal(err)
	}
	m := &fakeMinter{out: MintOutput{AccessToken: "minted", ExpiresIn: 300}}
	uc := mustUseCase(t, Config{
		Scope: "registry", AllowedAudiences: []string{"registry"}, DefaultService: "registry",
	}, m).WithBasicCredentialResolver(rowlessResolver{live: secret})

	_, err = uc.Execute(context.Background(), IssueInput{Username: credID, Password: secret, Service: "registry"})
	if !errors.Is(err, ErrIssuerUnavailable) {
		t.Fatalf("авторитет не назвал строки удостоверения, ожидалась недоступность издателя, получено: %v", err)
	}
	if m.got.Subject != "" {
		t.Fatalf("подписанту передан выпуск для %q — токен без ключа отсечки удостоверения выпущен", m.got.Subject)
	}

	// Законный близнец: тот же вход, авторитет назвал строку — токен выпущен и
	// несёт её ключом отсечки.
	m2 := &fakeMinter{out: MintOutput{AccessToken: "minted", ExpiresIn: 300}}
	uc2 := mustUseCase(t, Config{
		Scope: "registry", AllowedAudiences: []string{"registry"}, DefaultService: "registry",
	}, m2).WithBasicCredentialResolver(&fakeBasicResolver{
		live:  map[string]string{credID: secret},
		svaOf: map[string]string{credID: "sva_0000000000000row1"},
	})
	if _, err := uc2.Execute(context.Background(), IssueInput{Username: credID, Password: secret, Service: "registry"}); err != nil {
		t.Fatalf("близнец отвергнут: %v", err)
	}
	if m2.got.CredentialID != credID {
		t.Fatalf("ключ отсечки выпуска %q, ожидалась строка удостоверения %q", m2.got.CredentialID, credID)
	}
}
