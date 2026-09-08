// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// token_test.go — общие дублёры полосы и её ВХОД.
//
// Проб проверяющего ключевой материал здесь больше нет: приём ключа в поле
// пароля снят задачей #1143 вместе с самим проверяющим. То, что осталось у
// этого файла, — вход полосы (отсутствие удостоверения) и умолчание адресата;
// снятый вид проверяется отдельно, в key_material_refused_test.go.

package registry_token

import (
	"context"
	"errors"
	"testing"

	"github.com/PRO-Robotech/kacho/pkg/credsecret"
)

// fakeSigner — records the assertion input and returns a canned assertion.
// Живёт ради АНОНИМНОГО потока: полоса предъявленного удостоверения утверждений
// не подписывает — ключевого материала у принимаемого вида не существует.
type fakeSigner struct {
	got AssertionInput
	err error
}

func (f *fakeSigner) Sign(in AssertionInput) (string, error) {
	f.got = in
	if f.err != nil {
		return "", f.err
	}
	return "assertion.for." + in.ClientID, nil
}

// fakeExchanger — a scripted TokenExchanger (тот же анонимный поток).
type fakeExchanger struct {
	out ExchangeOutput
	err error
	got ExchangeInput
}

func (f *fakeExchanger) Exchange(_ context.Context, in ExchangeInput) (ExchangeOutput, error) {
	f.got = in
	return f.out, f.err
}

// TestExecute_ServiceFallsBackToDefault — пустой ?service= даёт объявленный
// посадкой адресат, а не пустой.
func TestExecute_ServiceFallsBackToDefault(t *testing.T) {
	uc, minter, credID, secret := laneUnderTest(t)

	if _, err := uc.Execute(context.Background(), IssueInput{Username: credID, Password: secret}); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if minter.got.Audience != "registry" {
		t.Errorf("requested aud = %q; want DefaultService", minter.got.Audience)
	}
	_ = uc
}

// TestExecute_MissingCredential_Unauthenticated — отсутствие половины
// удостоверения — отказ fail-closed, и чеканки не происходит.
func TestExecute_MissingCredential_Unauthenticated(t *testing.T) {
	secretOfNobody, _, err := credsecret.Mint("soc_0000000000000none")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		in   IssueInput
	}{
		{"empty username", IssueInput{Username: "", Password: secretOfNobody}},
		{"empty password", IssueInput{Username: "cid", Password: ""}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			uc, minter, _, _ := laneUnderTest(t)
			out, err := uc.Execute(context.Background(), tc.in)
			if !errors.Is(err, ErrUnauthenticated) {
				t.Fatalf("err = %v; want ErrUnauthenticated", err)
			}
			if out.Token != "" || minter.got.Subject != "" {
				t.Fatal("на отказе аутентификации не бывает ни токена, ни чеканки")
			}
		})
	}
}

// TestExecute_LaneWithoutItsAuthority_FailsClosedAsIssuerUnavailable — полоса,
// собранная без авторитета о предъявленном секрете, отвечает недоступностью
// издателя, а не отказом в удостоверении: предъявитель ни при чём.
//
// Пара к TestExecute_ServiceFallsBackToDefault выше: та же строка на полосе с
// авторитетом проходит, поэтому «отвергнуто» здесь не зеленеет на всём.
func TestExecute_LaneWithoutItsAuthority_FailsClosedAsIssuerUnavailable(t *testing.T) {
	secret, _, err := credsecret.Mint("soc_0000000000001143n")
	if err != nil {
		t.Fatal(err)
	}
	uc := NewIssueRegistryTokenUseCase(Config{
		AllowedAudiences: []string{"registry"}, DefaultService: "registry",
	}, &fakeSigner{}, &fakeExchanger{})

	out, err := uc.Execute(context.Background(), IssueInput{
		Username: "soc_0000000000001143n", Password: secret,
	})
	if !errors.Is(err, ErrIssuerUnavailable) {
		t.Fatalf("err = %v; want ErrIssuerUnavailable", err)
	}
	if errors.Is(err, ErrUnauthenticated) {
		t.Error("неисправность сборки выдана за негодные учётные данные — клиент стал бы менять секрет")
	}
	if out.Token != "" {
		t.Fatal("токен на несобранной полосе")
	}
}

// TestExecute_MinterFailure_IsIssuerUnavailable — отказ НАШЕЙ чеканки — тоже
// недоступность издателя: повтор осмыслен, учётные данные ни при чём.
func TestExecute_MinterFailure_IsIssuerUnavailable(t *testing.T) {
	const credID, svaID = "soc_0000000000001143m", "sva0000000000001143m"
	secret, _, err := credsecret.Mint(credID)
	if err != nil {
		t.Fatal(err)
	}
	res := &fakeBasicResolver{
		live:  map[string]string{credID: secret},
		svaOf: map[string]string{credID: svaID},
	}
	m := &fakeMinter{err: errors.New("no signing key")}
	uc := NewIssueRegistryTokenUseCase(Config{
		AllowedAudiences: []string{"registry"}, DefaultService: "registry",
	}, &fakeSigner{}, &fakeExchanger{}).
		WithLocalMinter(m).
		WithBasicCredentialResolver(res)

	_, err = uc.Execute(context.Background(), IssueInput{Username: credID, Password: secret})
	if !errors.Is(err, ErrIssuerUnavailable) {
		t.Fatalf("err = %v; want ErrIssuerUnavailable", err)
	}
}
