// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// docker_lane_fixture_test.go — общий вход докерной полосы для внешних проб.
//
// После задачи #1143 полоса принимает ОДИН вид удостоверения — базовый токен
// доступа, — поэтому фикстура одна на все пробы этого пакета: второй её формы
// не бывает, и заводить её «на всякий случай» значило бы держать вход, которого
// продукт не принимает.
//
// Авторитет здесь НЕ снисходительнее продукта: форму он разбирает тем же
// единственным объявлением (`pkg/credsecret`), а не своим сравнением строк.

package registry_token_test

import (
	"context"
	"testing"

	"github.com/PRO-Robotech/kacho/pkg/credsecret"
	registrytokenuc "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/registry_token"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// liveBasicCredential — авторитет, знающий ровно одну живую строку.
type liveBasicCredential struct {
	secret string
	sva    string
}

func (l liveBasicCredential) ResolveBasic(_ context.Context, presented string) (domain.BasicCredential, error) {
	p, err := credsecret.Parse(presented)
	if err != nil || presented != l.secret {
		return domain.BasicCredential{}, domain.ErrBasicCredentialRefused
	}
	return domain.BasicCredential{
		PrincipalType: "service_account", PrincipalID: l.sva, CredentialID: p.CredentialID,
	}, nil
}

// dockerCredentialID / dockerSubject — идентификатор удостоверения и служебная
// учётка, за которую оно говорит.
const (
	dockerCredentialID = "soc_0000000000000dock"
	dockerSubject      = "sva0000000000000dock"
)

// newBasicCredential чеканит живую строку и авторитет, который её признаёт.
func newBasicCredential(t *testing.T) (string, liveBasicCredential) {
	t.Helper()
	secret, _, err := credsecret.Mint(dockerCredentialID)
	if err != nil {
		t.Fatalf("чеканка базового токена: %v", err)
	}
	return secret, liveBasicCredential{secret: secret, sva: dockerSubject}
}

// dockerLogin — вход докерной полосы: имя обязано совпадать с идентификатором,
// который несёт сама строка.
func dockerLogin(secret string) registrytokenuc.IssueInput {
	return registrytokenuc.IssueInput{Username: dockerCredentialID, Password: secret}
}
