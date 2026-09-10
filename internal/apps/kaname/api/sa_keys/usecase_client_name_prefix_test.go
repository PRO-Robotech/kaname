// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// usecase_client_name_prefix_test.go — приставка имени клиента внешнего
// провайдера и ПЕРЕХОД к ней (задача #2556, полоса Л3 разреза #2076).
//
// Имя клиента складывает САМА служба, в установке, где платформы нет вовсе,
// поэтому приставка носит имя службы. Имя при этом ВИДНО оператору провайдера
// — но видимость и адресуемость это РАЗНЫЕ вещи, и проба обязана держать
// именно вторую: клиент адресуется `client_id`, а по владельцу ищется через
// `owner`; имя не участвует ни в том, ни в другом.
//
// Объявленный переход: смена приставки касается ТОЛЬКО вновь заводимых
// клиентов. Уже заведённый клиент сохраняет своё имя и продолжает работать,
// потому что имя его не адресует — оно только пишется и никогда не читается
// обратно (перепись чтений `.ClientName` по службе — ноль).
package sa_keys

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/clients"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// clientNamePrefixOwnedByTheService — приставка, которую служба складывает сама.
const clientNamePrefixOwnedByTheService = "kaname-sak-"

// clientNamePrefixComposedBefore — приставка, которой служба пользовалась до
// смены. Клиенты с такими именами живут у провайдера и обязаны продолжать
// работать.
const clientNamePrefixComposedBefore = "kacho-sak-"

// issueOnce прогоняет выдачу и отдаёт запрос, ушедший провайдеру.
func issueOnce(t *testing.T, prefix string) clients.CreateOAuthClientRequest {
	t.Helper()
	hydra := &stubHydra{}
	ops := &stubOpsRepo{}
	u := NewIssueSAKeyUseCase(&stubSAClientRepo{}, &stubTx{}, hydra, ops).
		WithTrustedIssuerWriter(&fakeTrustedIssuers{})
	if prefix != "" {
		u.HydraClientNamePrefix = prefix
	}
	u.AudiencePrefix = "https://example/api"

	_, err := u.Execute(context.Background(), IssueInput{
		ServiceAccountID: "sva_test000000000000",
		CreatedByUserID:  "usr_admin00000000000",
		TrustedSubjects: []domain.TrustedSubject{
			{
				Issuer:         "https://token.actions.githubusercontent.com",
				SubjectPattern: "^repo:acme/infra:ref:refs/heads/main$",
				PublicKeyPEM:   testIssuerPublicKeyPEM,
				KeyAlgorithm:   "ES256",
			},
		},
	})
	require.NoError(t, err, "выдача ключа с приставкой %q", prefix)
	// Выдача асинхронна: клиент провайдера заводит работник. Дожидаемся ИСХОДА
	// операции, а не паузой — иначе проба зеленела бы на несозданном предмете.
	waitForOp(t, ops)
	require.True(t, hydra.created, "клиент провайдера не заводился — предмет пробы не возник")
	return hydra.gotReq
}

// TestClientNamePrefixNamesTheServiceThatComposesIt — умолчание называет службу.
func TestClientNamePrefixNamesTheServiceThatComposesIt(t *testing.T) {
	u := NewIssueSAKeyUseCase(&stubSAClientRepo{}, &stubTx{}, &stubHydra{}, &stubOpsRepo{})
	require.Equalf(t, clientNamePrefixOwnedByTheService, u.HydraClientNamePrefix,
		"умолчательная приставка имени клиента = %q; складывает имя служба, а не платформа",
		u.HydraClientNamePrefix)

	got := issueOnce(t, "")
	require.Truef(t, strings.HasPrefix(got.ClientName, clientNamePrefixOwnedByTheService),
		"имя, ушедшее провайдеру, = %q; приставка обязана называть службу (%q)",
		got.ClientName, clientNamePrefixOwnedByTheService)
}

// TestClientNameIsALabelAndNeverAnAddress — ПЕРЕХОД, и он держится ОДНИМ
// ФАКТОМ разницы.
//
// Два прогона одной выдачи отличаются РОВНО приставкой имени. Всё, чем клиент
// адресуется — идентификатор, владелец, адресат, способ предъявления, набор
// ключей, — обязано совпасть побайтово; разойтись вправе только само имя.
// Пока это так, смена приставки не трогает ни одной адресующей координаты, и
// заведённый прежде клиент продолжает находиться и работать.
//
// Если когда-нибудь имя станет адресом, разойдётся не только оно — и проба
// назовёт, ЧТО именно, а не просто покраснеет.
func TestClientNameIsALabelAndNeverAnAddress(t *testing.T) {
	before := issueOnce(t, clientNamePrefixComposedBefore)
	after := issueOnce(t, clientNamePrefixOwnedByTheService)

	require.NotEqual(t, before.ClientName, after.ClientName,
		"имена совпали — одно-фактной разницы не возникло, проба беспредметна")
	require.Truef(t, strings.HasPrefix(before.ClientName, clientNamePrefixComposedBefore),
		"прежняя приставка перестала складываться: %q", before.ClientName)

	// Then — адресующие координаты не шелохнулись.
	before.ClientName, after.ClientName = "", ""
	require.Equal(t, before, after,
		"смена приставки ИМЕНИ изменила адресующую координату клиента — так переход не объявлялся")
}
