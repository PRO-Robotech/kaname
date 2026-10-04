// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package audit_test

// upsert_journal_initiator_integration_test.go — заведение человека по
// удостоверению поставщика пишет ресурсный журнал службы доступа (NTF-3, Р2;
// сценарий NTF3-63). Вызов без токена удостоверенного субъекта не несёт
// (`{system, bootstrap}` — отметка его отсутствия) — инициатор строки журнала
// компонент заведения; вызов с токеном — его субъект. Пара отличается одним
// фактом: принципалом вызова.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/operations"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/user"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

func TestUpsertFromIdentity_JournalInitiatorIsTheCallerOrTheProvisioningComponent(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	admin := ids.NewID(domain.PrefixUser)

	for _, tc := range []struct {
		name, tag string
		caller    operations.Principal
		want      string
	}{
		{name: "без токена — компонент заведения", tag: "prov",
			caller: operations.Principal{Type: "system", ID: "bootstrap", DisplayName: "kaname-bootstrap"},
			want:   "system:kaname-provisioning"},
		{name: "с токеном — его субъект", tag: "jwt",
			caller: operations.Principal{Type: "user", ID: admin, DisplayName: "admin"},
			want:   "user:" + admin},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ext := "ext-journal-" + tc.tag + "-" + ids.NewID("tst")[3:11]
			email := "u-journal-" + tc.tag + "-" + ids.NewID("tst")[3:11] + "@example.com"
			uc := user.NewUpsertFromIdentityUseCase(env.repo, env.opsRepo)
			_, err := uc.Execute(operations.WithPrincipal(ctx, tc.caller), user.UpsertFromIdentityInput{
				ExternalID:  domain.ExternalSubject(ext),
				Email:       domain.Email(email),
				DisplayName: domain.DisplayName("Journal " + tc.tag),
			})
			require.NoError(t, err)
			awaitWorkers(t)

			usrID := singleID(t, ctx, env, `SELECT id FROM kaname.users WHERE external_id = $1 AND email = $2`, ext, email)
			var initiator string
			require.NoError(t, env.pool.QueryRow(ctx, `
				SELECT initiator FROM kaname.resource_journal
				 WHERE resource_kind = 'iam_user' AND resource_id = $1 AND event_type = 'CREATED'`,
				usrID).Scan(&initiator), "строки журнала о заведении человека нет ровно одной")
			require.Equal(t, tc.want, initiator)
		})
	}
}
