// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// secret_backstop_interactive_client_integration_test.go — перечень
// подметальщика не только ОБЪЯВЛЕН, но и ДЕЙСТВУЕТ на секрете интерактивного
// клиента (задача kaname#405, приёмка
// confidential-interactive-client-secret-shown-once, IC-SECRET-12, уровень I).
//
// Секрет кладётся в тело строки операции В ОБХОД конструкции глагола (тело
// строки у `Create` секрета не несёт вовсе): это ровно тот будущий второй путь
// записи, против которого стоит бэкстоп. Строка состарена за предел «осела» —
// подметаются только строки старше льготы плюс запас и моложе окна.

import (
	"context"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/anypb"

	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/PRO-Robotech/corelib/operations"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/iampgtest"
)

func TestIntegration_IC12_BackstopSweepsAClientSecretStrandedInAnOperationRow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, iampgtest.NewTestPostgres(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	ops := operations.NewRepo(pool, "kaname")

	const opID = "iop_ic405_stranded"
	const secret = "stranded-client-secret-4b7f"
	now := time.Now().UTC().Truncate(time.Second)
	if err := ops.Create(ctx, operations.Operation{
		ID: opID, Description: "Create interactive client stranded", CreatedAt: now, ModifiedAt: now,
		Principal: operations.SystemPrincipal(),
	}); err != nil {
		t.Fatal(err)
	}
	body, err := anypb.New(&iamv1.CreateInteractiveClientResponse{
		InteractiveClient: &iamv1.InteractiveClient{Id: "ic-00000000000000405", ClientId: "oic-stranded00000000000"},
		ClientSecret:      secret,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := ops.MarkDone(ctx, opID, body); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx,
		`UPDATE kaname.operations SET modified_at = now() - interval '30 minutes' WHERE id = $1`, opID); err != nil {
		t.Fatal(err)
	}
	read := func() *iamv1.CreateInteractiveClientResponse {
		t.Helper()
		op, err := ops.Get(ctx, opID)
		if err != nil {
			t.Fatal(err)
		}
		var r iamv1.CreateInteractiveClientResponse
		if err := op.Response.UnmarshalTo(&r); err != nil {
			t.Fatal(err)
		}
		return &r
	}
	if read().GetClientSecret() != secret {
		t.Fatal("ПРЕДУСЛОВИЕ: секрет не положен в тело строки — подметать нечего")
	}

	targets, err := secretSweepTargets()
	if err != nil {
		t.Fatal(err)
	}
	pgTargets := make([]kanamepg.SecretSweepTarget, 0, len(targets))
	for _, tg := range targets {
		pgTargets = append(pgTargets, kanamepg.SecretSweepTarget{ResponseType: tg.ResponseType, Fields: tg.Fields})
	}
	res, err := kanamepg.NewOpsResponseRedactor(pool, "kaname").SweepStrandedSecrets(ctx, kanamepg.SecretSweepSpec{
		Targets: pgTargets, Settled: 10 * time.Minute, Window: secretSweepWindow, Limit: secretSweepBatch,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("подметальщик: прочитано %d, вычищено %d", res.Scanned, res.Redacted)
	after := read()
	if after.GetClientSecret() != "" {
		t.Fatalf("бэкстоп НЕ вычистил секрет интерактивного клиента из строки операции: перечень его не знает "+
			"(прочитано %d, вычищено %d)", res.Scanned, res.Redacted)
	}
	if after.GetInteractiveClient().GetClientId() != "oic-stranded00000000000" {
		t.Error("бэкстоп снёс не только поле-носитель: ресурс в теле потерян")
	}
	if res.Redacted != 1 {
		t.Errorf("бэкстоп обязан назвать вычищенное: вычищено %d, ждали 1", res.Redacted)
	}
}
