// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/stretchr/testify/require"
)

// Инъекции меняют настоящий production corpus, не ответ решателя.
func TestChildRegistrationQuestionRequiresBoundServingPath(t *testing.T) {
	corpus := directRouteCorpus(t)
	evidence, err := check.CensusChildRegistrationQuestionProof(corpus)
	require.NoError(t, err)
	require.NotEmpty(t, evidence, "законный FULL путь обязан разрешиться")
	const app = "internal/apps/kaname/api/"
	const pg = "internal/repo/kaname/pg/"
	for _, tc := range []struct{ name, file, before, after string }{
		{"слушатель не подключён к публичной регистрации", "cmd/kaname/serve.go", "registerPublicServices(publicAdmission.Registrar(grpcSrv), svcs, opsRepo)", "_ = grpcSrv"},
		{"композиция заполняет другой набор служб", "cmd/kaname/serve.go", "wireFullStartupServices(ctx, fullStartup, kanameRepo, svcs, pool)", "wireFullStartupServices(ctx, fullStartup, kanameRepo, another, pool)"},
		{"публичный mount снят", "cmd/kaname/grpc_register.go", "iamv1.RegisterChildRegistrationServiceServer(srv, svcs.childRegistrationHandler)", "_ = svcs.childRegistrationHandler"},
		{"чужой import mount", "cmd/kaname/grpc_register.go", `"github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"`, `"example.invalid/iam/v1"`},
		{"подменён runner", "cmd/kaname/full_startup.go", "kanamepg.NewResourceDecisionRunner(ctx, repo, profile.bundle, svcs.resourceGate)", "kanamepg.NewOtherRunner(ctx, repo, profile.bundle, svcs.resourceGate)"},
		{"публикация теряет capability", "cmd/kaname/full_startup.go", "internaliamapp.NewUserChildRegistration(writers)", "internaliamapp.NewUserChildRegistration(otherRunner)"},
		{"публикация теряет закреплённую редакцию", "cmd/kaname/catalog_publication_reconcile.go", "generation.resource.RunUserChildRegistration(pinned, in, principal)", "generation.resource.RunUserChildRegistration(ctx, in, principal)"},
		{"иной capability", "cmd/kaname/full_startup.go", "internaliamapp.NewUserChildRegistration(resourceDecisions)", "internaliamapp.NewUserChildRegistration(otherRunner)"},
		{"повторная запись handler", "cmd/kaname/full_startup.go", "svcs.internalIAMHandler.WithChildParentClose(resourceDecisions)", "svcs.childRegistrationHandler = nil\n svcs.internalIAMHandler.WithChildParentClose(resourceDecisions)"},
		{"constructor теряет UC", app + "child_registration/handler.go", "return &Handler{register: register}", "return &Handler{register: nil}"},
		{"constructor теряет port", app + "internal_iam/register_user_child.go", "return &UserChildRegistration{tx: tx}", "return &UserChildRegistration{tx: nil}"},
		{"transport не зовёт UC", app + "child_registration/handler.go", "h.register.Register(ctx,", "h.register.Other(ctx,"},
		{"UC не зовёт port", app + "internal_iam/register_user_child.go", "uc.tx.RunUserChildRegistration(ctx, input, principal)", "uc.tx.Other(ctx, input, principal)"},
		{"ранний успешный ответ", app + "internal_iam/register_user_child.go", "version, err := uc.tx.RunUserChildRegistration", "if true { return time.Time{}, nil }; version, err := uc.tx.RunUserChildRegistration"},
		{"FULL guard снят", pg + "resource_child_run.go", "r.repo.fullContract == nil || !r.repo.fullContractMatches(r.bundle)", "false"},
		{"retry не делает ни одной попытки", pg + "writer_protocol.go", "const authorityEntryAttempts = 3", "const authorityEntryAttempts = 0"},
		{"callback не вызывается", pg + "resource_attempt_retry.go", "result, err := once()", "var result T; var err error"},
		{"retry идёт в обход RR", pg + "resource_child_run.go", "return r.runUserChildRegistrationOnce(ctx, lease.Conn(), input, principal, budget)", "return time.Time{}, nil"},
		{"ошибка уборки оставляет версию", pg + "resource_child_run.go", "version = time.Time{}", "_ = version"},
		{"неподтверждённое наличие родителя", pg + "resource_child_run.go", "if !stage.parentRegistered {", "if !stage.childRegistered {"},
		{"stage не читает authorizer", pg + "resource_child_stage.go", "r.captureUserChildAuthorization(ctx, tx, lifetime, input, principal, budget)", "r.otherAuthorization(ctx, tx, lifetime, input, principal, budget)"},
		{"регистрация читается раньше права", pg + "resource_child_stage.go", "authorization, err := r.captureUserChildAuthorization", "_, _ = newResourceSourceCapture(tx, budget, lifetime); authorization, err := r.captureUserChildAuthorization"},
		{"родитель подменён", pg + "resource_child_authorization.go", "policy.Path.Resolve(input.ResourceID)", "policy.Path.Resolve(otherID)"},
		{"вопрос снят", pg + "resource_child_authorization.go", "Check(ctx, subject, target.ParentAction, target.ParentObject)", "Other(ctx, subject, target.ParentAction, target.ParentObject)"},
		{"результат права игнорируется", pg + "resource_child_authorization.go", "if !allowed {\n\t\treturn nil, childPermissionDenied\n\t}", "_ = allowed"},
		{"изменён вопрос FINAL", pg + "resource_child_body.go", "target.ParentAction, target.ParentObject)", "target.ParentAction, target.ChildObject)"},
		{"отказ FINAL остаётся обязательным", pg + "resource_child_body.go", "if !allowed {", "if allowed {"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := string(corpus[tc.file])
			require.Equal(t, 1, strings.Count(body, tc.before), "предмет инъекции изменился")
			changed := make(map[string][]byte, len(corpus))
			for name, source := range corpus {
				changed[name] = source
			}
			changed[tc.file] = []byte(strings.Replace(body, tc.before, tc.after, 1))
			got, err := check.CensusChildRegistrationQuestionProof(changed)
			require.NoError(t, err)
			require.Empty(t, got, "нарушенная цепочка не даёт права освобождённому RPC")
		})
	}
}
