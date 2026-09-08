// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// usecase_secret_kind_test.go — ВЫДАЧА БАЗОВОГО СЕКРЕТА (задача #1142,
// приёмка BAT-1 §2.5, §4.3, §7; сценарии BAT-1-09, 11, 12, 14, 16, 17, 21, 22).

package user_tokens

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kaname/cloud/iam/v1"
	"github.com/PRO-Robotech/kacho/pkg/credsecret"
	"github.com/PRO-Robotech/kacho/pkg/tokenpolicy"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// BAT-1-09 — положительный путь фазы: выдача вида SECRET завершается НА ПУТИ
// ЗАПРОСА, ответ несёт непустой секрет объявленной формы, заполненный срок и
// идентификатор.
func TestBAT1_09_IssueSecretCompletesOnTheRequestPathAndCarriesTheSecret(t *testing.T) {
	repo := &stubUserClientRepo{}
	ops := &stubOpsRepo{}
	uc := NewIssueUserTokenUseCase(repo, &stubTx{}, ops)

	op, err := uc.Execute(context.Background(), IssueInput{
		UserID:          "usr00000000000000001",
		Description:     "сборочный конвейер",
		TTLSeconds:      int64((30 * 24 * time.Hour).Seconds()),
		CreatedByUserID: "usr00000000000000001",
		CredentialKind:  domain.CredentialKindSecret,
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if op == nil {
		t.Fatal("nil operation")
	}
	if !op.Done {
		t.Fatal("операция не завершена в ответе самого Issue — секрет показывается один раз, " +
			"и второго чтения у него нет")
	}
	if op.Error != nil {
		t.Fatalf("операция завершена ошибкой: %v", op.Error)
	}

	var resp iamv1.IssueUserTokenResponse
	if err := op.Response.UnmarshalTo(&resp); err != nil {
		t.Fatalf("разбор ответа: %v", err)
	}
	secret := resp.GetSecret()
	if secret == "" {
		t.Fatal("ответ выдачи не несёт секрета")
	}
	p, perr := credsecret.Parse(secret)
	if perr != nil {
		t.Fatalf("секрет не объявленной формы: %v (%q)", perr, secret)
	}
	if p.CredentialID != resp.GetToken().GetId() {
		t.Errorf("строка называет удостоверение %q, а выпущено %q", p.CredentialID, resp.GetToken().GetId())
	}

	// Форма ответа по видам: у SECRET ключевого материала нет ВСЕГО.
	if resp.GetPrivateKeyPem() != "" || resp.GetPublicKeyPem() != "" || resp.GetAlgorithm() != "" {
		t.Error("ответ вида SECRET несёт ключевой материал")
	}
	if resp.GetToken().GetCredentialKind() != iamv1.CredentialKind_CREDENTIAL_KIND_SECRET {
		t.Errorf("вид в строке ресурса = %v", resp.GetToken().GetCredentialKind())
	}
	if resp.GetToken().GetExpiresAt() == nil {
		t.Error("срок не заполнен — бессрочного секрета не бывает")
	}
}

// BAT-1-21/22 — секрет не существует НИ В ОДНОМ пути записи, кроме тела ответа,
// полученного вызывающим. Утверждается ПАРА: секрета нет И прочие поля на месте
// (иначе «пусто» означало бы «ответа нет вовсе», и проба зеленела бы на
// сломанной выдаче).
func TestBAT1_21_TheSecretIsInNoWrittenPath(t *testing.T) {
	repo := &stubUserClientRepo{}
	ops := &stubOpsRepo{}
	audit := &stubAudit{}
	uc := NewIssueUserTokenUseCase(repo, &stubTx{}, ops).WithAuditEmitter(audit)

	op, err := uc.Execute(context.Background(), IssueInput{
		UserID:          "usr00000000000000001",
		CreatedByUserID: "usr00000000000000001",
		CredentialKind:  domain.CredentialKindSecret,
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	var resp iamv1.IssueUserTokenResponse
	if err := op.Response.UnmarshalTo(&resp); err != nil {
		t.Fatalf("разбор ответа: %v", err)
	}
	secret := resp.GetSecret()
	if secret == "" {
		t.Fatal("секрета нет в ответе — дальнейшие отрицания были бы вакуумны")
	}
	p, _ := credsecret.Parse(secret)

	// (1) Строка операции. Момент чтения ЗДЕСЬ несущий: у вида SECRET
	// отложенного стирания нет вовсе, поле не кладётся в тело при записи.
	if ops.lastResp == nil {
		t.Fatal("строка операции не получила тела ответа — положительный контроль не выполнен")
	}
	var persisted iamv1.IssueUserTokenResponse
	if err := ops.lastResp.UnmarshalTo(&persisted); err != nil {
		t.Fatalf("разбор записанного тела: %v", err)
	}
	if persisted.GetSecret() != "" {
		t.Error("секрет записан в строку операции — «показан один раз» стало «показан ещё столько-то»")
	}
	if persisted.GetToken().GetId() == "" { // положительный контроль
		t.Error("записанное тело пусто — «секрета нет» верно и о выдаче, которой не было")
	}
	if strings.Contains(ops.lastResp.String(), p.SecretPart) {
		t.Error("секретная часть найдена подстрокой в записанном теле операции")
	}

	// (2) Строка удостоверения: хеш есть, секрета нет ни в одной колонке.
	row := repo.inserted
	if len(row.SecretHash) == 0 {
		t.Error("строка удостоверения не несёт хеша — положительный контроль не выполнен")
	}
	if !credsecret.Verify(string(row.ID), p.SecretPart, row.SecretHash) {
		t.Error("хеш строки не признаёт выданную секретную часть")
	}
	for name, v := range map[string]string{
		"public_key_pem":  row.PublicKeyPEM,
		"key_algorithm":   row.KeyAlgorithm,
		"description":     string(row.Description),
		"name":            string(row.Name),
		"hydra_client_id": string(row.OAuthClientID),
	} {
		if v != "" && strings.Contains(v, p.SecretPart) {
			t.Errorf("секретная часть найдена в колонке %s", name)
		}
	}

	// (3) Журнал аудита: идентификатор есть, секрета нет.
	if len(audit.events) == 0 {
		t.Fatal("журнал аудита пуст — положительный контроль не выполнен")
	}
	for _, ev := range audit.events {
		if strings.Contains(fmt.Sprintf("%+v", ev), p.SecretPart) {
			t.Error("секретная часть найдена в записи журнала аудита")
		}
	}
}

// BAT-1-11 — прежнее поведение сохраняется ДОСЛОВНО: вид не назван ⇒ KEYPAIR,
// ответ несёт ключевой материал и НЕ несёт секрета.
func TestBAT1_11_UnnamedKindKeepsTheKeypairBehaviourVerbatim(t *testing.T) {
	repo := &stubUserClientRepo{}
	ops := &stubOpsRepo{}
	uc := NewIssueUserTokenUseCase(repo, &stubTx{}, ops)

	op, err := uc.Execute(context.Background(), IssueInput{
		UserID:          "usr00000000000000001",
		CreatedByUserID: "usr00000000000000001",
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	_ = op
	waitForOp(t, ops)
	var resp iamv1.IssueUserTokenResponse
	if err := ops.lastResp.UnmarshalTo(&resp); err != nil {
		t.Fatalf("разбор ответа: %v", err)
	}
	if resp.GetPrivateKeyPem() == "" {
		t.Error("прежнее поведение сломано: ключевого материала нет")
	}
	if resp.GetSecret() != "" {
		t.Error("вид KEYPAIR отдал секрет")
	}
	if repo.inserted.CredentialKind != domain.CredentialKindKeypair {
		t.Errorf("вид записан как %v, ожидался KEYPAIR", repo.inserted.CredentialKind)
	}
}

// BAT-1-14 — LEGACY, названный явно, отвергается ВСЕГДА и с именем поля.
func TestBAT1_14_ExplicitLegacyKindIsRefusedWithTheFieldName(t *testing.T) {
	uc := NewIssueUserTokenUseCase(&stubUserClientRepo{}, &stubTx{}, &stubOpsRepo{})

	_, err := uc.Execute(context.Background(), IssueInput{
		UserID:          "usr00000000000000001",
		CreatedByUserID: "usr00000000000000001",
		CredentialKind:  domain.CredentialKindLegacy,
	})
	if err == nil {
		t.Fatal("вид LEGACY выпущен — его не производит ни один глагол")
	}
	st, _ := grpcstatus.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("код = %v, ожидался INVALID_ARGUMENT", st.Code())
	}
	if !strings.Contains(st.Message(), "credential_kind") {
		t.Errorf("отказ не называет поля: %q", st.Message())
	}

	// FEDERATED у личности недостижим by construction — в её контракте нет
	// поля, которым он задаётся; названный явно, он тоже отвергается.
	_, err = uc.Execute(context.Background(), IssueInput{
		UserID:          "usr00000000000000001",
		CreatedByUserID: "usr00000000000000001",
		CredentialKind:  domain.CredentialKindFederated,
	})
	if err == nil {
		t.Fatal("вид FEDERATED выпущен у личности, где его быть не может")
	}
}

// BAT-1-16 — срок сверх потолка ОТВЕРГАЕТСЯ, а не урезается; ровно на потолке
// принимается (граница включительна, проверена обеими сторонами).
func TestBAT1_16_TTLAboveTheCeilingIsRefusedAndTheCeilingItselfIsAccepted(t *testing.T) {
	ceiling := int64(tokenpolicy.SecretCredentialTTLCeiling.Seconds())

	uc := NewIssueUserTokenUseCase(&stubUserClientRepo{}, &stubTx{}, &stubOpsRepo{})
	_, err := uc.Execute(context.Background(), IssueInput{
		UserID:          "usr00000000000000001",
		CreatedByUserID: "usr00000000000000001",
		CredentialKind:  domain.CredentialKindSecret,
		TTLSeconds:      ceiling + 1,
	})
	if err == nil {
		t.Fatal("срок сверх потолка принят — параметр урезан молча")
	}
	st, _ := grpcstatus.FromError(err)
	if st.Code() != codes.InvalidArgument || !strings.Contains(st.Message(), "ttl_seconds") {
		t.Errorf("отказ = %v %q, ожидался INVALID_ARGUMENT с именем поля", st.Code(), st.Message())
	}

	// Положительный контроль: ровно на потолке.
	repo := &stubUserClientRepo{}
	uc2 := NewIssueUserTokenUseCase(repo, &stubTx{}, &stubOpsRepo{})
	if _, err := uc2.Execute(context.Background(), IssueInput{
		UserID:          "usr00000000000000001",
		CreatedByUserID: "usr00000000000000001",
		CredentialKind:  domain.CredentialKindSecret,
		TTLSeconds:      ceiling,
	}); err != nil {
		t.Fatalf("срок ровно на потолке отвергнут: %v", err)
	}
}

// BAT-1-17 — срок не назван ⇒ умолчание; «бессрочно» у этого вида не
// выражается НИ ОДНИМ входом.
func TestBAT1_17_UnnamedTTLGetsTheDefaultAndForeverIsUnexpressible(t *testing.T) {
	for name, ttl := range map[string]int64{
		"ноль":          0,
		"отрицательный": -1,
	} {
		repo := &stubUserClientRepo{}
		uc := NewIssueUserTokenUseCase(repo, &stubTx{}, &stubOpsRepo{})
		op, err := uc.Execute(context.Background(), IssueInput{
			UserID:          "usr00000000000000001",
			CreatedByUserID: "usr00000000000000001",
			CredentialKind:  domain.CredentialKindSecret,
			TTLSeconds:      ttl,
		})
		if err != nil {
			// Отрицательный срок вправе быть отвергнут — это тоже «не бессрочно».
			continue
		}
		if repo.inserted.ExpiresAt == nil {
			t.Errorf("%s: строка удостоверения бессрочна — вид SECRET такого не допускает", name)
			continue
		}
		if name == "ноль" {
			want := tokenpolicy.SecretCredentialTTLDefault
			got := time.Until(*repo.inserted.ExpiresAt)
			if got < want-time.Minute || got > want+time.Minute {
				t.Errorf("умолчание = %v, объявлено %v", got, want)
			}
		}
		_ = op
	}

	// Положительный контроль: явный срок применяется дословно.
	repo := &stubUserClientRepo{}
	uc := NewIssueUserTokenUseCase(repo, &stubTx{}, &stubOpsRepo{})
	if _, err := uc.Execute(context.Background(), IssueInput{
		UserID:          "usr00000000000000001",
		CreatedByUserID: "usr00000000000000001",
		CredentialKind:  domain.CredentialKindSecret,
		TTLSeconds:      int64((7 * 24 * time.Hour).Seconds()),
	}); err != nil {
		t.Fatalf("явный срок отвергнут: %v", err)
	}
	if repo.inserted.ExpiresAt == nil {
		t.Fatal("явный срок не применён")
	}
	if got := time.Until(*repo.inserted.ExpiresAt); got < 6*24*time.Hour {
		t.Errorf("явный срок = %v, ожидалось около 7 суток", got)
	}
}
