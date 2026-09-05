// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// usecase_trusted_issuers_test.go — федеративная выдача пишет перечень
// доверенных издателей в НАШУ таблицу (задача #1124).
//
// # Что здесь утверждается вместо прежнего
//
// Прежде эти пробы утверждали, что выдача регистрирует доверие У ПОСТАВЩИКА, и
// что отказ регистрации откатывает заведённое им же зеркало клиента. Предмет
// обеих переехал: перечень стал нашей таблицей, а веер обращений к поставщику
// исчез вместе с ним.
//
// Свойство, однако, осталось тем же и утверждается здесь: перечень записан ТОЧНО
// тот, что назвал вызывающий, и строка ключа без своего перечня не существует.
// Заменять пробу на более слабую при переезде предмета нельзя — она осталась бы
// зелёной при неработающей выдаче.
package sa_keys

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"
	"time"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	"github.com/PRO-Robotech/kacho-iam/internal/service"
)

// testIssuerPublicKeyPEM — НАСТОЯЩИЙ открытый ключ, а не правдоподобная
// строка.
//
// Домен проверяет запись доверия на разбираемость ключа, поэтому фикстура,
// похожая на ключ, но им не являющаяся, отвергалась бы вместе со всей выдачей —
// и проба краснела бы на исправном коде. Обратный случай хуже: приняв заглушку,
// проба перестала бы отличать «ключ доехал» от «доехало что угодно».
var testIssuerPublicKeyPEM = func() string {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		panic(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}()

// recordedTrustList — один вызов записи перечня.
type recordedTrustList struct {
	clientID  domain.SAOAuthClientID
	subjects  []domain.TrustedSubject
	expiresAt *time.Time
}

// fakeTrustedIssuers — писатель НАШЕГО перечня.
//
// Дублёр не снисходительнее настоящего: пустой перечень настоящий отвергает, и
// этот отвергает тоже. Дублёр, молча принявший пустой список, скрыл бы ровно
// тот дефект, ради которого перечень заведён, — ключ, не доверяющий никому,
// выглядел бы выданным успешно.
type fakeTrustedIssuers struct {
	calls []recordedTrustList
	err   error
}

func (f *fakeTrustedIssuers) InsertTrustedIssuers(
	_ context.Context, _ service.Tx,
	clientID domain.SAOAuthClientID, subjects []domain.TrustedSubject, expiresAt *time.Time,
) error {
	if len(subjects) == 0 {
		return errors.New("trusted issuers: an empty list means 'trust nobody' and is never written as one")
	}
	if f.err != nil {
		return f.err
	}
	f.calls = append(f.calls, recordedTrustList{clientID: clientID, subjects: subjects, expiresAt: expiresAt})
	return nil
}

// trustedIssuerInput — вход федеративной выдачи с одним доверенным субъектом.
func trustedIssuerInput() IssueInput {
	return IssueInput{
		ServiceAccountID: "sva_test000000000000",
		CreatedByUserID:  "usr_admin00000000000",
		TrustedSubjects: []domain.TrustedSubject{{
			Issuer:         "https://kube.cluster.local",
			SubjectPattern: "^system:serviceaccount:ci:deployer$",
			PublicKeyPEM:   testIssuerPublicKeyPEM,
			KeyAlgorithm:   "ES256",
		}},
	}
}

// TestIssue_Federated_WritesTheTrustListIntoOurTable — перечень записан, и
// записан ТОЧНЫМ субъектом вместе с ключом издателя.
func TestIssue_Federated_WritesTheTrustListIntoOurTable(t *testing.T) {
	repo := &stubSAClientRepo{}
	ops := &stubOpsRepo{}
	ti := &fakeTrustedIssuers{}
	u := NewIssueSAKeyUseCase(repo, &stubTx{}, &stubHydra{}, ops).WithTrustedIssuerWriter(ti)

	if _, err := u.Execute(context.Background(), trustedIssuerInput()); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	waitForOp(t, ops)

	if !repo.insertOK {
		t.Fatal("строка ключа обязана быть записана на успехе")
	}
	if len(ti.calls) != 1 {
		t.Fatalf("записей перечня = %d; ожидалась 1", len(ti.calls))
	}
	got := ti.calls[0]
	if len(got.subjects) != 1 {
		t.Fatalf("доверенных субъектов = %d; ожидался 1", len(got.subjects))
	}
	if got.subjects[0].Issuer != "https://kube.cluster.local" {
		t.Errorf("издатель = %q", got.subjects[0].Issuer)
	}
	if got.subjects[0].KeyAlgorithm != "ES256" || got.subjects[0].PublicKeyPEM == "" {
		t.Error("ключевой материал издателя обязан доехать до перечня: без него запись не отвергает ничего")
	}
	if got.clientID != repo.inserted.ID {
		t.Errorf("перечень привязан к %q, а строка ключа — %q", got.clientID, repo.inserted.ID)
	}
}

// TestIssue_Federated_TrustListFailureLeavesNoKeyRow — отказ записи перечня не
// оставляет строки ключа.
//
// Ключ, чей перечень не записан, не примет никого. Останься строка — выдача
// ответила бы успехом на удостоверение, которым нельзя воспользоваться, и узнал
// бы об этом только тот, кто попробует им предъявиться.
func TestIssue_Federated_TrustListFailureLeavesNoKeyRow(t *testing.T) {
	repo := &stubSAClientRepo{}
	ops := &stubOpsRepo{}
	ti := &fakeTrustedIssuers{err: errors.New("trust list write failed")}
	u := NewIssueSAKeyUseCase(repo, &stubTx{}, &stubHydra{}, ops).WithTrustedIssuerWriter(ti)

	if _, err := u.Execute(context.Background(), trustedIssuerInput()); err != nil {
		t.Fatalf("Execute (sync): %v", err)
	}
	waitForOp(t, ops)

	if ops.lastErr == nil {
		t.Fatal("операция обязана завершиться отказом")
	}
	if len(ti.calls) != 0 {
		t.Error("отказавшая запись не считается записанной")
	}
}

// TestIssue_Federated_WithoutTheTrustListWriterIsRefused — СТРАЖ ПРОВЯЗКИ.
//
// Посадка, забывшая провязать писателя перечня, обязана отказать в выдаче, а не
// выдать ключ без перечня. Второе объявило бы возможность, которая не работает
// ни при каком входе, — и выглядело бы это как исправная выдача.
func TestIssue_Federated_WithoutTheTrustListWriterIsRefused(t *testing.T) {
	repo := &stubSAClientRepo{}
	ops := &stubOpsRepo{}
	u := NewIssueSAKeyUseCase(repo, &stubTx{}, &stubHydra{}, ops)

	if _, err := u.Execute(context.Background(), trustedIssuerInput()); err != nil {
		t.Fatalf("Execute (sync): %v", err)
	}
	waitForOp(t, ops)

	if ops.lastErr == nil {
		t.Fatal("выдача без писателя перечня обязана отказать")
	}
	if repo.insertOK {
		t.Error("строки ключа быть не должно")
	}
}

// TestIssue_Federated_TrustBindingDoesNotOutliveTheKey — срок доверия равен
// сроку ключа.
//
// Доверие постороннему издателю не вправе пережить удостоверение, ради которого
// выдавалось: иначе снятие ключа оставляло бы стоять поручительство за чужой
// субъект.
func TestIssue_Federated_TrustBindingDoesNotOutliveTheKey(t *testing.T) {
	repo := &stubSAClientRepo{}
	ops := &stubOpsRepo{}
	ti := &fakeTrustedIssuers{}
	u := NewIssueSAKeyUseCase(repo, &stubTx{}, &stubHydra{}, ops).WithTrustedIssuerWriter(ti)

	in := trustedIssuerInput()
	in.TTLSeconds = 3600
	if _, err := u.Execute(context.Background(), in); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	waitForOp(t, ops)

	if len(ti.calls) != 1 {
		t.Fatalf("записей перечня = %d", len(ti.calls))
	}
	if ti.calls[0].expiresAt == nil {
		t.Fatal("срок доверия обязан быть назван, раз назван срок ключа")
	}
	if repo.inserted.ExpiresAt == nil || !ti.calls[0].expiresAt.Equal(*repo.inserted.ExpiresAt) {
		t.Errorf("срок доверия %v не совпал со сроком ключа %v",
			ti.calls[0].expiresAt, repo.inserted.ExpiresAt)
	}
}
