// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// handler_federated_passthrough_test.go — ключевой материал издателя, названный
// ВЫЗЫВАЮЩИМ на проводе, обязан доехать до перечня доверия.
//
// # Почему проба стоит здесь, а не рядом с use-case
//
// Пробы уровня use-case строят IssueInput сами и потому шва «провод → домен» не
// видят вовсе: они остаются зелёными ровно тогда, когда транспорт поле роняет.
// Свойство, которое здесь утверждается, — свойство ШВА, и наблюдается оно только
// через хендлер.
//
// # Какой класс это ловит
//
// «Принято-и-проигнорировано» (api-conventions.md) в худшей его форме. Поле
// объявлено обязательным и на проводе, и в домене, а транспорт его не переносит.
// Тогда федеративная выдача отвергает ЛЮБОЙ вход, включая полностью законный, и
// называет негодным поле, которое вызывающий прислал, — то есть возможность
// объявлена, задокументирована, покрыта типами и не работает ни при каком входе
// (api-conventions.md, «Неисполнимая возможность: ДВА ПРАВИЛА ОБ ОДНОМ ПОЛЕ»).
package sa_keys

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
	"github.com/PRO-Robotech/kacho/pkg/operations"
)

// wireTrustedSubject — законный доверенный субъект В ФОРМЕ ПРОВОДА.
//
// Ключ здесь настоящий (testIssuerPublicKeyPEM разбирается доменом), а не
// правдоподобная строка: приняв заглушку, проба перестала бы отличать «ключ
// доехал» от «доехало что угодно».
func wireTrustedSubject() *iamv1.TrustedSubject {
	return &iamv1.TrustedSubject{
		Issuer:         "https://kube.cluster.local",
		SubjectPattern: "^system:serviceaccount:ci:deployer$",
		PublicKeyPem:   testIssuerPublicKeyPEM,
		KeyAlgorithm:   "ES256",
	}
}

// TestHandlerIssue_Federated_IssuerKeyMaterialReachesTheTrustList — положительная
// половина, и она же та, ради которой проба написана.
//
// Законная федеративная выдача обязана (а) не быть отвергнутой и (б) записать в
// перечень ТОТ ЖЕ ключ и ТОТ ЖЕ алгоритм, что назвал вызывающий. Утверждать
// только (а) недостаточно: транспорт, подставляющий вместо присланного ключа
// что угодно непустое, прошёл бы такую пробу.
func TestHandlerIssue_Federated_IssuerKeyMaterialReachesTheTrustList(t *testing.T) {
	repo := &stubSAClientRepo{}
	ops := &stubOpsRepo{}
	ti := &fakeTrustedIssuers{}
	uc := NewIssueSAKeyUseCase(repo, &stubTx{}, &stubHydra{}, ops).WithTrustedIssuerWriter(ti)
	h := NewHandler(uc, nil, nil)

	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: "usr00000000000000007"})

	_, err := h.Issue(ctx, &iamv1.IssueSAKeyRequest{
		ServiceAccountId: "sva00000000000000001",
		TrustedSubjects:  []*iamv1.TrustedSubject{wireTrustedSubject()},
	})
	require.NoError(t, err,
		"законная федеративная выдача не может отвергаться: вызывающий прислал каждое обязательное поле")
	waitForOp(t, ops)
	require.Nil(t, ops.lastErr, "асинхронная половина выдачи обязана завершиться успехом")

	require.Len(t, ti.calls, 1, "перечень доверия обязан быть записан ровно один раз")
	require.Len(t, ti.calls[0].subjects, 1, "доверенный субъект обязан доехать")
	got := ti.calls[0].subjects[0]
	require.Equal(t, "https://kube.cluster.local", got.Issuer)
	require.Equal(t, "^system:serviceaccount:ci:deployer$", got.SubjectPattern)
	require.Equal(t, testIssuerPublicKeyPEM, got.PublicKeyPEM,
		"ключ издателя обязан доехать ДОСЛОВНО: перечень без ключа не отвергает ничего")
	require.Equal(t, "ES256", got.KeyAlgorithm,
		"алгоритм обязан доехать: пустое значение означает «ключа нет», а не «любой алгоритм»")
}

// TestHandlerIssue_Federated_MissingIssuerKeyIsRefusedNamingTheField — парная
// отрицательная половина.
//
// Без неё положительная проба не отличала бы «поле переносится» от «проверка
// снята»: транспорт, перестающий требовать ключ, прошёл бы её так же. Отказ
// обязан НАЗЫВАТЬ поле — иначе вызывающий не знает, что менять.
func TestHandlerIssue_Federated_MissingIssuerKeyIsRefusedNamingTheField(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*iamv1.TrustedSubject)
		field  string
	}{
		{"no public key", func(s *iamv1.TrustedSubject) { s.PublicKeyPem = "" }, "public_key_pem"},
		{"no algorithm", func(s *iamv1.TrustedSubject) { s.KeyAlgorithm = "" }, "key_algorithm"},
		{"algorithm outside the dictionary", func(s *iamv1.TrustedSubject) { s.KeyAlgorithm = "HS256" }, "key_algorithm"},
		{"a private key where a public one belongs", func(s *iamv1.TrustedSubject) {
			s.PublicKeyPem = "-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n"
		}, "public_key_pem"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := &stubSAClientRepo{}
			ops := &stubOpsRepo{}
			ti := &fakeTrustedIssuers{}
			uc := NewIssueSAKeyUseCase(repo, &stubTx{}, &stubHydra{}, ops).WithTrustedIssuerWriter(ti)
			h := NewHandler(uc, nil, nil)

			ctx := operations.WithPrincipal(context.Background(),
				operations.Principal{Type: "user", ID: "usr00000000000000007"})

			subject := wireTrustedSubject()
			tc.mutate(subject)

			_, err := h.Issue(ctx, &iamv1.IssueSAKeyRequest{
				ServiceAccountId: "sva00000000000000001",
				TrustedSubjects:  []*iamv1.TrustedSubject{subject},
			})
			require.Error(t, err, "запись доверия без пригодного ключа издателя не примет никого")
			require.Equal(t, codes.InvalidArgument, grpcstatus.Code(err))
			require.Contains(t, grpcstatus.Convert(err).Message(), tc.field,
				"отказ обязан называть поле")
			require.Empty(t, ti.calls, "отвергнутая выдача не пишет перечня")
		})
	}
}
