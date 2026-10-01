// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// retired_vendor_bindings_ledger.go — ВЕДОМОСТЬ привязок к снимаемому провайдеру
// личности, по файлу. Судит её `retired_vendor_bindings.go`; единица счёта —
// `RetiredVendorCountingUnit`.
//
// Число записи — ТОЧНОЕ число привязок файла, а не потолок:
//
//   - изменение сняло привязки — число записи снижается тем же изменением до
//     того, что печатает находка «убыль не записана»;
//   - в файле привязок не осталось либо файл снят — запись снимается;
//   - привязка перенесена в другой файл — запись того файла заводится, а
//     прежнего снижается, и обе правки стоят в одном диффе рядом.
//
// Запись ЗАНИМАЕТ ДВЕ СТРОКИ — путь и число: две ветки, снявшие привязки в
// соседних по порядку файлах, правят несоседние строки и сливаются без
// конфликта (обоснование — шапка `retired_vendor_bindings.go`). Пути строго по
// возрастанию: форма проверяется судьёй, и место новой записи однозначно.
//
// Точка отсчёта — дерево 8f95be6c6 (голова линии #367 на момент заведения),
// из которого тем же изменением сняты шесть строк роста, найденного задачей
// #323: две пробы полос хуков задавали адрес прежнего издателя, которого не
// судят. На сведённом дереве сборки волны 4 (#483) записи приведены вниз к
// факту: полосы волны снимали привязки, ещё не зная этой ведомости. Рост,
// который они принесли в пяти файлах, НЕ записан: три файла сняли привязки по
// существу, а строки миграции, снявшей столбец зеркала, и её пробы — история
// схемы снятого идентификатора (`retired_vendor_schema_history.go`); то же
// снятие снизило запись свода, который столбец завёл. Ни одна запись не
// поднималась выше точки отсчёта и ни одна не заведена сверх неё. Каждая
// запись уходит вниз вместе с изменением, снимающим её привязки.
package check

// RetiredVendorLedger — точное число привязок по файлу, по возрастанию пути.
var RetiredVendorLedger = []RetiredVendorLedgerEntry{
	{File: "deploy/foreign_operator_declared_injection_test.go",
		Bindings: 1},
	{File: "docs/specs/reviews/access-keys-are-ours/79a82b12e95fe969b29b960ad98c02685dc97363cddd1f565ed778f5baaa531c.yaml",
		Bindings: 1},
	{File: "docs/specs/reviews/assurance-level-is-declared-by-our-session/87d47598d5b7fc860492709b7d2fdbca4fb851e0795cd07fce2c336aeb860a66.yaml",
		Bindings: 1},
	{File: "docs/specs/reviews/assurance-level-is-declared-by-our-session/c67a550612873247126eff7baf4ee68200fe136c200c3c0c039af18f17f17d6f.yaml",
		Bindings: 1},
	{File: "docs/specs/reviews/login-lane-issues-our-session-and-logout-ends-it-server-side/1a7f6846d102068bd7023eab4527010b573a22f43a1c988416a4c5f63e1a1170.yaml",
		Bindings: 1},
	{File: "docs/specs/reviews/login-lane-issues-our-session-and-logout-ends-it-server-side/f0c5850724d1372fb4be5d305c7bbcd22e45bbf613315912ed88bd3ab06e7fed.yaml",
		Bindings: 2},
	{File: "docs/specs/reviews/login-session-and-credentials-are-our-contract/664d261d56f3b8c845f0fe3e958d7a968b78b207c0073010835cca715cf3ac7e.yaml",
		Bindings: 3},
	{File: "docs/specs/reviews/login-session-and-credentials-are-our-contract/8893e52c686f57076c3f556803264dab5a0dea309e4c578f51a69f1dfdb4b24c.yaml",
		Bindings: 6},
	{File: "docs/specs/reviews/login-session-and-credentials-are-our-contract/8cdb75fcc0139c48bd0d78fd36ecbc398328428c24d386865eb02e2dc14d32e5.yaml",
		Bindings: 2},
	{File: "docs/specs/reviews/login-session-and-credentials-are-our-contract/d65209d603f2b9fb455571af072f3fd00ad82b7229bd5e6a453866ad2225b12d.yaml",
		Bindings: 3},
	{File: "docs/specs/reviews/login-session-and-credentials-are-our-contract/f8ea0dd42091d04138cd055a43e0ff3a4ffa6de82ef37d8b7d36768e3a16f9b8.yaml",
		Bindings: 1},
	{File: "docs/specs/reviews/password-verifier-follows-the-stored-value/2554fb6f46fa7f5768f746b5d620843fc045e53d7778919d9829f1b9467070cb.yaml",
		Bindings: 1},
	{File: "docs/specs/reviews/password-verifier-follows-the-stored-value/52bb1359370197d81ef5b9a42d75b83ff47dec17e787573a2495c8ff3f3cb852.yaml",
		Bindings: 1},
	{File: "docs/specs/reviews/password-verifier-follows-the-stored-value/b191a212653e8ac0caa9d58a663e884b31bd23995c5525c50fe2202fc763bbef.yaml",
		Bindings: 1},
	{File: "docs/specs/reviews/passwordless-login-with-access-key/305f0777c4864536746b45977419b55fa6e8c0b12985148b7a0ab34a21ced05f.yaml",
		Bindings: 1},
	{File: "docs/specs/reviews/passwordless-login-with-access-key/449a08dda5a3c693a81eb8acbee91767355ba57a227128ed9b73c07237c8bbdf.yaml",
		Bindings: 1},
	{File: "docs/specs/reviews/recovery-of-access/e889257fcf903394913affa761dc3d55ab54c8616c34175adce5cce63abcdc39.yaml",
		Bindings: 1},
	{File: "docs/specs/reviews/registration-and-its-three-consequences/397640b0fb41191a55aa6838c5a726e78151511d77203aa3192d70cf7f990be0.yaml",
		Bindings: 1},
	{File: "docs/specs/reviews/second-factor-totp-and-recovery-codes/08b6e9f7adfc32cd859c1aff6f5c211c708ca84e0e857f915173d346b9b490d3.yaml",
		Bindings: 2},
	{File: "internal/apps/kaname/api/audit/user_audit_integration_test.go",
		Bindings: 1},
	{File: "internal/apps/kaname/config/lane_gates_injection_test.go",
		Bindings: 3},
	{File: "internal/apps/kaname/config/lane_gates_test.go",
		Bindings: 1},
	{File: "internal/authzguard/public_caller_policy_test.go",
		Bindings: 1},
	{File: "internal/bootstraptokenwire/provider_absent_injection_test.go",
		Bindings: 1},
	{File: "internal/check/carried_coordinate_ledger_test.go",
		Bindings: 1},
	{File: "internal/check/retired_issuer_claim.go",
		Bindings: 6},
	{File: "internal/check/retired_issuer_claim_injection_test.go",
		Bindings: 12},
	{File: "internal/check/retired_vendor_bindings.go",
		Bindings: 1},
	{File: "internal/domain/user_test.go",
		Bindings: 1},
	{File: "internal/errors/client_vocabulary_test.go",
		Bindings: 1},
	{File: "internal/migrations/0001_initial.sql",
		Bindings: 1},
	{File: "internal/migrations/20260917015400_recovery_code_is_our_record.sql",
		Bindings: 1},
	{File: "internal/repo/kaname/pg/name_form_constraint_integration_test.go",
		Bindings: 1},
	{File: "pkg/api/kaname/cloud/iam/v1/service_account_oauth_client.pb.go",
		Bindings: 1},
	{File: "pkg/api/kaname/cloud/iam/v1/user_oauth_client.pb.go",
		Bindings: 1},
	{File: "proto/kaname/cloud/iam/v1/service_account_oauth_client.proto",
		Bindings: 1},
	{File: "proto/kaname/cloud/iam/v1/user_oauth_client.proto",
		Bindings: 1},
	{File: "scripts/provider-revocation-equivalence-probe.sh",
		Bindings: 2},
	{File: "tests/newman/cases/rbac-subject-channel-equivalence.py",
		Bindings: 1},
	{File: "tests/newman/scripts/selftest_token_facade_forms.py",
		Bindings: 1},
}
