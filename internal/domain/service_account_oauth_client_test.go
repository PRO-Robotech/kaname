// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// service_account_oauth_client_test.go — domain validation for the
// private_key_jwt shape and the federation-IN (trusted_subjects) shape of the
// SA-OAuth-client mapping.
package domain

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
)

// testSPKI и testPrivatePEM — НАСТОЯЩИЕ ключи, а не правдоподобные строки.
//
// Валидация проверяет разбираемость, поэтому фикстура, похожая на ключ и им не
// являющаяся, отвергалась бы вместе с положительным контролем. Обратный случай
// хуже: приняв заглушку, проба перестала бы отличать «ключ разобран» от
// «разобралось что угодно».
var testSPKI, testPrivatePEM = func() (string, string) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	pub, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		panic(err)
	}
	priv, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		panic(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub})),
		string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: priv}))
}()

func TestTrustedSubject_Validate(t *testing.T) {
	tests := []struct {
		name    string
		in      TrustedSubject
		wantErr string // substring; "" = expect nil
	}{
		{
			name:    "ok literal anchored k8s subject",
			in:      TrustedSubject{PublicKeyPEM: testSPKI, KeyAlgorithm: "ES256", Issuer: "https://kube.cluster.local", SubjectPattern: "^system:serviceaccount:ci:deployer$"},
			wantErr: "",
		},
		{
			name:    "ok literal anchored ci subject",
			in:      TrustedSubject{PublicKeyPEM: testSPKI, KeyAlgorithm: "ES256", Issuer: "https://token.actions.githubusercontent.com", SubjectPattern: "^repo:acme/app:ref:refs/heads/main$"},
			wantErr: "",
		},
		{
			name:    "empty issuer",
			in:      TrustedSubject{PublicKeyPEM: testSPKI, KeyAlgorithm: "ES256", Issuer: "", SubjectPattern: "^x$"},
			wantErr: "issuer: required",
		},
		{
			name:    "non-url issuer",
			in:      TrustedSubject{PublicKeyPEM: testSPKI, KeyAlgorithm: "ES256", Issuer: "not-a-url", SubjectPattern: "^x$"},
			wantErr: "https URL to a public host",
		},
		{
			name:    "non-https issuer",
			in:      TrustedSubject{PublicKeyPEM: testSPKI, KeyAlgorithm: "ES256", Issuer: "http://x.example", SubjectPattern: "^x$"},
			wantErr: "https URL to a public host",
		},
		{
			name:    "loopback issuer (anti-SSRF)",
			in:      TrustedSubject{PublicKeyPEM: testSPKI, KeyAlgorithm: "ES256", Issuer: "https://127.0.0.1", SubjectPattern: "^x$"},
			wantErr: "https URL to a public host",
		},
		{
			name:    "localhost issuer (anti-SSRF)",
			in:      TrustedSubject{PublicKeyPEM: testSPKI, KeyAlgorithm: "ES256", Issuer: "https://localhost", SubjectPattern: "^x$"},
			wantErr: "https URL to a public host",
		},
		{
			name:    "private-ip issuer (anti-SSRF)",
			in:      TrustedSubject{PublicKeyPEM: testSPKI, KeyAlgorithm: "ES256", Issuer: "https://10.1.2.3", SubjectPattern: "^x$"},
			wantErr: "https URL to a public host",
		},
		{
			name:    "empty pattern",
			in:      TrustedSubject{PublicKeyPEM: testSPKI, KeyAlgorithm: "ES256", Issuer: "https://x.example", SubjectPattern: ""},
			wantErr: "subject_pattern: required",
		},
		{
			name:    "unanchored pattern",
			in:      TrustedSubject{PublicKeyPEM: testSPKI, KeyAlgorithm: "ES256", Issuer: "https://x.example", SubjectPattern: "system:serviceaccount:ci:deployer"},
			wantErr: "literal anchored subject",
		},
		{
			name:    "missing closing anchor",
			in:      TrustedSubject{PublicKeyPEM: testSPKI, KeyAlgorithm: "ES256", Issuer: "https://x.example", SubjectPattern: "^system:serviceaccount:ci:deployer"},
			wantErr: "literal anchored subject",
		},
		{
			name:    "wildcard .* pattern",
			in:      TrustedSubject{PublicKeyPEM: testSPKI, KeyAlgorithm: "ES256", Issuer: "https://x.example", SubjectPattern: "^system:serviceaccount:ci:.*$"},
			wantErr: "literal anchored subject",
		},
		{
			name:    "glob star pattern",
			in:      TrustedSubject{PublicKeyPEM: testSPKI, KeyAlgorithm: "ES256", Issuer: "https://x.example", SubjectPattern: "^system:serviceaccount:ci:*$"},
			wantErr: "literal anchored subject",
		},
		{
			name:    "bare wildcard",
			in:      TrustedSubject{PublicKeyPEM: testSPKI, KeyAlgorithm: "ES256", Issuer: "https://x.example", SubjectPattern: ".*"},
			wantErr: "literal anchored subject",
		},
		// Ключевой материал ИЗДАТЕЛЯ — с задачи #1124. Пустой ключ означал бы
		// «доверяем паре без проверки подписи», то есть ровно тот класс, ради
		// которого перечень и заводится.
		{
			name:    "ключ издателя не назван",
			in:      TrustedSubject{Issuer: "https://x.example", SubjectPattern: "^x$", KeyAlgorithm: "ES256"},
			wantErr: "public_key_pem: required",
		},
		{
			name:    "алгоритм издателя не назван",
			in:      TrustedSubject{Issuer: "https://x.example", SubjectPattern: "^x$", PublicKeyPEM: testSPKI},
			wantErr: "key_algorithm: required",
		},
		{
			name: "алгоритм вне закрытого словаря",
			in: TrustedSubject{Issuer: "https://x.example", SubjectPattern: "^x$",
				PublicKeyPEM: testSPKI, KeyAlgorithm: "HS256"},
			wantErr: "key_algorithm: must be one of",
		},
		{
			name: "ключ не разбирается",
			in: TrustedSubject{Issuer: "https://x.example", SubjectPattern: "^x$",
				PublicKeyPEM: "not a pem at all", KeyAlgorithm: "ES256"},
			wantErr: "not a PEM block",
		},
		{
			// Закрытая половина, попавшая сюда по недосмотру называющего, была
			// бы принята как «ключ есть» — и мы взяли бы на хранение чужой
			// секрет, которого просить не должны.
			name: "прислан закрытый ключ вместо открытого",
			in: TrustedSubject{Issuer: "https://x.example", SubjectPattern: "^x$",
				PublicKeyPEM: testPrivatePEM, KeyAlgorithm: "ES256"},
			wantErr: "private key was supplied",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.in.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("want nil, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("want err containing %q, got %v", tt.wantErr, err)
			}
		})
	}
}

// TestTrustedSubject_LiteralSubject — a valid literal-anchored pattern yields the
// unanchored literal (the exact subject the Hydra trust-grant enforces); a
// non-literal / non-anchored pattern is not extractable.
func TestTrustedSubject_LiteralSubject(t *testing.T) {
	ok := TrustedSubject{Issuer: "https://kube.cluster.local", SubjectPattern: "^system:serviceaccount:ci:deployer$"}
	lit, ok2 := ok.LiteralSubject()
	if !ok2 {
		t.Fatalf("expected literal-anchored pattern to be extractable")
	}
	if lit != "system:serviceaccount:ci:deployer" {
		t.Fatalf("literal = %q; want the unanchored subject", lit)
	}

	bad := TrustedSubject{Issuer: "https://kube.cluster.local", SubjectPattern: "^system:serviceaccount:ci:.*$"}
	if _, ok3 := bad.LiteralSubject(); ok3 {
		t.Fatalf("wildcard pattern must NOT yield a literal subject")
	}
}

func TestSAOAuthClient_Validate_FederatedVsPrivateKey(t *testing.T) {
	base := ServiceAccountOAuthClient{
		ID:              "soc_01abcdefghjkmnpqr",
		SvaID:           "sva_01",
		OAuthClientID:   "hydra-cli",
		CreatedByUserID: "usr_01",
		// Имя названо явно, потому что предмет этой пробы — вид удостоверения,
		// а не имя: строка без имени отвергалась бы формой (#1279), и
		// положительный контроль ниже падал бы по чужой причине.
		Name: "federated-key",
	}

	// Federated row with public_key set → must reject.
	bad := base
	bad.TrustedSubjects = []TrustedSubject{{Issuer: "https://x.example", SubjectPattern: "^x$",
		PublicKeyPEM: testSPKI, KeyAlgorithm: "ES256"}}
	bad.PublicKeyPEM = "fake-pem"
	bad.KeyAlgorithm = "ES256"
	if err := bad.Validate(); err == nil || !strings.Contains(err.Error(), "must not carry public_key_pem") {
		t.Fatalf("want federated/public_key conflict, got %v", err)
	}

	// Federated row clean — must pass.
	ok := base
	ok.TrustedSubjects = []TrustedSubject{{Issuer: "https://x.example", SubjectPattern: "^x$",
		PublicKeyPEM: testSPKI, KeyAlgorithm: "ES256"}}
	if err := ok.Validate(); err != nil {
		t.Fatalf("clean federated must pass, got %v", err)
	}

	// private_key_jwt row — must pass.
	pk := base
	pk.PublicKeyPEM = "fake-spki"
	pk.KeyAlgorithm = "ES256"
	if err := pk.Validate(); err != nil {
		t.Fatalf("private_key_jwt must pass, got %v", err)
	}
}
