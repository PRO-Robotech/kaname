// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// assertion_verifier_single_injection_test.go — инъекция в обе стороны на
// синтетике (Ф13-31): копия сверки под другим именем в пакете полосы —
// красное с координатой; законный близнец — обёртка, ЗОВУЩАЯ проверяющего, —
// молчит и считается вызывающим; псевдоним импорта примитива не прячет копию.
package check_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
)

const avHome = `package webauthnverify
import "crypto/ecdsa"
func verifySignature(k *ecdsa.PublicKey, h, sig []byte) bool { return ecdsa.VerifyASN1(k, h, sig) }
func VerifyAssertion() {}`

func TestAssertionVerifierInjection_CopyIsFoundTwinIsSilent(t *testing.T) {
	t.Parallel()
	twin := `package humansession
import wv "github.com/PRO-Robotech/kaname/internal/webauthnverify"
func (uc *AccessKeyLoginUseCase) Execute() { wv.VerifyAssertion() }`
	copyOf := `package humansession
import sig "crypto/ecdsa"
func checkLoginAssertion(k *sig.PublicKey, h, s []byte) bool { return sig.VerifyASN1(k, h, s) }`

	findings, c, err := check.JudgeAssertionVerifiers(check.TreeCorpus{
		"internal/webauthnverify/verify.go":                         avHome,
		"internal/apps/kaname/api/humansession/access_key_login.go": twin,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 || len(c.Declarations) != 1 || len(c.Callers) != 1 {
		t.Fatalf("законный близнец обязан молчать и считаться вызывающим: находки %v, перепись %+v", findings, c)
	}

	findings, _, err = check.JudgeAssertionVerifiers(check.TreeCorpus{
		"internal/webauthnverify/verify.go":                   avHome,
		"internal/apps/kaname/api/humansession/copy_of_it.go": copyOf,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || !strings.Contains(findings[0], "internal/apps/kaname/api/humansession/copy_of_it.go:3") ||
		!strings.Contains(findings[0], "checkLoginAssertion") {
		t.Fatalf("копия сверки под псевдонимом обязана краснеть с координатой: %v", findings)
	}

	_, c, err = check.JudgeAssertionVerifiers(check.TreeCorpus{"internal/webauthnverify/verify.go": `package webauthnverify`})
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Declarations) != 0 {
		t.Fatalf("дом без сверки — объявлений ноль, пробе ответить «предмета нет»: %+v", c)
	}
}
