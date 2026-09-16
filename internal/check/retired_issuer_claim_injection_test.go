// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// Инъекция в обе стороны: КАЖДАЯ форма утверждения даёт находку с координатой,
// её надгробный близнец молчит, нейтральное упоминание молчит, пустой корпус —
// отказ, а не «находок нет».
func TestRetiredIssuerClaim_InjectionBothWays(t *testing.T) {
	t.Parallel()

	defects := map[string]string{
		"остаётся (stays/remains)":       "# fetches verification keys here (Hydra stays signer/issuer).",
		"является издателем/подписантом": "// Hydra is the token issuer; the edge only verifies.",
		"ключи проверки — его":           "// The data-plane's verification keys are Hydra's, served via the mirror.",
		"служба не чеканит":              "// it does not mint tokens (Hydra does) and does not decrypt any key.",
		"остаётся (по-русски)":           "# Подписант на стенде один: издатель — Hydra, служба лишь проксирует.",
	}
	for form, line := range defects {
		t.Run("дефект: "+form, func(t *testing.T) {
			t.Parallel()
			corpus := map[string]string{"deploy/values.yaml": "a: 1\n" + line + "\nb: 2\n"}
			f, census, err := check.JudgeRetiredIssuerClaims(corpus)
			if err != nil {
				t.Fatalf("фикстура обязана судиться: %v", err)
			}
			if len(f) != 1 {
				t.Fatalf("ожидалась ровно одна находка, получено %d: %+v", len(f), f)
			}
			if f[0].File != "deploy/values.yaml" || f[0].Line != 2 {
				t.Fatalf("находка обязана называть файл и строку: %s:%d", f[0].File, f[0].Line)
			}
			if f[0].Form != form {
				t.Fatalf("форма распознана не та: хотели %q, получили %q", form, f[0].Form)
			}
			if census.Findings != 1 || census.Tombstones != 0 {
				t.Fatalf("перепись расходится с находкой: %s", census)
			}
			if !strings.Contains(f[0].String(), "deploy/values.yaml:2") {
				t.Fatalf("текст находки обязан нести координату: %s", f[0])
			}
		})
	}

	twins := map[string]string{
		"кавычки-ёлочки":     "// Здесь стояло «Hydra stays the issuer/signer» — утверждение верно про прошлое.",
		"прямые кавычки":     `// It said "Hydra remains the issuer / signer; iam only brokers" — that is false now.`,
		"маркер без кавычек": "# ЗДЕСЬ СТОЯЛО Hydra stays the SIGNER — снято 2026-09-10, подписант наш.",
		"no longer":          "// Hydra is the token issuer no longer: the key set is ours since F1.",
		"нейтральное имя":    "// дорога к прежнему издателю (KANAME_HYDRA_ADMIN_URL) собирается стражем",
		"описание полосы":    "// TokenVerifier — port для JWKS-валидации Hydra-issued access JWT.",
		"чеканит о другом":   "// Operation здесь не чеканится: отказ синхронный.",
	}
	for name, line := range twins {
		t.Run("близнец: "+name, func(t *testing.T) {
			t.Parallel()
			f, census, err := check.JudgeRetiredIssuerClaims(map[string]string{"x.go": line + "\n"})
			if err != nil {
				t.Fatalf("фикстура обязана судиться: %v", err)
			}
			if len(f) != 0 {
				t.Fatalf("законный близнец обязан молчать, получено: %+v", f)
			}
			if census.Findings != 0 {
				t.Fatalf("перепись не сошлась с молчанием: %s", census)
			}
		})
	}

	t.Run("надгробие считается, а не теряется", func(t *testing.T) {
		t.Parallel()
		_, census, err := check.JudgeRetiredIssuerClaims(map[string]string{
			"a.md": "Здесь стояло «Hydra remains the signer» — и это было верно до F1.\n",
		})
		if err != nil {
			t.Fatal(err)
		}
		if census.Claims != 1 || census.Tombstones != 1 || census.Findings != 0 {
			t.Fatalf("надгробие обязано попасть в перепись утверждений и надгробий: %s", census)
		}
	})

	t.Run("пустой корпус — отказ, не «находок нет»", func(t *testing.T) {
		t.Parallel()
		_, _, err := check.JudgeRetiredIssuerClaims(map[string]string{})
		if !errors.Is(err, check.ErrEmptyTraversal) {
			t.Fatalf("пустой корпус обязан давать ErrEmptyTraversal, получено: %v", err)
		}
	})

	t.Run("отбор корпуса: пробы и стабы вне, документация внутри", func(t *testing.T) {
		t.Parallel()
		cases := map[string]bool{
			"internal/x/y.go":                     true,
			"internal/x/y_test.go":                false,
			"pkg/api/kaname/cloud/iam/v1/a.pb.go": false,
			"tests/newman/cases/a.py":             false,
			"internal/handler/testdata/README.md": false,
			"docs/content/intro.mdx":              true,
			"deploy/values.yaml":                  true,
			"go.sum":                              false,
		}
		for rel, want := range cases {
			if got := check.RetiredIssuerProseFile(rel); got != want {
				t.Errorf("%s: хотели %v, получили %v", rel, want, got)
			}
		}
	})
}
