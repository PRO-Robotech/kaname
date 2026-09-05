// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// derived_id_test.go — деривация детерминированного идентификатора (приёмка
// `roles-come-as-data-not-migrations.md` §3.3; сценарии MOD-RD-07 … MOD-RD-11).
//
// # Ожидаемые значения посчитаны НЕ этим кодом
//
// Проба, сверяющая функцию с собственной копией формулы, зелена всегда.
// Литералы ниже вычислены сторонним счётчиком (`hashlib.md5(...).hexdigest()`)
// и вписаны дословно; совпадение с постгресовым `substr(md5(s),1,17)` следует из
// того, что MD5 один, а не из того, что мы так решили.
//
// Полное утверждение MOD-RD-07 — на ЖИВОМ наборе из сорока шести имён — здесь
// невыразимо: у этих имён миграция несёт ВЫРАЖЕНИЕ `'rol' || substr(md5(…),1,17)`,
// а не литерал, поэтому сверять статически не с чем (приёмка §12.3). Оно живёт
// интеграционной пробой, и её единица названа там же.
package domain_test

import (
	"testing"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
)

// TestMODRD07SystemRoleIDDerivesFromTheNameVerbatim — идентичность системной
// роли есть функция её ИМЕНИ, и функция та самая, что стоит в применённых
// миграциях.
func TestMODRD07SystemRoleIDDerivesFromTheNameVerbatim(t *testing.T) {
	// Имя → идентификатор, посчитанный сторонним счётчиком. Первые три имени —
	// живые системные роли дерева (`0001_initial.sql`), четвёртое — служебная
	// учётка модуля (`0057_storage_sa_least_priv.sql`).
	cases := map[string]string{
		"vpc.network.admin":     "rol8ed48ecc3878c2e73",
		"iam.role.view":         "rolee27bb5ba1efb68cb",
		"compute.instance.edit": "rol79a7325eb0d31fad4",
		"module.storage_sa":     "rol2ef08a40c45493ee3",
	}
	for name, want := range cases {
		if got := domain.SystemRoleID(domain.RoleName(name)); string(got) != want {
			t.Errorf("SystemRoleID(%q) = %q, а миграция адресует строку как %q — "+
				"выдачи по прежнему идентификатору перестали бы резолвиться МОЛЧА: "+
				"`role_id` остаётся синтаксически верным и не находит строки",
				name, got, want)
		}
	}
}

// TestDerivedIDSuffixIsSeventeenHexChars — форма суффикса: ровно семнадцать
// шестнадцатеричных символов. Отдельно от значений выше, потому что это
// свойство ФОРМЫ: шестнадцать вместо семнадцати дают идентификатор верной формы,
// не совпадающий НИ С ОДНОЙ строкой (инъекция Г1а).
func TestDerivedIDSuffixIsSeventeenHexChars(t *testing.T) {
	const seed = "kacho-bootstrap-admin"
	got := domain.DerivedIDSuffix(seed)
	if len(got) != 17 {
		t.Fatalf("DerivedIDSuffix(%q) даёт %d символов, а миграции адресуют строки семнадцатью",
			seed, len(got))
	}
	for i, r := range got {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			t.Fatalf("DerivedIDSuffix(%q)[%d] = %q — не шестнадцатеричный символ нижнего регистра",
				seed, i, r)
		}
	}
	if want := "b91854890de887e6d"; got != want {
		t.Errorf("DerivedIDSuffix(%q) = %q, ожидалось %q (сторонний счётчик)", seed, got, want)
	}
}
