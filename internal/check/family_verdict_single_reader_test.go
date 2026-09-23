// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// family_verdict_single_reader_test.go — гейт на РЕАЛЬНОМ дереве: решение «отозвано
// ли семейство выпуска» читается одним оператором, порт зовёт только правило, и
// правило зовёт каждая поверхность предъявления (kaname#319).
//
// Предмет и границы — в шапке `family_verdict_single_reader.go`. Способность
// упасть доказана инъекцией — `family_verdict_single_reader_injection_test.go`.
package check_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/treecorpus"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// familyVerdictSurfaces — ЗАКРЫТЫЙ перечень поверхностей предъявления, судящих
// о выпуске семейства. Поверхность, заведённая и не вписанная сюда, гейтом не
// судится — поэтому перечень держит и проба предпосылки ниже: каждый каталог
// перечня существует.
var familyVerdictSurfaces = []string{
	// IsRevoked службы отзыва — внутренний слушатель.
	"internal/apps/kaname/api/session_revocations",
	// Авторитет отзыва — сюда край идёт на пути запроса за нашим токеном.
	"internal/handler/tokenintrospecthttp",
	// Читатель предъявленного — публичный слушатель.
	"internal/presentedcred",
}

// prodGoFiles — непроверочные исходники каталогов internal и cmd модуля: путь
// относительно корня в косой записи → текст.
func prodGoFiles(t *testing.T, root string) map[string]string {
	t.Helper()
	files := map[string]string{}
	for _, d := range []string{"internal", "cmd"} {
		paths, err := treecorpus.UnderWithSuffix(filepath.Join(root, d), ".go")
		if err != nil {
			t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: обход %s: %v", d, err)
		}
		for _, p := range paths {
			if strings.HasSuffix(p, "_test.go") {
				continue
			}
			b, err := os.ReadFile(p) // #nosec G304 -- путь из состава дерева этого модуля
			if err != nil {
				t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: чтение %s: %v", p, err)
			}
			rel, err := filepath.Rel(root, p)
			if err != nil {
				t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: относительный путь %s: %v", p, err)
			}
			files[filepath.ToSlash(rel)] = string(b)
		}
	}
	return files
}

// TestFamilyVerdictHasOneReaderAndEverySurfaceAsksTheRule — предмет.
func TestFamilyVerdictHasOneReaderAndEverySurfaceAsksTheRule(t *testing.T) {
	t.Parallel()
	root := moduleRoot(t)

	// Предпосылка: каждый каталог перечня существует. Исчезнувший каталог —
	// находка, а не молчание: поверхность, которую гейт больше не видит, он и
	// не судит.
	for _, s := range familyVerdictSurfaces {
		if st, err := os.Stat(filepath.Join(root, filepath.FromSlash(s))); err != nil || !st.IsDir() {
			t.Errorf("поверхность перечня %s в дереве не найдена — перечень пережил свой предмет", s)
		}
	}

	files := prodGoFiles(t, root)
	census, err := check.FamilyVerdict(files)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	t.Logf("перепись: файлов %d · литералов %d · вызовов %d · читателей записи выпуска %d · "+
		"вызовов порта мимо правила %d · каталогов, зовущих правило, %d",
		census.FilesParsed, census.LiteralsSeen, census.CallsSeen, len(census.Readers),
		len(census.Bypasses), len(census.RuleCallers))
	for _, f := range check.FamilyVerdictFindings(census, familyVerdictSurfaces) {
		t.Error(f)
	}
}
