// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package check

// type_miss_injection_test.go — предъявление распознавателя #1980 СИНТЕТИКЕ.
//
// Гейт на дереве сегодня зелёный, и без этих проб его зелень неотличима от
// распознавателя, который не ищет ничего. Вход подаётся синтетический: обход
// живого дерева здесь не годится ни в одну сторону — дефект в него не внести, а
// доказательство, которому нужно грязное дерево, истекает вместе с грязью.
//
// Каждая проба меняет РОВНО ОДИН факт против своего положительного близнеца.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// missFixture — файл, читающий пакет и берущий у двузначного символа оба
// значения либо только первое.
func missFixture(t *testing.T, dir, name, importSpec, callSite string) string {
	t.Helper()
	body := "package fx\n\nimport (\n\t" + importSpec + "\n)\n\n" +
		"func f(module, resource string) string {\n" + callSite + "\n}\n"
	full := filepath.Join(dir, name)
	if err := os.WriteFile(full, []byte(body), 0o600); err != nil {
		t.Fatalf("фикстура %s: %v", name, err)
	}
	return full
}

const authzmapImport = `"github.com/PRO-Robotech/kacho/services/iam/internal/authzmap"`

// TestIAMCT2_TypeMissRecognizerInjection — распознаватель, обе стороны.
func TestIAMCT2_TypeMissRecognizerInjection(t *testing.T) {
	root := t.TempDir()

	cases := []struct {
		name       string
		importSpec string
		call       string
		wantMiss   int
		wantCalls  int
	}{
		{
			// ИНЪЕКЦИЯ: второе значение отброшено — находка.
			name:       "инъекция: признак отброшен",
			importSpec: authzmapImport,
			call:       "\tt, _ := authzmap.ObjectType(module, resource)\n\treturn t",
			wantMiss:   1, wantCalls: 1,
		},
		{
			// КОНТРОЛЬ: тот же вызов, признак ПРОЧИТАН — гейт молчит. Без него
			// находка выше неотличима от гейта, краснеющего на любом вызове.
			name:       "контроль: признак прочитан",
			importSpec: authzmapImport,
			call:       "\tt, ok := authzmap.ObjectType(module, resource)\n\tif !ok {\n\t\treturn \"\"\n\t}\n\treturn t",
			wantMiss:   0, wantCalls: 1,
		},
		{
			// ИНЪЕКЦИЯ: ПСЕВДОНИМ импорта. Распознаватель, знающий только
			// написание `authzmap.`, вывел бы всё написанное так ИЗ НАБЛЮДЕНИЯ —
			// не признав нарушением и не признав чистым.
			name:       "инъекция: пакет под псевдонимом",
			importSpec: `am ` + authzmapImport,
			call:       "\tt, _ := am.DottedType(module)\n\treturn t",
			wantMiss:   1, wantCalls: 1,
		},
		{
			// КОНТРОЛЬ: символ ТОТАЛЬНЫЙ (одно значение) — отбрасывать нечего, и
			// в перепись двузначных он попадать не должен.
			name:       "контроль: тотальный переходник — не двузначный",
			importSpec: authzmapImport,
			call:       "\treturn authzmap.ModelTypeName(module)",
			wantMiss:   0, wantCalls: 0,
		},
		{
			// КОНТРОЛЬ: пакет НЕ импортирован — одноимённый чужой символ находкой
			// не является. Иначе гейт судил бы слово, а не предмет.
			name:       "контроль: одноимённый символ ЧУЖОГО пакета",
			importSpec: `authzmap "strings"`,
			call:       "\tt, _ := authzmap.CutPrefix(module, resource)\n\t_ = t\n\treturn module",
			wantMiss:   0, wantCalls: 0,
		},
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(root, "c"+string(rune('a'+i)))
			if err := os.MkdirAll(dir, 0o750); err != nil {
				t.Fatalf("каталог: %v", err)
			}
			f := missFixture(t, dir, "fx.go", tc.importSpec, tc.call)
			misses, importers, calls, err := discardedTypeMisses(root, []string{f}, twoValueSymbols)
			if err != nil {
				t.Fatalf("разбор фикстуры: %v", err)
			}
			if len(misses) != tc.wantMiss {
				t.Errorf("находок %d, ожидалось %d (импортёров %d, двузначных вызовов %d): %+v",
					len(misses), tc.wantMiss, importers, calls, misses)
			}
			if calls != tc.wantCalls {
				t.Errorf("двузначных вызовов %d, ожидалось %d", calls, tc.wantCalls)
			}
			for _, m := range misses {
				if !strings.HasSuffix(m.File, "fx.go") || m.Line == 0 || m.Symbol == "" {
					t.Errorf("находка обязана называть файл, строку и символ, получено %+v", m)
				}
			}
		})
	}
}

// TestIAMCT2_TypeMissEmptyWalkIsAVerdictlessRun — пустой обход НЕ является
// чистым деревом.
//
// Без этой пробы гейт, чей обход по любой причине вернул ноль файлов, печатал бы
// «находок 0» и выходил успехом — то есть «ноль прочитанного» было бы
// неотличимо от «ноль находок».
func TestIAMCT2_TypeMissEmptyWalkIsAVerdictlessRun(t *testing.T) {
	misses, importers, calls, err := discardedTypeMisses(t.TempDir(), nil, twoValueSymbols)
	if err != nil {
		t.Fatalf("пустой обход дал ошибку разбора: %v", err)
	}
	if len(misses) != 0 || importers != 0 || calls != 0 {
		t.Fatalf("пустой обход дал ненулевые числа: находок %d, импортёров %d, вызовов %d",
			len(misses), importers, calls)
	}
	// Само требование «обход пуст ⇒ Fatalf» живёт в гейте на дереве; здесь
	// утверждается ВХОД этого требования: обходчик действительно отдаёт нули, а
	// не выдумывает объём.
}

// TestIAMCT2_DecodedMissLedgerHasASubject — записи ведомости имеют предмет.
//
// Положительная сторона самоистечения: гейт на дереве роняет запись, которой
// нечего исключать, а эта проба утверждает обратную половину — что каждая запись
// названа СУЩЕСТВУЮЩИМ файлом и несёт непустую причину. Запись, указывающая в
// никуда, прошла бы самоистечение как «файл перестал отбрасывать признак», и
// опечатка в пути была бы неотличима от починки.
func TestIAMCT2_DecodedMissLedgerHasASubject(t *testing.T) {
	root := catalogRepoRoot(t)
	if len(decodedMissFiles) == 0 {
		t.Skip("ведомость пуста — утверждать не о чем; это законная цель, а не поломка")
	}
	for f, why := range decodedMissFiles {
		if _, err := os.Stat(filepath.Join(root, f)); err != nil {
			t.Errorf("запись ведомости %q не резолвится в дереве: %v", f, err)
		}
		if strings.TrimSpace(why) == "" {
			t.Errorf("запись ведомости %q не называет декодера пустоты — «мы так решили» "+
				"причиной не является", f)
		}
	}
	t.Logf("осмотрено записей ведомости: %d", len(decodedMissFiles))
}
