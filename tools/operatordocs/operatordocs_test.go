// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// operatordocs_test.go — ГЕЙТ свежести документов оператора и доказательство
// того, что он способен упасть.
//
// # Что стережётся
//
//	THIRD-PARTY-NOTICES.md   перечень третьих сторон сходится с тем, что
//	                         линкуют поставляемые бинари СЕГОДНЯ;
//	INSTALL.md, блок величин перечень обязательных величин сходится с таблицей
//	                         стража старта.
//
// Первое — исполнение требования чужой лицензии к распространению: перечень,
// умалчивающий о части распространяемого, выглядит исполняющим и не исполняет.
// Второе — то, ради чего документ вообще писался: страж меняется коммитом в свой
// файл, документ не меняется вовсе, и расхождение видит только тот, кто в этот
// день ставит службу впервые.
//
// # Три исхода читаются КОДОМ, а не видом вывода
//
// Прогон печатает перепись всегда, и «сходится» на пустом обходе невозможно by
// construction: пустой обход даёт код «без предмета», а не ноль.
package operatordocs

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/config"
)

// iamRoot — корень дерева iam относительно каталога этой пробы
// (services/iam/tools/operatordocs).
const iamRoot = "../.."

// runGate прогоняет сверку и возвращает код и вывод.
func runGate(t *testing.T, table []config.RequiredSetting) (int, string) {
	t.Helper()
	var buf bytes.Buffer
	code := Run(Options{Root: iamRoot, Write: false, Out: &buf, Table: table})
	return code, buf.String()
}

// ─────────────────────────────────────────────────────────────────────────────
// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: на дереве как есть документы сходятся.

func TestOperatorDocs_TreeIsInSync(t *testing.T) {
	code, out := runGate(t, nil)
	if code != ExitSynced {
		t.Fatalf("сверка документов оператора вернула %d, ожидался %d (сходится).\n"+
			"Починка: `make -C services/iam operator-docs`\n\nвывод:\n%s", code, ExitSynced, out)
	}
	if !strings.Contains(out, "модулей") || !strings.Contains(out, "строк ") {
		t.Fatalf("перепись не напечатана — «находок 0» неотличимо от «прочитано 0».\nвывод:\n%s", out)
	}
	t.Logf("%s", strings.TrimSpace(out))
}

// ─────────────────────────────────────────────────────────────────────────────
// ИНЪЕКЦИЯ СКВОЗЬ ВЕСЬ ГЕЙТ: битая таблица на настоящем дереве.

func TestOperatorDocsGate_CanFail_OnDriftedTable(t *testing.T) {
	cases := []struct {
		name  string
		table []config.RequiredSetting
		want  int
		names string
		why   string
	}{
		{
			name:  "законный близнец: действующая таблица",
			table: nil,
			want:  ExitSynced,
			why:   "положительный контроль: без него всякое красное ниже могло бы приходить от самого гейта",
		},
		{
			name: "объяснение величины изменилось, документ — нет",
			table: mutated(func(s *config.RequiredSetting) {
				if s.Key == "authn.hook-shared-secret" {
					s.Why = "объяснение переписано, а документ остался прежним"
				}
			}),
			want:  ExitFinding,
			names: InstallFile,
			why: "самый частый случай в жизни: правку стража внесли, документ забыли. " +
				"Без гейта расхождение увидел бы только тот, кто в этот день ставит службу",
		},
		{
			// НАПРАВЛЕНИЕ ПЕРЕОБЪЯВЛЕНИЯ РАЗВЁРНУТО (задача #2040). Прежде случай
			// объявлял ОКРУЖЕНИЕ там, где действовал файл, — и держался на том,
			// что у ключа файловый путь единственный. Ключ привязан, путь стал
			// общим, мутация превратилась в тождество, и случай СМОЛЧАЛ:
			// фикстура истекла вместе со своим предметом. Теперь объявляется
			// ФАЙЛ там, где таблица говорит «окружение», — направление, которое
			// не зависит от того, какие ключи привязаны сегодня, и заодно
			// единственный производитель файловой ветви рендера: без него она
			// осталась бы без входа, а перепись печатала бы «подаются только
			// файлом 0» при мёртвой ветви.
			name: "путь подачи переобъявлен",
			table: mutated(func(s *config.RequiredSetting) {
				if s.Key == "authn.trusted-forwarder-sans" {
					s.Supply = config.SupplyFile
				}
			}),
			want:  ExitFinding,
			names: InstallFile,
			why: "документ продолжал бы называть путь через окружение там, где таблица объявила файл, — " +
				"то есть врал бы ровно в той колонке, ради которой заведён",
		},
		{
			name: "новая обязательная величина заведена, документ о ней молчит",
			table: append(mutated(nil), config.RequiredSetting{
				Key: "authn.brand-new-knob", Env: "KACHO_IAM_AUTHN__BRAND_NEW_KNOB",
				Supply: config.SupplyEnv, Sample: "x", Why: "заведена сегодня", Refusal: "authn.brand-new-knob",
			}),
			want:  ExitFinding,
			names: InstallFile,
			why:   "оператор упёрся бы в отказ старта по величине, которой в документе нет",
		},
		{
			name:  "пустая таблица",
			table: []config.RequiredSetting{},
			want:  ExitFinding,
			why: "порождённый блок был бы пуст, а документ — зелен. " +
				"Пустая таблица находкой является, а не поводом смолчать",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, out := runGate(t, tc.table)
			if code != tc.want {
				t.Fatalf("гейт вернул %d, ожидался %d.\nЧто должно было ловиться: %s\n\nвывод:\n%s",
					code, tc.want, tc.why, out)
			}
			if tc.names != "" && !strings.Contains(out, tc.names) {
				t.Fatalf("находка есть, а КООРДИНАТЫ %q в ней нет — читатель пойдёт чинить не туда.\nвывод:\n%s",
					tc.names, out)
			}
			t.Logf("код %d · %s", code, firstFinding(out))
		})
	}
}

// mutated — копия действующей таблицы с применённой правкой (nil — без правки).
func mutated(f func(*config.RequiredSetting)) []config.RequiredSetting {
	out := make([]config.RequiredSetting, len(config.RequiredSettings))
	copy(out, config.RequiredSettings)
	if f != nil {
		for i := range out {
			f(&out[i])
		}
	}
	return out
}

func firstFinding(out string) string {
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "·") {
			return strings.TrimSpace(l)
		}
	}
	return strings.TrimSpace(strings.Split(out, "\n")[0])
}

// ─────────────────────────────────────────────────────────────────────────────
// ПОДСТАНОВКА БЛОКА: метки обязаны быть, и ровно одни.

func TestSpliceBlock_RefusesDocumentsThatCannotCarryTheBlock(t *testing.T) {
	block := SettingsBeginMarker + "\nтело\n" + SettingsEndMarker

	cases := []struct {
		name    string
		doc     string
		wantErr string
		why     string
	}{
		{
			name: "законный близнец: метки есть и стоят по порядку",
			doc:  "проза\n" + SettingsBeginMarker + "\nстарое\n" + SettingsEndMarker + "\nещё проза\n",
			why:  "положительный контроль: без него отрицания ниже зеленели бы на любом документе",
		},
		{
			name:    "нет метки начала",
			doc:     "проза\n" + SettingsEndMarker + "\n",
			wantErr: "метки начала",
			why:     "порождать некуда; молча дописать блок в конец значило бы завести второе место об одном предмете",
		},
		{
			name:    "нет метки конца",
			doc:     "проза\n" + SettingsBeginMarker + "\n",
			wantErr: "метки конца",
			why:     "подстановка съела бы остаток документа",
		},
		{
			name:    "метки переставлены",
			doc:     SettingsEndMarker + "\nпроза\n" + SettingsBeginMarker + "\n",
			wantErr: "не по порядку",
			why:     "подстановка вывернула бы документ наизнанку",
		},
		{
			name:    "метка начала дважды",
			doc:     SettingsBeginMarker + "\nа\n" + SettingsEndMarker + "\n" + SettingsBeginMarker + "\nб\n" + SettingsEndMarker,
			wantErr: "дважды",
			why:     "блоков об одном предмете два: правится один, читается другой, и разойдутся они молча",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := SpliceBlock(tc.doc, block)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("подстановка отвергла законный документ: %v\nпочему он законен: %s", err, tc.why)
				}
				if !strings.Contains(got, "тело") {
					t.Fatalf("блок не подставлен, хотя ошибки нет:\n%s", got)
				}
				return
			}
			if err == nil {
				t.Fatalf("подстановка приняла негодный документ — она НЕ способна упасть по этой оси.\n"+
					"Что должно было ловиться: %s", tc.why)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("отказ есть, а причина названа не та: %v (искали %q)", err, tc.wantErr)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// ОПОЗНАНИЕ ЛИЦЕНЗИИ: молчание на неопознанном — тоже исход.

func TestIdentify_NamesTheLicenceOrSaysItCannot(t *testing.T) {
	mit := "MIT License\n\nPermission is hereby granted, free of charge, to any person obtaining a copy"
	apache := "                                 Apache License\n                           Version 2.0, January 2004"
	bsd3 := "Redistributions in binary form must reproduce the above copyright notice.\n" +
		"Neither the name of the copyright holder nor the names of its contributors"

	cases := []struct {
		name string
		file string
		body string
		want string
		why  string
	}{
		{"MIT", "LICENSE", mit, "MIT", "самая частая лицензия перечня"},
		{"Apache-2.0", "LICENSE", apache, "Apache-2.0", "вторая по частоте"},
		{"BSD-3-Clause", "LICENSE", bsd3, "BSD-3-Clause", "узкий распознаватель обязан стоять раньше двухпунктового"},
		{"иное имя файла", "COPYING.md", mit, "MIT", "модуль вправе назвать файл иначе"},
		{
			"текст, который не опознаётся", "LICENSE", "Все права защищены. Условия по запросу.", "",
			"молчание здесь — ИСХОД, а не пропуск: распространять чужой код, не зная его лицензии, нельзя, " +
				"и вызывающий обязан завести находку",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, tc.file), []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			got := Identify(Module{Path: "example.com/m", Version: "v1.0.0", Dir: dir})
			if got.License != tc.want {
				t.Fatalf("опознано %q, ожидалось %q (%s)", got.License, tc.want, tc.why)
			}
			if got.Evidence != tc.file {
				t.Fatalf("координата свидетельства %q, ожидалась %q — читателю нечего открыть", got.Evidence, tc.file)
			}
		})
	}
}

// Модуль, не извлечённый в кэш, НЕ считается проверенным: «ноль находок»
// обязано быть отличимо от «ноль прочитанного».
func TestIdentify_UnresolvedModuleIsNotCountedAsChecked(t *testing.T) {
	got := Identify(Module{Path: "example.com/m", Version: "v1.0.0", Dir: ""})
	if got.License != "" || got.Evidence != "" {
		t.Fatalf("модуль без каталога получил лицензию %q по свидетельству %q — "+
			"гейт утверждал бы о непрочитанном", got.License, got.Evidence)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// БЕЗ ПРЕДМЕТА — отдельный исход, а не вердикт о дереве.

func TestRun_SaysNotRunWhenTheRootIsNotIam(t *testing.T) {
	var buf bytes.Buffer
	code := Run(Options{Root: t.TempDir(), Out: &buf})
	if code != ExitNotRun {
		t.Fatalf("на чужом каталоге гейт вернул %d, ожидался %d (не исполнялось): "+
			"вердикт о дереве, которого он не читал, хуже отсутствия вердикта.\nвывод:\n%s",
			code, ExitNotRun, buf.String())
	}
}
