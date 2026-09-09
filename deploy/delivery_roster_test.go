// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// delivery_roster_test.go — перепись поставляемого каталога: что этот чарт
// ОБЪЯВЛЯЕТ своим составом, и что лежит на диске.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Каталог `deploy/` уезжает арендатору целиком, и уезжает КОПИРОВАНИЕМ. У
// копирования нет вердикта: файл, не доехавший до артефакта, не делает красным
// ничего — ни у нас, ни у арендатора. Он просто отсутствует, а отсутствие
// неотличимо от «такого файла и не было».
//
// Замер 2026-09-06, из которого выведен этот гейт: в дереве продукта файлов
// каталога `deploy/` было ЧЕТЫРНАДЦАТЬ, в опубликованном артефакте —
// ТРИНАДЦАТЬ. Не доехал `workload_identity_single_source_test.go`, и разошлись
// они по ВОЗРАСТУ: снимок артефакта снят 2026-09-05 05:22, а файл заведён в тот
// же день в 17:39 — то есть отбора никто не делал, и решения тоже никто не
// принимал. Это и есть тот класс, который надо ловить: не злой умысел, а
// снимок, отставший молча.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ОБЪЯВЛЕНИЕ, А НЕ СВЕРКА ДВУХ ДЕРЕВЬЕВ
//
// Сверить состав продукта с составом артефакта может только тот, у кого открыты
// оба, — а у арендатора нашего дерева нет и не будет. Поэтому объявление ЕДЕТ
// ВМЕСТЕ С КАТАЛОГОМ: перечень ниже — часть поставки, и он спрашивает у того
// дерева, в котором исполняется, всё ли на месте. Файл, не доехавший до
// артефакта, делает прогон У АРЕНДАТОРА красным и называет имя.
//
// Второе место об одном предмете здесь заведено НАМЕРЕННО, и цена названа: одна
// строка на каждую правку состава каталога. Это не издержка, а предмет — правка
// состава поставляемого каталога и есть то, что обязано быть замечено. Реестр
// самоистекает в обе стороны: снятый файл, чья строка осталась, — находка ровно
// так же, как заведённый файл без строки.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЕДИНИЦА СЧЁТА — ФАЙЛ, и осмотренное печатается отдельно от найденного
//
// «Ноль расхождений» обязано быть отличимо от «ноль прочитанного»: обход,
// не нашедший ни одного файла, есть отказ, а не чистое дерево. Каталог, в
// котором нет даже `Chart.yaml`, чартом не является.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ОБХОД НЕ СЧИТАЕТ, И ПОЧЕМУ ЭТО НЕ ПОСЛАБЛЕНИЕ
//
// Пропускаются имена, начинающиеся с точки. Это не ведомость исключений: точка в
// начале имени — то же правило, по которому `helm package` не кладёт файл в
// архив, то есть такой файл поставкой не является BY CONSTRUCTION. Никаких
// других пропусков нет — ни по расширению, ни по имени, ни поимённо.
package deploy_test

import (
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// deliveryRoster — состав поставляемого каталога, объявленный поимённо. Пути от
// каталога чарта, разделитель прямой косой чертой в обоих деревьях.
//
// ПОРЯДОК — алфавитный, и он не несёт смысла: смысл несёт СОСТАВ.
var deliveryRoster = []string{
	"Chart.yaml",
	"boot_guard_defaults_injection_test.go",
	"boot_guard_defaults_test.go",
	"defaultless_keys_injection_test.go",
	"defaultless_keys_test.go",
	"delivery_roster_test.go",
	"foreign_object_defaults_test.go",
	"image_coordinate_injection_test.go",
	"image_coordinate_test.go",
	"operator_keys_carry_no_foreign_prefix_injection_test.go",
	"operator_keys_carry_no_foreign_prefix_test.go",
	"probe_scheme_follows_edge_injection_test.go",
	"probe_scheme_follows_edge_test.go",
	"prod_profile_injection_test.go",
	"port_knob_moves_its_listener_injection_test.go",
	"port_knob_moves_its_listener_test.go",
	"prod_profile_render_injection_test.go",
	"prod_profile_render_test.go",
	"prod_profile_test.go",
	"provider_hops_test.go",
	"release_namespace_test.go",
	"render-guard.sh",
	"schema_mechanism_precedes_the_service_injection_test.go",
	"schema_mechanism_precedes_the_service_test.go",
	"scrape_declared_injection_test.go",
	"scrape_declared_test.go",
	"service_routes_every_surface_injection_test.go",
	"service_routes_every_surface_test.go",
	"templates/_helpers.tpl",
	"templates/configmap.yaml",
	"templates/deployment.yaml",
	"templates/service.yaml",
	"tree_root_test.go",
	"values.dev.yaml",
	"values.prod.yaml",
	"values.yaml",
	"workload_identity_single_source_test.go",
}

// walkDeliveredFiles читает состав каталога чарта с диска.
//
// Каталог берётся ОТ КОРНЯ МОДУЛЯ, найденного подъёмом до маркера
// (tree_root_test.go), а не от рабочего каталога напрямую: рабочий каталог у
// пробы и так равен каталогу пакета, но подъём делает это утверждением, которое
// проверяется, а не допущением, которое молчит.
func walkDeliveredFiles(root string) ([]string, error) {
	found := []string{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		if rel == "." {
			return nil
		}
		if strings.HasPrefix(d.Name(), ".") {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}
		found = append(found, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(found)
	return found, nil
}

// TestDeliveredChartMatchesItsDeclaredRoster — состав каталога на диске сходится
// с объявленным. Расхождение в ЛЮБУЮ сторону роняет прогон.
func TestDeliveredChartMatchesItsDeclaredRoster(t *testing.T) {
	chartDir := filepath.Join(serviceRoot(t), "deploy")

	onDisk, err := walkDeliveredFiles(chartDir)
	if err != nil {
		t.Fatalf("обход каталога поставки не состоялся (%s): %v", chartDir, err)
	}
	// Обход, ничего не прочитавший, — отказ, а не чистое дерево.
	if len(onDisk) == 0 {
		t.Fatalf("осмотрено 0 файлов в %s — обход беспредметен, вердикт недействителен", chartDir)
	}

	declared := map[string]bool{}
	for _, rel := range deliveryRoster {
		declared[rel] = true
	}
	present := map[string]bool{}
	for _, rel := range onDisk {
		present[rel] = true
	}

	missing, unlisted := []string{}, []string{}
	for _, rel := range deliveryRoster {
		if !present[rel] {
			missing = append(missing, rel)
		}
	}
	for _, rel := range onDisk {
		if !declared[rel] {
			unlisted = append(unlisted, rel)
		}
	}
	sort.Strings(missing)
	sort.Strings(unlisted)

	t.Logf("перепись: объявлено файлов %d, на диске %d, не доехало %d, не объявлено %d (каталог %s)",
		len(deliveryRoster), len(onDisk), len(missing), len(unlisted), chartDir)

	if len(missing) > 0 {
		t.Errorf("объявлено, но в дереве нет (%d): %s\n"+
			"  Либо файл не доехал до этого дерева — тогда чинится КОПИРОВАНИЕ, а не реестр: у "+
			"арендатора без него нет вердикта о посадке, и отсутствие неотличимо от «такого файла "+
			"и не было». Либо файл снят намеренно — тогда снимается и строка реестра, тем же "+
			"изменением: реестр, переживший свой предмет, начинает прощать следующую пропажу.",
			len(missing), strings.Join(missing, ", "))
	}
	if len(unlisted) > 0 {
		t.Errorf("в дереве есть, но не объявлено (%d): %s\n"+
			"  Состав поставляемого каталога изменился и об этом никто не заявил. Внеси строку в "+
			"deliveryRoster — тем же изменением, которым заведён файл: иначе следующая сверка "+
			"артефакта с продуктом сойдётся на неверном перечне.",
			len(unlisted), strings.Join(unlisted, ", "))
	}
}

// TestDeliveryRosterIsNotVacuous — доказательство того, что сверка выше СПОСОБНА
// упасть, и падает в ОБЕ стороны.
//
// Вход синтетический, и это здесь единственная годная форма: настоящее дерево
// расхождения не несёт (иначе соседняя проба была бы красной), а доказывать
// способность падать на входе, которого не бывает, значит не доказывать ничего.
// Каждый случай меняет против целого состава РОВНО ОДИН факт.
func TestDeliveryRosterIsNotVacuous(t *testing.T) {
	base := t.TempDir()

	// Целый состав — положительный контроль. Без него оба отрицания ниже
	// зеленели бы на дереве, которого обход вообще не читает.
	whole := filepath.Join(base, "whole")
	buildRosterFixture(t, whole, deliveryRoster)
	if got := diffAgainstRoster(t, whole); got != "" {
		t.Fatalf("целый состав обязан сходиться, получено: %s", got)
	}

	// Файл не доехал.
	dropped := filepath.Join(base, "dropped")
	buildRosterFixture(t, dropped, deliveryRoster[1:])
	want := deliveryRoster[0]
	if got := diffAgainstRoster(t, dropped); !strings.Contains(got, "не доехало 1") ||
		!strings.Contains(got, want) {
		t.Fatalf("пропажа %q обязана быть найдена и НАЗВАНА, получено: %s", want, got)
	}

	// Файл появился и не объявлен.
	extra := filepath.Join(base, "extra")
	buildRosterFixture(t, extra, append(append([]string{}, deliveryRoster...), "templates/newcomer.yaml"))
	if got := diffAgainstRoster(t, extra); !strings.Contains(got, "не объявлено 1") ||
		!strings.Contains(got, "templates/newcomer.yaml") {
		t.Fatalf("незаявленный файл обязан быть найден и НАЗВАН, получено: %s", got)
	}

	// Законный близнец пропажи: имя, начинающееся с точки, поставкой не
	// является — обход обязан о нём молчать, а не считать незаявленным.
	dotted := filepath.Join(base, "dotted")
	buildRosterFixture(t, dotted, append(append([]string{}, deliveryRoster...), ".helmignore"))
	if got := diffAgainstRoster(t, dotted); got != "" {
		t.Fatalf("файл с точкой в начале имени поставкой не является, ожидалось молчание, получено: %s", got)
	}

	// Пустой каталог — отказ, а не «расхождений нет».
	empty := filepath.Join(base, "empty")
	mkdirAllOrFail(t, empty)
	files, err := walkDeliveredFiles(empty)
	if err != nil {
		t.Fatalf("обход пустого каталога не состоялся: %v", err)
	}
	if len(files) != 0 {
		t.Fatalf("в пустом каталоге прочитано %d файлов", len(files))
	}

	t.Logf("перепись доказательства: случаев 5 (целый состав, пропажа, незаявленный, "+
		"имя с точкой, пустой каталог), объявленных файлов в реестре %d, расхождений 0",
		len(deliveryRoster))
}

// buildRosterFixture кладёт названные пути пустыми файлами.
func buildRosterFixture(t *testing.T, root string, rels []string) {
	t.Helper()
	for _, rel := range rels {
		path := filepath.Join(root, filepath.FromSlash(rel))
		mkdirAllOrFail(t, filepath.Dir(path))
		writeFileOrFail(t, path, "")
	}
}

// diffAgainstRoster повторяет сверку соседней пробы над синтетическим каталогом
// и возвращает её словами. Пустая строка — состав сошёлся.
func diffAgainstRoster(t *testing.T, root string) string {
	t.Helper()
	onDisk, err := walkDeliveredFiles(root)
	if err != nil {
		t.Fatalf("обход %s не состоялся: %v", root, err)
	}
	declared := map[string]bool{}
	for _, rel := range deliveryRoster {
		declared[rel] = true
	}
	present := map[string]bool{}
	for _, rel := range onDisk {
		present[rel] = true
	}
	missing, unlisted := []string{}, []string{}
	for _, rel := range deliveryRoster {
		if !present[rel] {
			missing = append(missing, rel)
		}
	}
	for _, rel := range onDisk {
		if !declared[rel] {
			unlisted = append(unlisted, rel)
		}
	}
	if len(missing) == 0 && len(unlisted) == 0 {
		return ""
	}
	return strings.Join([]string{
		"не доехало " + strconv.Itoa(len(missing)) + ": " + strings.Join(missing, ", "),
		"не объявлено " + strconv.Itoa(len(unlisted)) + ": " + strings.Join(unlisted, ", "),
	}, "; ")
}
