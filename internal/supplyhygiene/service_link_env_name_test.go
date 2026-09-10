// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// service_link_env_name_test.go — ПЛОСКОЕ ИМЯ ПЕРЕМЕННОЙ, КОТОРОЕ ПОДСТАВЛЯЕТ
// КЛАСТЕР, НЕ ЧИТАЕТСЯ НИГДЕ БЕЗ ОБЪЯВЛЕННОЙ ФОРМЫ ЗНАЧЕНИЯ.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЗАЧЕМ ЭТА МЕРА СВЕРХ ГЕЙТА КЛАССА В ПАКЕТЕ НАСТРОЕК
//
// Тот гейт судит перепись, ВЫВЕДЕННУЮ из объявлений загрузки: ключи настроек,
// поля посадки транспорта, перечень плоских псевдонимов. Он полон ровно
// настолько, насколько полны объявления, — и слеп к плоскому имени, прочитанному
// в обход них: `os.Getenv("KANAME_SIDECAR_PORT")` где-нибудь в композиционном
// корне в его перепись не попадёт ВООБЩЕ, и молчание гейта о нём не будет ни
// красным, ни зелёным.
//
// Здесь спрашивается дерево: какие плоские имена корневого сегмента службы в нём
// вообще написаны, и нет ли среди них такого, которое подставляет кластер, а
// формы значения у него не объявлено.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ РАЗБОР, А НЕ ПОИСК ПО ОБРАЗЦУ
//
// Имена вида `KANAME_INTERNAL_PORT` стоят в этом дереве не только выражением
// ручки: они стоят в комментариях, объясняющих ЭТОТ ЖЕ класс, и в прозе
// документов. Поиск по подстроке краснел бы на собственном объяснении — тот
// самый класс, который корпус ловит. Здесь судится узел строкового литерала,
// полученный разбором.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ТОЛЬКО НЕ-ТЕСТОВОЕ ДЕРЕВО
//
// Предмет — что читает ПРОЦЕСС. Фикстуры инъекции предъявляют распознавателю все
// восемь форм кластера поимённо, и судить их этой мерой значило бы требовать от
// проверки не пользоваться тем, что она проверяет: обход по всему дереву даёт 14
// имён, из которых 11 — фикстуры доказательства собственной способности упасть.
package supplyhygiene

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

// serviceLinkEnvFinding — одно попадание.
type serviceLinkEnvFinding struct {
	file string
	line int
	name string
	form string
}

// serviceLinkEnvCensus — объём осмотренного. Печатается всегда: «ноль находок»
// обязано быть отличимо от «ноль прочитанного».
type serviceLinkEnvCensus struct {
	FilesRead int
	LitsSeen  int
	OwnPrefix int
	Flat      int
	Colliding int
	Declared  int
	Unparsed  []string
}

// judgeServiceLinkEnvNames — СУЖДЕНИЕ, отделённое от дерева прогона.
//
// Отделено намеренно: мера, чью способность падать нельзя предъявить иначе как
// поломкой настоящего дерева, доказательства не имеет. Инъекция зовёт тот же
// обход на синтетическом корне, меняя один факт.
func judgeServiceLinkEnvNames(root string) ([]serviceLinkEnvFinding, serviceLinkEnvCensus, error) {
	census := serviceLinkEnvCensus{}
	var findings []serviceLinkEnvFinding

	fset := token.NewFileSet()
	walkErr := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		if d.IsDir() {
			if _, skip := skippedDirs[d.Name()]; skip {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".go") || strings.HasSuffix(d.Name(), "_test.go") {
			return nil
		}
		census.FilesRead++

		f, parseErr := parser.ParseFile(fset, path, nil, 0)
		if parseErr != nil {
			// Негодный по синтаксису файл — не находка этой меры: о нём судит
			// сборка. Но и молчать нельзя: пропуск обязан быть виден.
			census.Unparsed = append(census.Unparsed, filepath.ToSlash(rel))
			return nil
		}

		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			census.LitsSeen++
			val, uqErr := strconv.Unquote(lit.Value)
			if uqErr != nil {
				return true
			}
			if !strings.HasPrefix(val, config.EnvPrefix+"_") {
				return true
			}
			census.OwnPrefix++
			if strings.Contains(val, "__") {
				// Имя, выведенное из пути ключа настроек: кластер двойного
				// подчёркивания не производит, столкновение невыразимо.
				return true
			}
			census.Flat++
			form, collides := config.ClusterServiceLinkForm(val)
			if !collides {
				return true
			}
			census.Colliding++
			if declared, guarded := config.FlatEnvKnobGuardsItsValue(val); declared && guarded {
				census.Declared++
				return true
			}
			findings = append(findings, serviceLinkEnvFinding{
				file: filepath.ToSlash(rel),
				line: fset.Position(lit.Pos()).Line,
				name: val,
				form: form,
			})
			return true
		})
		return nil
	})
	if walkErr != nil {
		return nil, census, walkErr
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].file != findings[j].file {
			return findings[i].file < findings[j].file
		}
		return findings[i].line < findings[j].line
	})
	return findings, census, nil
}

// TestNoFlatEnvNameTheClusterInjectsIsReadUndeclared — плоское имя, которое
// подставляет кластер, нигде в не-тестовом дереве не читается без объявленной
// формы значения.
func TestNoFlatEnvNameTheClusterInjectsIsReadUndeclared(t *testing.T) {
	root, err := filepath.Abs(serviceRoot)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: корень модуля не установлен: %v", err)
	}

	findings, census, err := judgeServiceLinkEnvNames(root)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: обход модуля сорвался: %v", err)
	}

	if census.FilesRead == 0 {
		t.Fatalf("обход пуст: файлов Go прочитано 0 (корень %s) — «находок ноль» здесь "+
			"неотличимо от «ноль прочитанного», и вердикт беспредметен", root)
	}
	if census.OwnPrefix == 0 {
		t.Fatalf("литералов корневого сегмента службы не найдено ни одного при %d "+
			"прочитанных файлах: распознаватель перестал их видеть, и молчание меры "+
			"ничего не означает", census.FilesRead)
	}
	if census.Colliding == 0 {
		t.Fatalf("с формой кластера не совпало ни одно из %d плоских имён: у службы есть "+
			"ручки порта, и ноль здесь означает, что мера смотрит не туда", census.Flat)
	}
	for _, u := range census.Unparsed {
		t.Logf("НЕ РАЗОБРАН (вердикт по нему не выносится): %s", u)
	}

	for _, f := range findings {
		t.Errorf("%s:%d: %q — плоское имя, которое КЛАСТЕР подставляет поду сам (форма %s), "+
			"читается прод-кодом, а формы значения у ручки не объявлено. Подстановка "+
			"перебьёт величину оператора молча — и отказ придёт не разбором настроек, а "+
			"последним шагом старта. Исходы: объявить ручку в flatEnvKnobs с формой "+
			"значения (config/service_link_collision.go) либо перевести величину на путь "+
			"ключа настроек — его имя viper выводит с `__`, а кластер двойного "+
			"подчёркивания не производит", f.file, f.line, f.name, f.form)
	}

	t.Logf("перепись: файлов Go (не-тестовых) прочитано %d · строковых литералов осмотрено %d · "+
		"из них корневого сегмента службы %d · плоских %d · совпало с формой кластера %d, "+
		"из них с объявленной формой значения %d · находок %d · не разобрано %d",
		census.FilesRead, census.LitsSeen, census.OwnPrefix, census.Flat,
		census.Colliding, census.Declared, len(findings), len(census.Unparsed))
}
