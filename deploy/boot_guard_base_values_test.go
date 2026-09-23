// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// boot_guard_base_values_test.go — ВЕЛИЧИНУ, БЕЗ КОТОРОЙ СЛУЖБА НЕ ПУСКАЕТСЯ,
// НЕ ПОДСТАВЛЯЮТ И БАЗОВЫЕ ЗНАЧЕНИЯ ЧАРТА.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Соседняя проба (`boot_guard_defaults_test.go`) судит подстановку В ШАБЛОНЕ:
// `default "ЛИТ"`, `coalesce`, `dig` и они же за `include`. Базовых значений
// (`values.yaml`) она не читает — и потому величина, у которой литерал стоит
// НЕ в шаблоне, а в базовых значениях, проходит мимо неё с переписью
// «подставляют своё 0». Отказ от подстановки у процесса и у шаблона при этом
// ничего не даёт: `helm` сливает базовые значения с накладкой оператора, и
// ключ, о котором накладка молчит, приезжает в файл настроек НАШИМ.
//
// Так было со сроком ключа подписи (#321): умолчание загрузчика и разрешитель
// структуры сняты, ключ внесён в таблицу стража, а `values.yaml` продолжал
// выбирать `2160h` за оператора — и страж на незаданном сроке не отказывал ни
// при какой накладке. Это тот же класс, что снятые умолчания имён объектов и
// координаты образа, на той оси, которой не видел ни один из держателей.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОПУЛЯЦИЯ И ПЕРЕЛОЖЕНИЕ БЕРУТСЯ ГОТОВЫМИ
//
// Перечень судимых величин — `config.RequiredSettings`, у процесса. Путь от
// ключа конфигурации к базовому значению — `configBridge`: ЕДИНСТВЕННОЕ
// повторение шаблона на Go в этом каталоге, верность которого шаблону держат
// `TestConfigBridge_MirrorsTheChartTemplate` и рендер
// (`TestConfigBridge_CoversEveryKeyTheChartRenders`). Второго перечня здесь не
// заводится.
//
// Записи переложения трёх родов, и каждый назван числом переписи:
//
//   - по пути значения (`valuePath`) — судится лист базовых значений;
//   - выключателем блока (`gate` при вычисляемой величине) — судится
//     выключатель: базовые значения, поднявшие его, включили бы блок за
//     оператора, и вычисленная величина доехала бы до стража готовой;
//   - склейкой без выключателя — не судятся: они читают по нескольку путей, и
//     непустое слагаемое (порт, имя базы) законно. Сегодня таких судимых
//     стражем записей ноль, и число печатается — рост его означает, что предмет
//     уехал в форму, которой проба не судит.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ЗНАЧИТ «ПОДСТАВЛЯЕТ» — ФОРМЫ НАЗВАНЫ ПОИМЁННО
//
// Незаданным лист считается, когда его нет, когда это пустая (или пробельная)
// строка и когда это пустой перечень или пустая карта: до стража в каждом из
// этих случаев не доезжает ни одного значения, принятого за оператора.
// Подстановка — непустая строка, непустой перечень или карта, `true` и
// ненулевое число.
//
// СЛЕПАЯ ЗОНА НАЗВАНА ЧИСЛОМ: `false` и ноль у листа по пути значения не
// судятся. Под ветвью `with` они означают «не отрендерено», под ветвью `hasKey`
// — объявленную величину (ноль собственного потолка есть решение «не заводить»),
// а переложение этих двух форм не различает. Сегодня таких листьев у судимых
// ключей ноль; выключатель блока (`if`) слепой зоны не имеет — ложь там всегда
// означает «блока нет».
package deploy_test

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

// baseValueForm — что базовый лист отдаёт стражу, когда накладка молчит.
type baseValueForm int

const (
	// baseValueUnset — до стража не доезжает ничего: он судит незаданное.
	baseValueUnset baseValueForm = iota
	// baseValueSubstituted — до стража доезжает НАШЕ значение.
	baseValueSubstituted
	// baseValueBlind — `false` или ноль у листа по пути значения: форма, которую
	// переложение не различает (см. шапку). Не судится и считается числом.
	baseValueBlind
)

// classifyBaseLeaf — форма листа базовых значений по пути значения.
func classifyBaseLeaf(v any) baseValueForm {
	switch x := v.(type) {
	case nil:
		return baseValueUnset
	case string:
		if strings.TrimSpace(x) == "" {
			return baseValueUnset
		}
		return baseValueSubstituted
	case []any:
		if len(x) == 0 {
			return baseValueUnset
		}
		return baseValueSubstituted
	case map[string]any:
		if len(x) == 0 {
			return baseValueUnset
		}
		return baseValueSubstituted
	case bool:
		if !x {
			return baseValueBlind
		}
		return baseValueSubstituted
	case int:
		if x == 0 {
			return baseValueBlind
		}
		return baseValueSubstituted
	case float64:
		if x == 0 {
			return baseValueBlind
		}
		return baseValueSubstituted
	default:
		return baseValueSubstituted
	}
}

// baseValuesCensus — объём осмотренного. Числа отдельно от находок: «ноль
// находок» обязано быть отличимо от «ноль прочитанного».
type baseValuesCensus struct {
	Guarded     int // строк таблицы стража
	Bridged     int // из них проведено чартом (есть запись переложения)
	ByPath      int // по пути значения
	BySwitch    int // выключателем блока
	ByGlue      int // склейкой без выключателя — не судятся
	Unset       int // базовые значения их не задают
	Blind       int // слепая зона: `false` / ноль по пути значения
	Substituted int // базовые значения подставляют своё — находки
}

func (c baseValuesCensus) String() string {
	return fmt.Sprintf(
		"строк таблицы стража %d · проведено чартом %d (по пути значения %d · выключателем блока %d · "+
			"склейкой без выключателя, не судятся %d) · базовые значения не задают %d · "+
			"слепая зона (false/ноль по пути значения) %d · подставляют своё %d",
		c.Guarded, c.Bridged, c.ByPath, c.BySwitch, c.ByGlue, c.Unset, c.Blind, c.Substituted)
}

// baseValueFinding — одна подстановка: какой ключ стража, каким листом.
type baseValueFinding struct {
	ConfigKey string
	ValuePath string
	Env       string
	Value     any
}

func (f baseValueFinding) String() string {
	return fmt.Sprintf(
		"  %s: %s = %#v — базовые значения чарта подставляют величину ключа %s.\n"+
			"    Без неё процесс НЕ ПУСКАЕТСЯ: страж старта отвергает пуск и называет ручку (%s).\n"+
			"    `helm` сливает базовые значения с накладкой оператора, поэтому накладка, о ключе\n"+
			"    промолчавшая, получает НАШЕ значение, и отказа не бывает ни при каком входе.\n"+
			"    Снимите значение (пустая строка): величину называет накладка профиля.",
		chartDefaultsFile, f.ValuePath, f.Value, f.ConfigKey, f.Env)
}

// auditBaseValueSubstitution — находки и перепись для НАЗВАННЫХ входов.
//
// Все три входа приходят параметрами, чтобы способность упасть доказывалась
// инъекцией, а не прочтением: пустая таблица, пустое переложение и пустые
// базовые значения — отказ обхода, а не зелёное.
func auditBaseValueSubstitution(
	bridge []bridged, base map[string]any, guarded []config.RequiredSetting,
) (findings []baseValueFinding, census baseValuesCensus, err error) {
	if len(guarded) == 0 {
		return nil, census, fmt.Errorf("обход пуст: таблица величин, судимых стражем старта, " +
			"не дала ни одной строки — вердикт беспредметен")
	}
	if len(bridge) == 0 {
		return nil, census, fmt.Errorf("обход пуст: переложение значений чарта не несёт ни одной " +
			"записи — путь от ключа стража к базовому значению взять неоткуда")
	}
	if len(base) == 0 {
		return nil, census, fmt.Errorf("обход пуст: базовые значения чарта пусты — судить нечего, " +
			"и зелёное относилось бы к другому дереву")
	}

	rows := map[string]config.RequiredSetting{}
	for _, s := range guarded {
		rows[s.Key] = s
	}
	census.Guarded = len(rows)

	for _, b := range bridge {
		row, ok := rows[b.configKey]
		if !ok {
			continue
		}
		census.Bridged++

		var path []string
		var form baseValueForm
		switch {
		case len(b.valuePath) > 0:
			census.ByPath++
			path = b.valuePath
			form = classifyBaseLeaf(at(base, path...))
		case len(b.gate) > 0:
			census.BySwitch++
			path = b.gate
			form = baseValueUnset
			if isTruthy(at(base, path...)) {
				form = baseValueSubstituted
			}
		default:
			census.ByGlue++
			continue
		}

		switch form {
		case baseValueUnset:
			census.Unset++
		case baseValueBlind:
			census.Blind++
		case baseValueSubstituted:
			census.Substituted++
			findings = append(findings, baseValueFinding{
				ConfigKey: b.configKey,
				ValuePath: strings.Join(path, "."),
				Env:       row.Env,
				Value:     at(base, path...),
			})
		}
	}

	if census.Bridged == 0 {
		return nil, census, fmt.Errorf(
			"обход пуст: ни одна из %d строк таблицы стража не проведена чартом (записей "+
				"переложения %d) — вердикт беспредметен", census.Guarded, len(bridge))
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].ConfigKey < findings[j].ConfigKey })
	return findings, census, nil
}

// TestChartBaseValuesSubstituteNoValueTheBootGuardMustJudge — базовые значения
// чарта не выбирают за оператора величину, без которой процесс не пускается.
func TestChartBaseValuesSubstituteNoValueTheBootGuardMustJudge(t *testing.T) {
	chartDir := filepath.Join(serviceRoot(t), "deploy")
	base, err := readChartValues(filepath.Join(chartDir, chartDefaultsFile))
	if err != nil {
		t.Fatalf("базовые значения не читаются: %v", err)
	}

	findings, census, err := auditBaseValueSubstitution(configBridge, base, config.RequiredSettings)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if len(findings) > 0 {
		lines := make([]string, 0, len(findings))
		for _, f := range findings {
			lines = append(lines, f.String())
		}
		t.Fatalf("базовые значения чарта подставляют величины, судимые стражем старта:\n%s\n\nперепись: %s",
			strings.Join(lines, "\n"), census)
	}
	t.Logf("перепись: %s", census)
}
