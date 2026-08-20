// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// verdictswitch.go — ОТВЕЧАЕМОСТЬ ТИПА ФОРМОЙ и перепись рубильника.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ЭТО ЗДЕСЬ, А НЕ В ПАКЕТЕ РУБИЛЬНИКА
//
// Рубильник — лист: он знает, какие типы названы, и не знает ни модели прав, ни
// движка, ни формы. «Умеет ли форма отвечать об этом типе» — вопрос к МОДЕЛИ, а
// модель доступна композиционному корню. Разнести эти два знания по разным
// местам обязательно: рубильник, которому пришлось бы импортировать модель,
// перестал бы быть листом и утащил бы её в путь решения.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО СЧИТАЕТСЯ ОТВЕЧАЕМЫМ — предикат ВЫВОДИТСЯ, а не выписывается
//
// Форма вычисляет вердикт, компилируя план вывода из той же модели, которой
// говорит движок. Значит тип отвечаем ровно тогда, когда:
//
//	· он объявлен в модели (иначе спрашивать не о чем: имя, которого нет,
//	  молча не совпадёт ни с одной строкой и даст «прав нет» без ошибки);
//	· у него есть хотя бы ОДНО отношение — иначе он бывает только субъектом, а
//	  объектом решения не бывает никогда;
//	· КАЖДОЕ его отношение компилируется в ВЫРАЗИМЫЙ план — план с неразобранным
//	  источником дал бы вердикт, у которого не хватает оснований, и он был бы
//	  отказом ровно там, где источник не разобран.
//
// Выписанный рядом перечень отвечаемых типов был бы вторым местом об одном
// предмете: он не сдвинулся бы от нового типа и продолжал бы сторожить прежние,
// то есть молчал бы ровно про тот тип, ради которого его пришлось бы править.
//
// ─────────────────────────────────────────────────────────────────────────────
// ГРАНИЦА ПРОВЕРКИ — НАЗВАНА, А НЕ ПОДРАЗУМЕВАЕТСЯ
//
// Страж судит ПЛАН, а не ДАННЫЕ. Он не знает и не может знать, населена ли цепь
// областей для объектов этого типа на конкретном стенде: это состояние базы, а
// не свойство модели. Значит «страж прошёл» означает «форме есть чем считать»,
// а не «форма ответит верно на этом стенде». Второе устанавливается конформной
// переписью по типу перед его переключением — отдельным прогоном, а не стартом
// процесса. Граница печатается самой переписью, чтобы молчание стража не
// прочиталось шире, чем оно есть.

package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/PRO-Robotech/kacho/services/iam/internal/authzmodel"
	"github.com/PRO-Robotech/kacho/services/iam/internal/verdictsource"
)

// verdictSwitchCensus — что перепись осмотрела и что нашла.
//
// Объём осмотренного — ПОЛЕ, а не строка в логе: «ноль неотвечаемых» обязано
// быть отличимо от «ноль прочитанных типов», и отличать это должен читатель
// переписи, а не тот, кто вспомнит спросить.
type verdictSwitchCensus struct {
	// TypesInModel — сколько типов объявляет модель прав. Знаменатель.
	TypesInModel int
	// AnswerableTypes — сколько из них форма способна отвечать.
	AnswerableTypes int
	// Declared — что назвал оператор, в устойчивом порядке.
	Declared []string
	// Switched — из названного то, что действительно переключится.
	Switched []string
	// Unanswerable — названное, о чём форму спросить нечем: тип → причина.
	Unanswerable map[string]string
}

// String — строка самоотчёта процесса при старте.
//
// Печатает ТРИ числа, которых требует гейт, и границу собственной проверки:
// перепись, умолчавшая о границе, читается как обещание того, чего она не
// проверяла.
func (c verdictSwitchCensus) String() string {
	switched := "—"
	if len(c.Switched) > 0 {
		switched = strings.Join(c.Switched, ",")
	}
	return fmt.Sprintf(
		"источник вердикта: типов в модели %d, форма отвечает %d, объявлено переключёнными %d, "+
			"переключается %d (%s), неотвечаемых %d; "+
			"проверен ПЛАН модели, населённость цепи областей НЕ проверена — она свойство данных стенда",
		c.TypesInModel, c.AnswerableTypes, len(c.Declared), len(c.Switched), switched, len(c.Unanswerable))
}

// surveyVerdictSwitch переписывает рубильник против модели прав.
//
// Ошибка означает, что разобрать модель не удалось вовсе: это отказ сборки, а
// не «типов ноль». Пустая перепись и неразобранная модель обязаны быть
// различимы — иначе процесс поднялся бы, объявив «неотвечаемых ноль», не
// прочитав ни одного типа.
func surveyVerdictSwitch(sb verdictsource.Switchboard) (verdictSwitchCensus, error) {
	plans, err := authzmodel.Shared()
	if err != nil {
		return verdictSwitchCensus{}, fmt.Errorf("модель прав не разобрана: %w", err)
	}
	model := plans.Model()

	census := verdictSwitchCensus{
		Declared:     sb.Declared(),
		Unanswerable: map[string]string{},
	}
	names := model.TypeNames()
	census.TypesInModel = len(names)
	for _, name := range names {
		if reason := unanswerableReason(plans, name); reason == "" {
			census.AnswerableTypes++
		}
	}

	for _, declared := range census.Declared {
		if reason := unanswerableReason(plans, declared); reason != "" {
			census.Unanswerable[declared] = reason
			continue
		}
		census.Switched = append(census.Switched, declared)
	}
	sort.Strings(census.Switched)
	return census, nil
}

// unanswerableReason — почему форму нельзя спросить об этом типе; "" когда можно.
//
// Причина возвращается ТЕКСТОМ, а не булевым: отказ в старте обязан назвать не
// только тип, но и то, что с ним не так, — иначе оператор видит запрет и не
// видит действия, которым его снять.
func unanswerableReason(plans *authzmodel.Plans, objectType string) string {
	model := plans.Model()
	mt := model.Type(objectType)
	if mt == nil {
		if strings.Contains(objectType, ".") {
			return "имя записано в словаре КАТАЛОГА; рубильник называет типы в словаре МОДЕЛИ прав " +
				"(соединение колонок разных словарей не совпадает никогда и молча)"
		}
		return "такого типа в модели прав нет"
	}
	if len(mt.Relations) == 0 {
		return "тип не несёт ни одного отношения: он бывает только субъектом, объектом решения — никогда"
	}
	for _, rel := range mt.Relations {
		plan, err := model.Compile(objectType, rel.Name)
		if err != nil {
			return fmt.Sprintf("отношение %q не компилируется в план: %v", rel.Name, err)
		}
		if !plan.Expressible() {
			return fmt.Sprintf("план отношения %q неполон (не разобраны источники %v): вердикт по нему "+
				"был бы отказом ровно там, где источник не разобран", rel.Name, plan.Unclassified)
		}
	}
	return ""
}

// verdictSwitchComplaint — почему рубильник в этой позиции не даёт поднять
// службу; "" когда даёт.
//
// Отдельная функция ради проверяемости: `os.Exit` внутри сборщика можно
// прочитать, но нельзя исполнить, а страж, которого никто не может исполнить, —
// страж, про который никто не знает, работает ли он.
//
// Текст называет ручку и тип НАМЕРЕННО: это рантайм-диагностика оператору,
// который иначе не поднимет стенд, и она из-под запрета на публичную сборку
// выведена явно.
func verdictSwitchComplaint(sb verdictsource.Switchboard, shadowCompare bool) string {
	if sb.IsEmpty() {
		// Не переключено ничего — позиция законна при любой сверке.
		return ""
	}
	if !shadowCompare {
		return fmt.Sprintf("рубильник источника вердикта называет типы (%s), но теневая сверка "+
			"выключена (authz.shadow-compare=false): без неё формы у сравнителя нет, и решения "+
			"продолжат идти движку — тип выглядел бы переключённым, не будучи им. Либо включите "+
			"authz.shadow-compare, либо очистите authz.verdict-form-types",
			strings.Join(sb.Declared(), ","))
	}
	census, err := surveyVerdictSwitch(sb)
	if err != nil {
		return fmt.Sprintf("рубильник источника вердикта (authz.verdict-form-types) проверить нечем: %v", err)
	}
	if len(census.Unanswerable) == 0 {
		return ""
	}
	names := make([]string, 0, len(census.Unanswerable))
	for name := range census.Unanswerable {
		names = append(names, name)
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, name := range names {
		parts = append(parts, fmt.Sprintf("%s — %s", name, census.Unanswerable[name]))
	}
	return fmt.Sprintf("authz.verdict-form-types называет типы, о которых форму спросить нечем: %s. "+
		"Поднявшись в этом состоянии, служба отвечала бы по ним молчаливым отказом",
		strings.Join(parts, "; "))
}
