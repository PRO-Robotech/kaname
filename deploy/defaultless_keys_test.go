// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// defaultless_keys_test.go — СНЯТОЕ УМОЛЧАНИЕ ОБЯЗАНО БЫТЬ ПОДХВАЧЕНО ШАБЛОНОМ.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Умолчание, называющее объект или координату НАШЕЙ установки, снимается —
// и это верно (`foreign_object_defaults_test.go`, `image_coordinate_test.go`).
// Но снятие само по себе дефекта не закрывает: ключ с пустым умолчанием, который
// шаблон подставляет ДОСЛОВНО, даёт манифест с пустой величиной. Установка
// проходит, объект создаётся, и отказ снова приходит уже в кластере — только
// теперь без имени: пустая координата не называет даже того, чего не нашли.
//
// Отсюда норма: у ключа с пустым умолчанием ровно два законных исхода, и оба
// означают, что ПУСТОТА УЗНАНА шаблоном —
//
//  1. отказ: рендер не проходит и называет, что задать (`if not …` → `fail`,
//     `required`). Так судятся координаты, без которых установка бессмысленна:
//     узел базы, секрет с паролем, координата образа;
//  2. ветвь: пустая величина означает «этой возможности нет», и блок не
//     рендерится вовсе (`if`, `with`, `range`). Так судятся необязательные
//     полосы: материал TLS, докерная полоса, посадка личности.
//
// Третьего исхода — «подставить как есть» — не существует.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ПРОБА СУДИТ И ЧЕГО НЕ СУДИТ
//
// Она ДЕКЛАРАТИВНА: читает базовые значения и ТЕКСТ шаблонов, а не рендер.
// Она судит, УЗНАНА ли пустота, и НЕ судит, какой из двух исходов выбран: выбор
// между отказом и ветвью — продуктовое решение (обязательна ли полоса), и
// требовать одного из них значило бы решать его за автора чарта.
//
// Пустая КАРТА и пустой СПИСОК в популяцию не входят, и это не послабление:
// «ни одной записи» — законная величина, а обход по ней даёт ноль итераций
// by construction. Предмет здесь — пустая СТРОКА, то есть снятое умолчание
// скалярной величины.
//
// Ключ, которого не читает ни один шаблон, тоже не судится: он не подставляется
// никуда, значит дословной подстановки нет. Такие ключи названы отдельным числом
// переписи — «ноль находок» обязано быть отличимо от «ноль прочитанного».
//
// ─────────────────────────────────────────────────────────────────────────────
// РАСПОЗНАВАТЕЛЬ ЗНАЕТ ВСЕ ЗАКОННЫЕ ФОРМЫ, И ОНИ НАЗВАНЫ ПОИМЁННО
//
// Форма, о которой распознаватель не знает, не даёт ни красного, ни зелёного —
// она молчит. Поэтому формы перечислены в `actionRecognizesEmptiness` и доказаны
// инъекцией по каждой: `if`, `else if`, `with`, `range`, `required`, `default`.
// Псевдонимы (`$tls := .Values.tls`) разрешаются до путей значений — иначе
// ветвь, написанная через псевдоним, читалась бы как отсутствующая.
//
// `fail` формой НЕ является намеренно: условный отказ пишется как `if not … →
// fail`, то есть уже узнан ветвью, а безусловный `fail` о пустоте не судит
// ничего. Форма, включённая «на всякий случай», прощала бы ключ, который в неё
// провалится следующим.
//
// СЛЕПАЯ ЗОНА, НАЗВАННАЯ ЗДЕСЬ, ЗАКРЫТА — И ЗАКРЫТА ТЕМ, ЧТО ОНА ПРЕДСКАЗАЛА.
//
// Здесь стояло: «распознаватель НЕ идёт по `include` в именованный шаблон…
// если такой ключ появится, гейт покраснеет НА ВЕРНОМ чарте. Починка — научить
// распознаватель ходить по `include`, и она заводится своим изменением».
//
// Ключ появился. Домен доверия отдаётся ветвью через помощника —
// `{{- with (include "kaname-svc.trustDomain" .) }}` … `trust-domain: {{ . }}`,
// — и обе половины формы лежат в РАЗНЫХ файлах: путь значения называет тело
// помощника, а пустоту узнаёт зовущий. Читая их порознь, распознаватель видел
// дословную подстановку на верном чарте, ровно как и было предсказано.
//
// Теперь `resolveRefs` идёт по переходу: действие, несущее `include "X"`,
// называет ТЕ ЖЕ пути значений, что и тело X (с его собственными псевдонимами).
// Тогда `with` вокруг перехода узнаёт пустоту пути, названного внутри.
// Доказано инъекцией по обеим сторонам: переход под ветвью — молчание, тот же
// переход без ветви — находка.
//
// Предсказание сбылось дословно, и урок в нём не про эту строку: слепая зона,
// названная числом и предикатом, ЗАКРЫВАЕТСЯ, когда предмет в неё приходит.
// Названная оговоркой — не закрывается никогда.
package deploy_test

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// valueSite — одна позиция, в которой шаблон называет путь значения.
type valueSite struct {
	file string
	line int
	body string
}

// actionRecognizesEmptiness — узнаёт ли действие шаблона, что величина может
// быть пустой.
//
// ФОРМЫ НАЗВАНЫ ПОИМЁННО, а не угаданы по виду: перечень и есть предмет
// инъекции. Ветвь (`if`/`else if`/`with`) не рендерит блок на пустой величине;
// обход (`range`) даёт ноль итераций; `required` роняет рендер с текстом;
// `default` подставляет величину вместо пустой.
func actionRecognizesEmptiness(body string) bool {
	fields := strings.Fields(body)
	if len(fields) == 0 {
		return false
	}
	switch fields[0] {
	case "if", "with", "range":
		return true
	case "else":
		return len(fields) > 1 && fields[1] == "if"
	}
	for _, word := range fields {
		switch strings.TrimLeft(word, "(|") {
		case "required", "default":
			return true
		}
	}
	return false
}

// collectValueSites — где шаблоны называют пути значений, с разделением на
// позиции, УЗНАЮЩИЕ пустоту, и позиции дословной подстановки.
func collectValueSites(chartDir string) (recognized, verbatim map[string][]valueSite, filesRead, linesRead, actionsRead int, err error) {
	names, err := chartTemplateNames(chartDir)
	if err != nil {
		return nil, nil, 0, 0, 0, fmt.Errorf("каталог шаблонов не читается: %w", err)
	}
	// Тела именованных шаблонов — чтобы действие с `include` называло те же
	// пути значений, что и тело, в которое оно переходит. Объявление читается
	// один раз: у `namedTemplateBodies` один источник на обе пробы каталога.
	bodies, _, err := namedTemplateBodies(chartDir)
	if err != nil {
		return nil, nil, 0, 0, 0, err
	}
	recognized, verbatim = map[string][]valueSite{}, map[string][]valueSite{}

	for _, name := range names {
		raw, readErr := os.ReadFile(filepath.Join(chartDir, templatesDir, name))
		if readErr != nil {
			return nil, nil, 0, 0, 0, fmt.Errorf("шаблон %s не читается: %w", name, readErr)
		}
		text := string(raw)
		filesRead++
		lines := strings.Split(text, "\n")
		linesRead += len(lines)
		aliases := templateAliases(text)

		for i, line := range lines {
			for _, m := range actionRe.FindAllStringSubmatch(line, -1) {
				body := strings.TrimSpace(m[1])
				// Комментарий шаблона (`{{/* … */}}`) действием не является:
				// проза о ключе — не объявление ключа.
				if strings.HasPrefix(body, "/*") {
					continue
				}
				actionsRead++
				site := valueSite{name, i + 1, body}
				bucket := verbatim
				if actionRecognizesEmptiness(body) {
					bucket = recognized
				}
				refs := resolveRefs(body, aliases)
				// ПЕРЕХОД В ИМЕНОВАННЫЙ ШАБЛОН. Половины формы лежат в разных
				// файлах: путь называет тело, а пустоту узнаёт зовущий.
				for _, m := range includeRe.FindAllStringSubmatch(body, -1) {
					helperBody, ok := bodies[m[1]]
					if !ok {
						continue
					}
					refs = append(refs, resolveRefs(helperBody, templateAliases(helperBody))...)
				}
				for _, p := range refs {
					bucket[p] = append(bucket[p], site)
				}
			}
		}
	}
	return recognized, verbatim, filesRead, linesRead, actionsRead, nil
}

// emptyStringDefaults — пути базовых значений, чьё умолчание — пустая строка.
func emptyStringDefaults(defaults map[string]any) []string {
	var out []string
	for _, path := range leafPaths(defaults, nil) {
		v, ok := leafAt(defaults, strings.Join(path, "."))
		if !ok {
			continue
		}
		s, isString := v.(string)
		if !isString || strings.TrimSpace(s) != "" {
			continue
		}
		out = append(out, strings.Join(path, "."))
	}
	sort.Strings(out)
	return out
}

// auditDefaultlessKeys — вердикт: всякий ключ с пустым умолчанием, который
// шаблон читает, узнан им как возможно-пустой.
func auditDefaultlessKeys(chartDir string) (findings []string, census string, err error) {
	defaults, err := readChartValues(filepath.Join(chartDir, chartDefaultsFile))
	if err != nil {
		return nil, "", fmt.Errorf("базовые значения не читаются: %w", err)
	}
	recognized, verbatim, filesRead, linesRead, actionsRead, err := collectValueSites(chartDir)
	if err != nil {
		return nil, "", err
	}

	// ПОЛОЖИТЕЛЬНЫЕ КОНТРОЛИ. Обход, ничего не прочитавший, и популяция, в
	// которой нет ни одного предмета, дают зелёное при любом содержимом.
	if actionsRead == 0 {
		return nil, "", fmt.Errorf(
			"обход пуст: в шаблонах не разобрано ни одного действия (файлов %d, строк %d) — "+
				"вердикт беспредметен", filesRead, linesRead)
	}
	if len(recognized) == 0 {
		return nil, "", fmt.Errorf(
			"обход пуст: ни одно действие шаблона не узнаёт пустоту — распознаватель не " +
				"знает ни одной формы этого чарта, и молчание ничего не значит")
	}
	population := emptyStringDefaults(defaults)
	if len(population) == 0 {
		return nil, "", fmt.Errorf(
			"обход пуст: ни одно базовое значение чарта не снято (пустых строк 0) — " +
				"судить нечего, и зелёное относилось бы к другому дереву")
	}

	unread := 0
	for _, path := range population {
		if len(recognized[path]) > 0 {
			continue
		}
		sites := verbatim[path]
		if len(sites) == 0 {
			// Ключ, которого не читает ни один шаблон: дословной подстановки
			// нет, судить нечего. Виден числом переписи.
			unread++
			continue
		}
		where := make([]string, 0, len(sites))
		for _, s := range sites {
			where = append(where, fmt.Sprintf("%s:%d", s.file, s.line))
		}
		findings = append(findings, fmt.Sprintf(
			"  %s — умолчание снято (пустая строка), а шаблон подставляет ключ ДОСЛОВНО: %s. "+
				"Установка пройдёт, объект создастся с пустой величиной, и отказ придёт уже в "+
				"кластере — без имени того, чего не хватило. Исхода два: назвать ключ перечнем "+
				"отказа рендера (`kaname-svc.requireOperatorSuppliedNames` в %s) либо укрыть "+
				"блок ветвью (`if`/`with`), если полоса необязательна.",
			path, strings.Join(where, ", "), helpersFile))
	}

	census = fmt.Sprintf(
		"шаблонов прочитано %d · строк %d · действий разобрано %d · путей, узнающих пустоту %d · "+
			"ключей со снятым умолчанием %d (%s) · из них не читает ни один шаблон %d · находок %d",
		filesRead, linesRead, actionsRead, len(recognized),
		len(population), strings.Join(population, ", "), unread, len(findings))
	return findings, census, nil
}

// TestEveryDefaultlessKeyIsRecognizedAsPossiblyEmpty — несущая проба: снятое
// умолчание подхвачено шаблоном, а не подставлено как есть.
func TestEveryDefaultlessKeyIsRecognizedAsPossiblyEmpty(t *testing.T) {
	chartDir := filepath.Join(serviceRoot(t), "deploy")

	findings, census, err := auditDefaultlessKeys(chartDir)
	require.NoError(t, err, "обход не состоялся")
	t.Logf("перепись: %s", census)

	require.Empty(t, findings,
		"снятое умолчание подставляется дословно:\n%s", strings.Join(findings, "\n"))
}
