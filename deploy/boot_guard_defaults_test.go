// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// boot_guard_defaults_test.go — ВЕЛИЧИНУ, БЕЗ КОТОРОЙ СЛУЖБА НЕ ПУСКАЕТСЯ, ЧАРТ
// НЕ ПОДСТАВЛЯЕТ ЗА ОПЕРАТОРА.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// У процесса есть страж старта, отказывающий в пуске, когда установка не
// назвала свою величину (`config.Validate`, таблица `config.RequiredSettings`).
// Страж работает ровно до тех пор, пока незаданное ДОЕЗЖАЕТ до него незаданным.
// Чарт, подставивший вместо оператора СВОЁ значение, отменяет стража целиком:
// величина непуста всегда, отказа не бывает ни при каком входе, и проверка
// зелена не потому, что установка настроена, а потому, что спросить её нечем.
//
// Хуже того, подставляется значение НАШЕЙ установки — то есть оператор чужого
// облака получает не «не задано», а тихо принятое чужое: домен доверия, под
// которым его собственная установка сертификатов не выпускает. По такому домену
// не опознаётся ни один его предъявитель, и служба отвергает каждого соседа
// молча, отказом, неотличимым от вызова без личности.
//
// ЭТО ТОТ ЖЕ КЛАСС, что снятые умолчания имён объектов (#2090) и координаты
// образа (#2094), и он на шаг дальше обоих: там непустое умолчание вело в
// никуда и отказывало в кластере, здесь оно ведёт в никуда и НЕ ОТКАЗЫВАЕТ
// ВОВСЕ. Предмет заводится своей задачей ровно потому, что предыдущие два
// предиката его не видят by construction: домен доверия не является ни объектом
// Kubernetes, ни координатой образа.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОПУЛЯЦИЯ БЕРЁТСЯ У ПРОЦЕССА, А НЕ ВЫПИСЫВАЕТСЯ ЗДЕСЬ
//
// Перечень величин, судимых стражем старта, объявлен ОДИН раз —
// `config.RequiredSettings`. Выписанный здесь второй перечень разошёлся бы с
// ним молча: страж меняется коммитом в свой файл, проба не меняется вовсе, и
// расхождение видит только тот, кто в этот день ставит службу впервые.
//
// Поэтому проба читает таблицу процесса и сверяет с ней ТО, ЧТО ЧАРТ РЕНДЕРИТ В
// ФАЙЛ НАСТРОЕК. Ключ, которого чарт не рендерит, не судится и печатается своим
// числом: он подаётся переменной окружения, и подстановки у чарта для него нет.
//
// ─────────────────────────────────────────────────────────────────────────────
// РАСПОЗНАВАТЕЛЬ ХОДИТ ПО `include`, И ЭТО НЕСУЩЕЕ
//
// Соседняя проба (`defaultless_keys_test.go`) свою слепую зону НАЗЫВАЕТ: она не
// идёт по `include` в именованный шаблон. Здесь предмет другой и переход по
// `include` обязателен — потому что подстановка живёт именно там: вызывающий
// шаблон пишет `trust-domain: {{ include "kaname-svc.trustDomain" . }}` и
// выглядит честным сквозным проходом, а литерал стоит в теле помощника.
//
// Формы подстановки названы ПОИМЁННО и доказаны инъекцией по каждой:
// `X | default "ЛИТ"`, `default "ЛИТ" X`, `coalesce … "ЛИТ"`, `dig … "ЛИТ" …`,
// и любая из них ЗА `include`. Пустой контейнер (`default dict`, `default list`)
// подстановкой НЕ является: он даёт ноль записей, а не значение.
//
// `include` ИЩЕТСЯ И В ОХРАНЯЮЩЕЙ СТРОКЕ, а не только в самой позиции ключа, и
// это выяснила инъекция, а не чтение. Ключ, отданный ветвью, пишется как
// `{{- with (include "X" .) }}` … `ключ: {{ . | quote }}`: в строке ключа
// перехода нет ВОВСЕ, он стоит уровнем выше. Распознаватель, читающий только
// строку ключа, на этой — самой частой — форме молчит; поэтому контекст точки
// разрешается до охраняющего выражения. Обе формы имеют свой случай инъекции.
//
// СЛЕПАЯ ЗОНА НАЗВАНА ЧИСЛОМ: литерал, выданный ветвью (`{{ if … }}ЛИТ{{ else }}`),
// образцу не виден. Сегодня таких позиций ноль, и это печатается — рост числа
// означает, что предмет уехал в форму, которой проба не судит.
package deploy_test

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

// ── распознаватель ───────────────────────────────────────────────────────────

// configMapTemplate — шаблон, рендерящий файл настроек службы.
const configMapTemplate = "configmap.yaml"

// settingsBlockAnchor — строка, с которой в шаблоне начинается сам файл
// настроек. Всё выше неё — оболочка объекта Kubernetes, а не настройки.
const settingsBlockAnchor = "config.yaml: |"

// defineRe — объявление именованного шаблона.
var defineRe = regexp.MustCompile(`\{\{-?\s*define\s+"([^"]+)"\s*-?\}\}`)

// includeRe — переход в именованный шаблон.
var includeRe = regexp.MustCompile(`include\s+"([^"]+)"`)

// literalDefaultRe — подстановка литерала: `default "ЛИТ"`, `default 42`,
// `coalesce … "ЛИТ"`, `dig … "ЛИТ" …`. Пустая строка литералом не считается —
// она означает «ничего не подставлено».
var literalDefaultRe = regexp.MustCompile(`\b(?:default|coalesce|dig)\b[^}]*?("[^"]+"|\b\d+\b)`)

// emptyContainerRe — `default dict` / `default list` / `default (dict)`.
// Пустой контейнер значения не подставляет: он даёт ноль записей.
var emptyContainerRe = regexp.MustCompile(`\bdefault\s+\(?\s*(?:dict|list)\s*\)?`)

// branchLiteralRe — литерал, выданный ВЕТВЬЮ. Образцу выше он не виден; это
// объявленная слепая зона, и она считается отдельным числом.
var branchLiteralRe = regexp.MustCompile(`\{\{-?\s*else\s*-?\}\}\s*"[^"]+"`)

// renderedSetting — один ключ файла настроек, который рендерит чарт.
type renderedSetting struct {
	key       string // дорожка ключа в файле настроек, как её знает процесс
	file      string
	line      int
	expr      string // выражение, дающее величину
	viaHelper string // имя именованного шаблона, если величина идёт через него
	literal   string // подставленный литерал; пусто — подстановки нет
}

// namedTemplateBodies — тела именованных шаблонов чарта, по имени.
//
// Собираются по ВСЕМ файлам каталога шаблонов: `define` живёт в помощниках, а
// зовётся откуда угодно, и привязка к одному файлу завела бы слепую зону при
// первом же переезде объявления.
func namedTemplateBodies(chartDir string) (map[string]string, int, error) {
	names, err := chartTemplateNames(chartDir)
	if err != nil {
		return nil, 0, fmt.Errorf("каталог шаблонов не читается: %w", err)
	}
	bodies := map[string]string{}
	for _, name := range names {
		raw, readErr := os.ReadFile(filepath.Join(chartDir, templatesDir, name))
		if readErr != nil {
			return nil, 0, fmt.Errorf("шаблон %s не читается: %w", name, readErr)
		}
		text := string(raw)
		locs := defineRe.FindAllStringSubmatchIndex(text, -1)
		for i, loc := range locs {
			end := len(text)
			if i+1 < len(locs) {
				end = locs[i+1][0]
			}
			bodies[text[loc[2]:loc[3]]] = text[loc[1]:end]
		}
	}
	return bodies, len(bodies), nil
}

// substitutedLiteral — какой литерал подставляет выражение, если подставляет.
// Пустая строка означает, что величина проходит насквозь.
func substitutedLiteral(expr string) string {
	stripped := emptyContainerRe.ReplaceAllString(expr, "")
	m := literalDefaultRe.FindStringSubmatch(stripped)
	if m == nil {
		return ""
	}
	return strings.Trim(m[1], `"`)
}

// dotValueRe — точка как ВЕЛИЧИНА: `{{ . }}`, `{{ . | quote }}`, `{{ default X . }}`.
// Путь значения (`{{ .Values.x }}`) точкой-величиной не является — за точкой там
// стоит имя.
var dotValueRe = regexp.MustCompile(`\.(\s|\||\}|$)`)

// valueComesFromDot — берёт ли выражение величину из контекста, а не из пути.
func valueComesFromDot(expr string) bool {
	for _, m := range actionRe.FindAllStringSubmatch(expr, -1) {
		if dotValueRe.MatchString(strings.TrimSpace(m[1])) {
			return true
		}
	}
	return false
}

// collectRenderedSettings — ключи файла настроек, которые пишет чарт, вместе с
// тем, откуда берётся величина каждого.
//
// Дорожка ключа собирается по ОТСТУПУ внутри блока файла настроек: `authn:` на
// одном уровне, `trust-domain:` на следующем дают `authn.trust-domain` — ровно
// ту запись, которой ключ назван у процесса.
func collectRenderedSettings(chartDir string) (
	settings []renderedSetting, filesRead, linesRead, branchLiterals int, err error,
) {
	bodies, _, err := namedTemplateBodies(chartDir)
	if err != nil {
		return nil, 0, 0, 0, err
	}

	names, err := chartTemplateNames(chartDir)
	if err != nil {
		return nil, 0, 0, 0, fmt.Errorf("каталог шаблонов не читается: %w", err)
	}
	for _, name := range names {
		raw, readErr := os.ReadFile(filepath.Join(chartDir, templatesDir, name))
		if readErr != nil {
			return nil, 0, 0, 0, fmt.Errorf("шаблон %s не читается: %w", name, readErr)
		}
		text := string(raw)
		filesRead++
		lines := strings.Split(text, "\n")
		linesRead += len(lines)
		branchLiterals += len(branchLiteralRe.FindAllString(text, -1))

		if name != configMapTemplate {
			continue
		}

		type frame struct {
			indent int
			key    string
		}
		var stack []frame
		// guards — открытые охраняющие выражения (`with`/`if`/`range`), внутри
		// которых стоит текущая строка. Ключ, отданный ветвью, величину берёт
		// из точки, а точку задаёт ближайшее из них.
		var guards []string
		inBlock, baseIndent := false, 0

		for i, line := range lines {
			trimmed := strings.TrimSpace(line)
			if !inBlock {
				if strings.Contains(trimmed, settingsBlockAnchor) {
					inBlock = true
					baseIndent = len(line) - len(strings.TrimLeft(line, " "))
				}
				continue
			}
			if strings.HasPrefix(trimmed, "{{") {
				for _, m := range actionRe.FindAllStringSubmatch(trimmed, -1) {
					body := strings.TrimSpace(m[1])
					switch {
					case strings.HasPrefix(body, "/*"):
					case body == "end":
						if len(guards) > 0 {
							guards = guards[:len(guards)-1]
						}
					case strings.HasPrefix(body, "with "),
						strings.HasPrefix(body, "if "),
						strings.HasPrefix(body, "range "):
						guards = append(guards, body)
					}
				}
				continue
			}
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				continue
			}
			indent := len(line) - len(strings.TrimLeft(line, " "))
			if indent <= baseIndent {
				break
			}
			key := yamlKeyOf(trimmed)
			if key == "" {
				continue
			}
			for len(stack) > 0 && stack[len(stack)-1].indent >= indent {
				stack = stack[:len(stack)-1]
			}

			value := strings.TrimSpace(trimmed[strings.Index(trimmed, ":")+1:])
			if value == "" {
				stack = append(stack, frame{indent, key})
				continue
			}
			if !strings.Contains(value, "{{") {
				continue
			}

			path := key
			for j := len(stack) - 1; j >= 0; j-- {
				path = stack[j].key + "." + path
			}

			// Величина, взятая из точки, приходит из охраняющего выражения:
			// строка ключа о её происхождении не говорит ничего.
			effective := value
			if valueComesFromDot(value) && len(guards) > 0 {
				effective = value + " " + guards[len(guards)-1]
			}

			found := renderedSetting{key: path, file: name, line: i + 1, expr: effective}
			found.literal = substitutedLiteral(effective)
			if m := includeRe.FindStringSubmatch(effective); m != nil {
				found.viaHelper = m[1]
				if found.literal == "" {
					found.literal = substitutedLiteral(bodies[m[1]])
				}
			}
			settings = append(settings, found)
		}
	}
	return settings, filesRead, linesRead, branchLiterals, nil
}

// auditBootGuardDefaults — находки и перепись.
func auditBootGuardDefaults(chartDir string) (findings []string, census string, err error) {
	settings, filesRead, linesRead, branchLiterals, err := collectRenderedSettings(chartDir)
	if err != nil {
		return nil, "", err
	}
	if filesRead == 0 {
		return nil, "", fmt.Errorf("обход пуст: каталог шаблонов не дал ни одного файла — вердикт беспредметен")
	}
	if len(config.RequiredSettings) == 0 {
		return nil, "", fmt.Errorf("обход пуст: таблица величин, судимых стражем старта, не дала ни одной строки — вердикт беспредметен")
	}

	guarded := map[string]config.RequiredSetting{}
	for _, s := range config.RequiredSettings {
		guarded[s.Key] = s
	}

	var rendered, passthrough, substituted int
	for _, s := range settings {
		req, ok := guarded[s.key]
		if !ok {
			continue
		}
		rendered++
		if s.literal == "" {
			passthrough++
			continue
		}
		substituted++
		via := ""
		if s.viaHelper != "" {
			via = fmt.Sprintf(" (через именованный шаблон %q)", s.viaHelper)
		}
		findings = append(findings, fmt.Sprintf(
			"  %s:%d: ключ %s — чарт подставляет своё значение %q%s.\n"+
				"    Без этой величины процесс НЕ ПУСКАЕТСЯ: страж старта отвергает пуск и называет ручку\n"+
				"    (%s). Подстановка отменяет его целиком — величина непуста при любом входе, отказа\n"+
				"    не бывает никогда, и оператор чужого облака получает не «не задано», а тихо принятое\n"+
				"    чужое. Уберите подстановку: незаданное обязано доехать до стража незаданным, а\n"+
				"    величину называет накладка профиля.",
			s.file, s.line, s.key, s.literal, via, req.Env))
	}

	if rendered == 0 {
		return nil, "", fmt.Errorf(
			"обход пуст: чарт не рендерит НИ ОДНОГО ключа из таблицы величин, судимых стражем старта "+
				"(ключей у процесса %d, ключей отрендерено чартом %d) — вердикт беспредметен",
			len(config.RequiredSettings), len(settings))
	}

	sort.Strings(findings)
	census = fmt.Sprintf(
		"перепись: шаблонов прочитано %d · строк %d · ключей, судимых стражем старта %d · "+
			"из них чарт рендерит %d (подают незаданное стражу %d · подставляют своё %d) · "+
			"ключей файла настроек всего %d · литералов в ветви (слепая зона) %d · находок %d",
		filesRead, linesRead, len(config.RequiredSettings),
		rendered, passthrough, substituted, len(settings), branchLiterals, len(findings))
	return findings, census, nil
}

// TestChartSubstitutesNoValueTheBootGuardMustJudge — чарт не подставляет за
// оператора величину, без которой процесс не пускается.
func TestChartSubstitutesNoValueTheBootGuardMustJudge(t *testing.T) {
	chartDir := filepath.Join(serviceRoot(t), "deploy")

	findings, census, err := auditBootGuardDefaults(chartDir)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if len(findings) > 0 {
		t.Fatalf("чарт подставляет величины, судимые стражем старта:\n%s\n\n%s",
			strings.Join(findings, "\n"), census)
	}
	t.Log(census)
}
