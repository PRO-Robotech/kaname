// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// config_sections_have_a_reader_test.go — СЕКЦИИ ФАЙЛА НАСТРОЕК, КОТОРЫЕ
// РЕНДЕРИТ ЧАРТ, И СЕКЦИИ, КОТОРЫЕ ЧИТАЕТ ПРОЦЕСС, — ОДНО МНОЖЕСТВО, сверенное в
// обе стороны (задача kaname#236).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Загрузчик настроек разбирает файл в `config.Config` через `mapstructure`, и
// секцию, которой у структуры нет, отбрасывает МОЛЧА: ключ объявлен, рендер
// зелёный, поведение прежнее. Шапка шаблона карты настроек обещала держателя
// этого класса, а держатель жил в дереве платформы и после выноса службы
// читал координату, которой у платформы больше нет, — у класса в этом дереве
// держателя не было.
//
// ─────────────────────────────────────────────────────────────────────────────
// ДВЕ СТОРОНЫ И ЧЕМ КАЖДАЯ БЕРЁТСЯ
//
//	шаблон  — верхнеуровневые ключи блока `config.yaml` в
//	          `templates/configmap.yaml`, прочитанные из ТЕКСТА шаблона, а не из
//	          рендера: секция, отданная ветвью, в рендере одного профиля
//	          отсутствует, а в тексте есть всегда;
//	процесс — теги `mapstructure` полей `config.Config`, прочитанные отражением
//	          у самого типа: второго перечня проба не заводит.
//
// Прямое направление — секция шаблона без читателя — находка всегда.
// Обратное — секция процесса, которой чарт не рендерит, — находка, если её не
// назвала ведомость ниже с причиной. Ведомость самоистекающая: запись о секции,
// которую чарт теперь рендерит или которой у процесса больше нет, — находка.
//
// СЛЕПАЯ ЗОНА НАЗВАНА: секцию, которую шаблон отдал бы не строкой `ключ:`, а
// подстановкой (`include`, `toYaml`, `tpl`) на уровне секции, текст не
// показывает. Такая строка — находка «форма, которой проба не судит», а не
// пропуск: сегодня таких строк ноль, и перепись это печатает.
package deploy_test

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

// configMapTemplatePath — шаблон, чей блок `config.yaml` судится; имя файла и
// каталог шаблонов — те же константы, что у соседних проб этого шаблона.
var configMapTemplatePath = filepath.Join(templatesDir, configMapTemplate)

// configSectionsNotRendered — секции, которые процесс читает, а чарт не
// рендерит, с причиной по каждой. Причина называет, откуда величина берётся,
// когда чарт молчит.
var configSectionsNotRendered = map[string]string{
	"authz": "окно отзыва собственной двери: умолчание процесса (`defaults.go`), " +
		"неположительную величину отвергает страж старта; посадка задаёт её " +
		"переменной окружения через карту `env` профиля",
	"jobs": "уборщик истёкших удостоверений: умолчания процесса (`defaults.go`), " +
		"срок отсрочки судит страж старта против срока токена; посадка задаёт их " +
		"переменной окружения через карту `env` профиля",
	"manifests": "доставка манифестов модулей: пустой каталог законно означает «доставка " +
		"не объявлена» (`manifests.go`), переменные привязаны загрузчиком (`load.go`); " +
		"чарт каталога манифестов не монтирует, поэтому и секции не рендерит",
	"retention": "сбор устаревших строк: умолчания процесса (`defaults.go`); посадка " +
		"задаёт их переменной окружения через карту `env` профиля",
}

var (
	// templateComment — комментарий шаблона `{{/* … */}}`, в том числе
	// многострочный и с обрезкой пробелов.
	templateComment = regexp.MustCompile(`(?s)\{\{-?\s*/\*.*?\*/\s*-?\}\}`)
	// sectionHead — ключ на уровне секции блока (отступ ровно четыре пробела).
	sectionHead = regexp.MustCompile(`^ {4}([a-z][a-z0-9-]*):(\s|$)`)
	// sectionDirective — подстановка на уровне секции.
	sectionDirective = regexp.MustCompile(`^ {4}\{\{-?\s*(.*)$`)
)

// controlDirective — управляющие формы, которые на уровне секции ничего не
// отдают сами: ветвь, её конец, связывание переменной, отказ рендера.
func controlDirective(body string) bool {
	for _, p := range []string{"if ", "else", "end", "with ", "range ", "$", "fail "} {
		if strings.HasPrefix(body, p) {
			return true
		}
	}
	return false
}

// templateConfigSections — верхнеуровневые ключи блока `config.yaml` шаблона и
// строки подстановок на уровне секции, которых текст не раскрывает.
func templateConfigSections(body string) (sections, opaque []string, err error) {
	clean := templateComment.ReplaceAllString(body, "")
	lines := strings.Split(clean, "\n")
	start := -1
	for i, l := range lines {
		if strings.TrimSpace(l) == "config.yaml: |" {
			start = i + 1
			break
		}
	}
	if start < 0 {
		return nil, nil, fmt.Errorf("в шаблоне нет блока `config.yaml: |` — судить нечего")
	}
	seen := map[string]bool{}
	for _, l := range lines[start:] {
		if strings.TrimSpace(l) == "" {
			continue
		}
		indent := len(l) - len(strings.TrimLeft(l, " "))
		if indent < 4 && !strings.HasPrefix(strings.TrimSpace(l), "{{") {
			break // блок кончился: следующий ключ карты
		}
		if m := sectionHead.FindStringSubmatch(l); m != nil {
			if !seen[m[1]] {
				seen[m[1]] = true
				sections = append(sections, m[1])
			}
			continue
		}
		if m := sectionDirective.FindStringSubmatch(l); m != nil && !controlDirective(m[1]) {
			opaque = append(opaque, strings.TrimSpace(l))
		}
	}
	sort.Strings(sections)
	return sections, opaque, nil
}

// configTypeSections — теги `mapstructure` верхнего уровня у типа настроек.
func configTypeSections(t reflect.Type) []string {
	var out []string
	for i := 0; i < t.NumField(); i++ {
		tag := strings.Split(t.Field(i).Tag.Get("mapstructure"), ",")[0]
		if tag != "" && tag != "-" {
			out = append(out, tag)
		}
	}
	sort.Strings(out)
	return out
}

// configSectionsCensus — объём осмотренного, отдельно от находок.
type configSectionsCensus struct {
	Template int // секций в блоке шаблона
	Process  int // секций у типа настроек
	Ledger   int // записей ведомости нерендеримых
	Opaque   int // подстановок на уровне секции
}

func (c configSectionsCensus) String() string {
	return fmt.Sprintf("секций шаблона %d · секций процесса %d · в ведомости нерендеримых %d · "+
		"подстановок на уровне секции %d", c.Template, c.Process, c.Ledger, c.Opaque)
}

// judgeConfigSections — тело пробы: входы параметрами, пустой — отказ обхода.
func judgeConfigSections(
	templateBody string, process []string, ledger map[string]string,
) (findings []string, census configSectionsCensus, err error) {
	rendered, opaque, err := templateConfigSections(templateBody)
	if err != nil {
		return nil, census, err
	}
	if len(rendered) == 0 {
		return nil, census, fmt.Errorf("обход пуст: в блоке `config.yaml` шаблона ни одной секции")
	}
	if len(process) == 0 {
		return nil, census, fmt.Errorf("обход пуст: у типа настроек ни одного тега `mapstructure`")
	}
	census = configSectionsCensus{Template: len(rendered), Process: len(process), Ledger: len(ledger), Opaque: len(opaque)}

	inProcess := map[string]bool{}
	for _, s := range process {
		inProcess[s] = true
	}
	inTemplate := map[string]bool{}
	for _, s := range rendered {
		inTemplate[s] = true
		if !inProcess[s] {
			findings = append(findings, fmt.Sprintf(
				"  %s: секцию %q шаблон рендерит, а у `config.Config` её нет — загрузчик "+
					"отбросит её молча: ключ объявлен, поведение прежнее", configMapTemplatePath, s))
		}
	}
	for _, s := range process {
		if !inTemplate[s] && ledger[s] == "" {
			findings = append(findings, fmt.Sprintf(
				"  `config.Config` читает секцию %q, а %s её не рендерит и ведомость "+
					"`configSectionsNotRendered` не называет причины", s, configMapTemplatePath))
		}
	}
	keys := make([]string, 0, len(ledger))
	for s := range ledger {
		keys = append(keys, s)
	}
	sort.Strings(keys)
	for _, s := range keys {
		switch {
		case !inProcess[s]:
			findings = append(findings, fmt.Sprintf(
				"  ведомость нерендеримых называет %q, а у `config.Config` такой секции нет — "+
					"прощение пережило свой предмет", s))
		case inTemplate[s]:
			findings = append(findings, fmt.Sprintf(
				"  ведомость нерендеримых называет %q, а шаблон её теперь рендерит — "+
					"прощение выдано тому, кого судят", s))
		}
	}
	for _, l := range opaque {
		findings = append(findings, fmt.Sprintf(
			"  %s: подстановка на уровне секции %q — форма, которой проба не судит: "+
				"отдаваемых ею секций текст не показывает", configMapTemplatePath, l))
	}
	return findings, census, nil
}

func TestConfigSectionsOfTheChartAndTheProcessAgree(t *testing.T) {
	raw, err := os.ReadFile(configMapTemplatePath)
	require.NoError(t, err)
	findings, census, err := judgeConfigSections(string(raw),
		configTypeSections(reflect.TypeOf(config.Config{})), configSectionsNotRendered)
	require.NoError(t, err)
	t.Logf("перепись: %s", census)
	require.Emptyf(t, findings, "секции файла настроек расходятся с тем, что читает процесс:\n%s",
		strings.Join(findings, "\n"))
}
