// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// image_coordinate_test.go — КООРДИНАТУ ОБРАЗА НАЗЫВАЕТ ТОТ, КТО СТАВИТ.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Базовые значения чарта объявляли `image: kaname:dev`. Тег `:dev` — артефакт
// НАШЕГО стенда: его кладёт в узлы сборка образов, и в чужом кластере его нет и
// быть не может. Умолчание при этом ВСЕГДА НЕПУСТО, поэтому профиль читается
// настроенным, а отказ приходит уже в кластере:
//
//	Failed to pull image "kaname:dev": pull access denied, repository does not
//	exist or may require authorization  (Init:ImagePullBackOff)
//
// Это тот же класс, что имена объектов нашего зонтичного релиза в умолчаниях
// (соседняя проба `foreign_object_defaults_test.go`), только на шаг дальше: там
// имя ОБЪЕКТА кластера, здесь координата ОБРАЗА в реестре. Отказ, приходящий в
// кластере, дороже отказа установки на порядок: до него надо доехать.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ЭТО НЕ ЗАКРЫЛА СОСЕДНЯЯ ПРОБА
//
// Её популяция выводится из ПОЗИЦИЙ ССЫЛКИ НА ОБЪЕКТ (`secretName:`,
// `secretKeyRef`, `configMap`). Координата образа такой позицией не является:
// образ — не объект Kubernetes. Расширять ту популяцию задним числом значило бы
// менять предмет уже доказанной пробы; предмет другой, и он судится здесь.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ПРОБА СУДИТ И ЧЕГО НЕ СУДИТ — граница названа первой
//
// Она ДЕКЛАРАТИВНА: читает объявления — базовые значения и профили, — а не
// отрендеренный вывод. Рендер требует helm и потому может пропуститься;
// объявление читается всегда.
//
// Она судит, НАЗВАНА ли координата, и НЕ судит, ЧТО именно названо: подставить
// за оператора имя его реестра нельзя, а заглушка в зарезервированной области
// `.example.invalid` — предписание той же формы, что у `db.host` рядом.
//
// Координата, прибитая в шаблоне ЛИТЕРАЛОМ, здесь СЧИТАЕТСЯ (её видно в
// переписи отдельным числом) и не судится. Причина названа, а не подразумевается:
// предмет этой пробы — умолчание, которое оператор обязан заменить, а литерал
// заменить нельзя вовсе, и вопрос к нему другой.
//
// ГРАНИЦА НАЗВАНА ЧЕСТНО, включая то, чего не судит НИКТО: литерал в
// контейнере НАКАТА судит `schema_mechanism_precedes_the_service_test.go`
// («образ наката задан литералом» — там он обязан приходить из тех же значений,
// что образ службы). Литерал на ПОСТОРОННЕМ контейнере — например, у ожидающего
// базу — не судится ни там, ни здесь: такой контейнер несёт чужой образ по
// построению, и требовать от него нашей координаты значило бы краснеть на
// верном чарте.
package deploy_test

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// ── популяция ────────────────────────────────────────────────────────────────

// imageCoordinate — одна найденная позиция координаты образа в шаблонах.
type imageCoordinate struct {
	file string
	line int
	path string // путь в дереве значений; пусто — координата прибита литералом
	expr string
}

// readChartValues — дерево значений одного файла профиля.
func readChartValues(path string) (map[string]any, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var tree map[string]any
	if err := yaml.Unmarshal(raw, &tree); err != nil {
		return nil, fmt.Errorf("%s не разбирается: %w", filepath.Base(path), err)
	}
	return tree, nil
}

// chartTemplateNames — файлы каталога шаблонов, по алфавиту.
func chartTemplateNames(chartDir string) ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(chartDir, templatesDir))
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names, nil
}

// templateAliases — псевдонимы шаблона: `$tls := .Values.tls`,
// `range $k, $v := .Values.secrets`. Собираются по всему тексту разом: объявление
// стоит выше употребления, и порядок строк тут ничего не решает.
func templateAliases(text string) map[string]string {
	aliases := map[string]string{}
	for _, m := range aliasAssignRe.FindAllStringSubmatch(text, -1) {
		aliases["$"+m[1]] = m[2]
	}
	for _, m := range rangeAssignRe.FindAllStringSubmatch(text, -1) {
		aliases["$"+m[2]] = m[3] + ".*"
	}
	return aliases
}

// yamlKeyOf — ключ строки YAML-шаблона. Строка комментария ключом не является:
// проза о ключе — не объявление ключа, и распознаватель, читающий её как
// объявление, краснел бы на собственном объяснении.
func yamlKeyOf(trimmed string) string {
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return ""
	}
	idx := strings.Index(trimmed, ":")
	if idx <= 0 {
		return ""
	}
	return strings.TrimLeft(strings.TrimSpace(trimmed[:idx]), "- ")
}

// collectImageCoordinates — позиции координаты образа во ВСЕХ шаблонах чарта,
// плюс перепись осмотренного.
//
// Популяция ВЫВОДИТСЯ из шаблонов, а не выписывается перечнем ключей:
// выписанный перечень разошёлся бы с шаблоном МОЛЧА — новый контейнер появляется
// коммитом в шаблон, перечень о нём не знает и остаётся зелёным.
func collectImageCoordinates(chartDir string) (coords []imageCoordinate, filesRead, linesRead int, err error) {
	names, err := chartTemplateNames(chartDir)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("каталог шаблонов не читается: %w", err)
	}
	for _, name := range names {
		raw, readErr := os.ReadFile(filepath.Join(chartDir, templatesDir, name))
		if readErr != nil {
			return nil, 0, 0, fmt.Errorf("шаблон %s не читается: %w", name, readErr)
		}
		text := string(raw)

		if name == helpersFile {
			// ПРЕДПОСЫЛКА, А НЕ ДОПУЩЕНИЕ: файл именованных шаблонов
			// пропускается только пока он не рендерит объектов. Заведут в нём
			// ресурс — обход скажет об этом, вместо того чтобы молча его не
			// осмотреть.
			if strings.Contains(text, "\nkind:") {
				return nil, 0, 0, fmt.Errorf(
					"%s объявляет ресурс — он больше не только именованные шаблоны, "+
						"и его позиции образа перестали осматриваться", name)
			}
			continue
		}

		filesRead++
		lines := strings.Split(text, "\n")
		linesRead += len(lines)
		aliases := templateAliases(text)

		for i, line := range lines {
			if yamlKeyOf(strings.TrimSpace(line)) != "image" {
				continue
			}
			trimmed := strings.TrimSpace(line)
			refs := resolveRefs(line, aliases)
			if len(refs) == 0 {
				coords = append(coords, imageCoordinate{name, i + 1, "", trimmed})
				continue
			}
			for _, p := range refs {
				coords = append(coords, imageCoordinate{name, i + 1, p, trimmed})
			}
		}
	}
	return coords, filesRead, linesRead, nil
}

// chartProfileNames — накладки чарта (`values.<профиль>.yaml`), по алфавиту.
// Базовые значения (`values.yaml`) накладкой не являются: они применяются, когда
// оператор не сказал ничего.
func chartProfileNames(chartDir string) ([]string, error) {
	matches, err := filepath.Glob(filepath.Join(chartDir, "values.*.yaml"))
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(matches))
	for _, m := range matches {
		names = append(names, filepath.Base(m))
	}
	sort.Strings(names)
	return names, nil
}

// ── аудит ────────────────────────────────────────────────────────────────────

// auditImageCoordinate — вердикт о координате образа: базовые значения её не
// несут, а каждая накладка, на которой служба поднимается, называет её явно.
//
// Обход, которому нечего читать, — ОШИБКА, а не чистое дерево: «ноль находок»
// обязано быть отличимо от «ноль прочитанного».
func auditImageCoordinate(chartDir string) (findings []string, census string, err error) {
	coords, filesRead, linesRead, err := collectImageCoordinates(chartDir)
	if err != nil {
		return nil, "", err
	}

	pathSet := map[string]imageCoordinate{}
	literals := 0
	for _, c := range coords {
		if c.path == "" {
			literals++
			continue
		}
		if _, dup := pathSet[c.path]; !dup {
			pathSet[c.path] = c
		}
	}
	paths := make([]string, 0, len(pathSet))
	for p := range pathSet {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	if len(paths) == 0 {
		return nil, "", fmt.Errorf(
			"обход пуст: ни одна позиция образа не берётся из значений чарта "+
				"(шаблонов прочитано %d, строк %d) — вердикт беспредметен", filesRead, linesRead)
	}

	profiles, err := chartProfileNames(chartDir)
	if err != nil {
		return nil, "", fmt.Errorf("накладки чарта не перечислены: %w", err)
	}
	if len(profiles) == 0 {
		return nil, "", fmt.Errorf(
			"обход пуст: у чарта нет ни одной накладки `values.<профиль>.yaml` — " +
				"утверждать, что координату называет тот, кто ставит, не на чем")
	}

	defaults, err := readChartValues(filepath.Join(chartDir, chartDefaultsFile))
	if err != nil {
		return nil, "", fmt.Errorf("базовые значения не читаются: %w", err)
	}

	// ОТРИЦАНИЕ: умолчания у координаты образа нет.
	for _, p := range paths {
		v, declared := leafAt(defaults, p)
		if !declared {
			continue
		}
		s := strings.TrimSpace(fmt.Sprintf("%v", v))
		if s == "" || s == "<nil>" {
			continue
		}
		c := pathSet[p]
		findings = append(findings, fmt.Sprintf(
			"  %s: %s = %q — умолчание координаты образа непусто (позиция %s:%d). "+
				"Непустое умолчание всегда выглядит настройкой и в чужом кластере ведёт в "+
				"никуда: образ по этой координате не тянется, и отказ приходит уже в кластере "+
				"(ImagePullBackOff), а не при установке. Снимите умолчание (пустая строка) и "+
				"назовите координату в накладке.",
			chartDefaultsFile, p, s, c.file, c.line))
	}

	// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ, а не украшение: без него отрицание выше зеленело
	// бы на чарте, который не ставится НИ ОДНОЙ накладкой — то есть на снятом
	// умолчании, которого никто не заменил.
	for _, prof := range profiles {
		overlay, readErr := readChartValues(filepath.Join(chartDir, prof))
		if readErr != nil {
			return nil, "", fmt.Errorf("накладка не читается: %w", readErr)
		}
		merged := mergeInto(mergeInto(map[string]any{}, defaults), overlay)
		for _, p := range paths {
			v, _ := leafAt(merged, p)
			s := strings.TrimSpace(fmt.Sprintf("%v", v))
			if s != "" && s != "<nil>" {
				continue
			}
			findings = append(findings, fmt.Sprintf(
				"  %s: %s не названа — цепочка `%s + %s` даёт пустую координату образа, "+
					"и под с ней не создаётся вовсе. Накладка есть объявление посадки: "+
					"координату реестра называет она, потому что подставить её за того, кто "+
					"ставит, нельзя.",
				prof, p, chartDefaultsFile, prof))
		}
	}

	census = fmt.Sprintf(
		"шаблонов прочитано %d · строк %d · позиций образа %d (через значения %d, литералом %d) · "+
			"путей значений %d (%s) · накладок %d (%s) · находок %d",
		filesRead, linesRead, len(coords), len(coords)-literals, literals,
		len(paths), strings.Join(paths, ", "), len(profiles), strings.Join(profiles, ", "), len(findings))
	return findings, census, nil
}

// ── проба ────────────────────────────────────────────────────────────────────

// TestImageCoordinateIsNamedByWhoeverInstalls — несущая проба задачи #2094.
func TestImageCoordinateIsNamedByWhoeverInstalls(t *testing.T) {
	chartDir := filepath.Join(serviceRoot(t), "deploy")

	findings, census, err := auditImageCoordinate(chartDir)
	require.NoError(t, err, "обход не состоялся")
	t.Logf("перепись: %s", census)

	require.Empty(t, findings,
		"координата образа названа не тем, кто ставит:\n%s", strings.Join(findings, "\n"))
}
