// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// docs_listener_address_test.go — адрес слушателя, названный документацией,
// обязан резолвиться в тот объект Service, который этот порт ВЫСТАВЛЯЕТ.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ (kacho#2576)
//
// Руководство по разбору отказов звало `grpcurl … kaname:9091`. Порт 9091 несёт
// объект `kaname-internal`; публичный объект его не выставляет вовсе — и это не
// оплошность чарта, а его назначение (запрет #6: внутреннее не публикуется
// наружу свойством ОБЪЕКТА, а не обещанием). Значит команда не резолвится ни на
// одном стенде.
//
// Цена не косметическая: руководство читают в момент разбора отказа, то есть
// тогда, когда цена неверного адреса максимальна. Читатель получает отказ имени
// и начинает искать причину в продукте, а причина — в инструкции.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ГЕЙТ, А НЕ ОДНА ПРАВКА
//
// Имя платформы в таком адресе не участвует, поэтому ни одна полоса остатка
// имени его не видит; найдено оно было адъюдикацией, а не предикатом. Класс
// «документация называет адрес, которого чарт не выставляет» переживёт свою
// починку ровно так же, как пережил заведение: следующий порт приедет со своим
// объектом, а руководство допишут по памяти.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ИМЕННО УТВЕРЖДАЕТСЯ
//
// Всякий адрес формы `<имя>:<порт>` в документации, чьё `<имя>` ОБЪЯВЛЕНО
// чартом как объект Service, называет объект, у которого этот порт есть.
// Находкой считается адрес, где порт выставлен ДРУГИМ объявленным объектом:
// тогда сказать, чем адрес неверен и чем его заменить, можно машинно.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧЕГО ЭТА ПРОВЕРКА НЕ ЗАКРЫВАЕТ — сказано прямо
//
//  1. Порт, не выставленный НИ ОДНИМ объектом, находкой не объявляется: он
//     бывает адресом чужой службы, локальной переадресации или процесса вне
//     чарта, и различить это машинно нечем. Ось стережёт подмену объекта, а не
//     существование порта.
//  2. Порт, чьё выражение в шаблоне разбору не поддаётся (`include`), в перечень
//     объекта не попадает и учитывается отдельной величиной переписи — чтобы
//     «порт не выставлен» было отличимо от «порт не прочитан».
//  3. Правильность самой команды (флаги, имя метода) — не её предмет.
package supplyhygiene

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// chartValuesFile — профиль чарта: единственный источник величин, которые
// шаблон подставляет в объявление объектов.
const chartValuesFile = "deploy/values.yaml"

// chartServiceTemplate — объявление объектов Service.
const chartServiceTemplate = "deploy/templates/service.yaml"

// valuesExpr — ССЫЛКА НА ВЕЛИЧИНУ ПРОФИЛЯ внутри выражения шаблона. Разбирается
// только эта форма: всё прочее (`include`, конвейеры, умолчания) объявляется
// неразобранным и в перечень объекта не попадает. Так «порт не выставлен»
// остаётся отличимо от «порт не прочитан».
var valuesExpr = regexp.MustCompile(`^\{\{-?\s*\.Values\.([A-Za-z0-9_.]+)\s*-?\}\}$`)

// serviceNameExpr — имя объекта: ссылка на величину плюс необязательный
// литеральный суффикс (`{{ .Values.name }}-internal`).
var serviceNameExpr = regexp.MustCompile(`^\{\{-?\s*\.Values\.([A-Za-z0-9_.]+)\s*-?\}\}([A-Za-z0-9-]*)$`)

// yamlDocSeparator — граница объекта в многодокументном шаблоне.
const yamlDocSeparator = "---"

// listenerAddress — адрес формы `<имя>:<порт>`. Имя — DNS-метка, порт — от двух
// до пяти цифр. Обрамление прозы и кавычки снимает вызывающий.
var listenerAddress = regexp.MustCompile(`\b([a-z0-9][a-z0-9-]{0,61}[a-z0-9]):([0-9]{2,5})\b`)

// declaredService — объект Service, каким его объявляет чарт.
type declaredService struct {
	name  string
	ports map[int]struct{}
}

// addressFinding — одно попадание: координата, названный адрес и объект,
// который этот порт на самом деле выставляет.
type addressFinding struct {
	file  string
	line  int
	host  string
	port  int
	owner string
}

// listenerAddressCensus — объём осмотренного. Печатается всегда: «ноль находок»
// обязано быть отличимо от «ноль прочитанного», а «ноль распознанных адресов» —
// от «распознаватель ослеп».
type listenerAddressCensus struct {
	servicesParsed  int
	portsResolved   int
	portsUnresolved int
	docFilesScanned int
	linesScanned    int
	addressesSeen   int
	addressesOwned  int
}

// lookupValue — путь вида `ports.internalGrpc` в дереве профиля.
func lookupValue(values map[string]any, path string) (any, bool) {
	var cur any = values
	for _, segment := range strings.Split(path, ".") {
		node, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = node[segment]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

// resolveServiceName — имя объекта из выражения шаблона плюс литеральный суффикс.
func resolveServiceName(values map[string]any, expr string) (string, bool) {
	m := serviceNameExpr.FindStringSubmatch(strings.TrimSpace(expr))
	if m == nil {
		return "", false
	}
	v, ok := lookupValue(values, m[1])
	if !ok {
		return "", false
	}
	base, ok := v.(string)
	if !ok || base == "" {
		return "", false
	}
	return base + m[2], true
}

// resolvePort — порт из выражения шаблона. Неразобранное выражение возвращает
// false, и вызывающий считает его ОТДЕЛЬНОЙ величиной переписи.
func resolvePort(values map[string]any, expr string) (int, bool) {
	m := valuesExpr.FindStringSubmatch(strings.TrimSpace(expr))
	if m == nil {
		return 0, false
	}
	v, ok := lookupValue(values, m[1])
	if !ok {
		return 0, false
	}
	switch typed := v.(type) {
	case int:
		return typed, true
	case string:
		n, err := strconv.Atoi(typed)
		if err != nil {
			return 0, false
		}
		return n, true
	default:
		return 0, false
	}
}

// parseDeclaredServices — объекты Service и их порты, прочитанные из шаблона
// против профиля. Разбор структурный: имя берётся из первой строки `name:` на
// отступе метаданных, порты — из строк `port:` перечня.
func parseDeclaredServices(root string) ([]declaredService, int, int, error) {
	rawValues, err := os.ReadFile(filepath.Join(root, chartValuesFile))
	if err != nil {
		return nil, 0, 0, err
	}
	values := map[string]any{}
	if err := yaml.Unmarshal(rawValues, &values); err != nil {
		return nil, 0, 0, err
	}

	rawTemplate, err := os.ReadFile(filepath.Join(root, chartServiceTemplate))
	if err != nil {
		return nil, 0, 0, err
	}

	var (
		services   []declaredService
		resolved   int
		unresolved int
		current    *declaredService
	)

	flush := func() {
		if current != nil && current.name != "" {
			services = append(services, *current)
		}
		current = nil
	}

	for _, line := range strings.Split(string(rawTemplate), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == yamlDocSeparator {
			flush()
			continue
		}
		if trimmed == "kind: Service" {
			flush()
			current = &declaredService{ports: map[int]struct{}{}}
			continue
		}
		if current == nil {
			continue
		}
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if current.name == "" && strings.HasPrefix(trimmed, "name: ") {
			if name, ok := resolveServiceName(values, strings.TrimPrefix(trimmed, "name: ")); ok {
				current.name = name
			}
			continue
		}
		if strings.HasPrefix(trimmed, "port: ") {
			if port, ok := resolvePort(values, strings.TrimPrefix(trimmed, "port: ")); ok {
				current.ports[port] = struct{}{}
				resolved++
			} else {
				unresolved++
			}
		}
	}
	flush()

	return services, resolved, unresolved, nil
}

// scanDocsListenerAddresses — разбор над ПРОИЗВОЛЬНЫМ корнем: и чарт, и
// документация берутся оттуда же. Вынесено из теста затем, чтобы способность
// гейта упасть доказывалась подачей входа, а не чтением.
func scanDocsListenerAddresses(root string) (listenerAddressCensus, []addressFinding, error) {
	var census listenerAddressCensus

	services, resolved, unresolved, err := parseDeclaredServices(root)
	if err != nil {
		return census, nil, err
	}
	census.servicesParsed = len(services)
	census.portsResolved = resolved
	census.portsUnresolved = unresolved

	byName := make(map[string]declaredService, len(services))
	for _, svc := range services {
		byName[svc.name] = svc
	}

	// ownerOf — объект, выставляющий этот порт. Имя первого по объявлению:
	// порт, выставленный двумя объектами сразу, подменой не является.
	ownerOf := func(port int) (string, bool) {
		for _, svc := range services {
			if _, ok := svc.ports[port]; ok {
				return svc.name, true
			}
		}
		return "", false
	}

	var findings []addressFinding

	walkErr := filepath.Walk(filepath.Join(root, docsDir), func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".md") {
			return nil
		}
		raw, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		census.docFilesScanned++

		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			rel = path
		}

		for idx, line := range strings.Split(string(raw), "\n") {
			census.linesScanned++
			for _, m := range listenerAddress.FindAllStringSubmatch(line, -1) {
				census.addressesSeen++
				host := m[1]
				svc, known := byName[host]
				if !known {
					continue
				}
				census.addressesOwned++
				port, convErr := strconv.Atoi(m[2])
				if convErr != nil {
					continue
				}
				if _, ok := svc.ports[port]; ok {
					continue
				}
				owner, ok := ownerOf(port)
				if !ok {
					// Порт не выставлен НИ ОДНИМ объектом — не предмет оси.
					continue
				}
				findings = append(findings, addressFinding{
					file: filepath.ToSlash(rel), line: idx + 1, host: host, port: port, owner: owner,
				})
			}
		}
		return nil
	})
	if walkErr != nil {
		return census, nil, walkErr
	}

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].file != findings[j].file {
			return findings[i].file < findings[j].file
		}
		return findings[i].line < findings[j].line
	})

	return census, findings, nil
}

func TestDocsNameTheServiceThatActuallyExposesThePort(t *testing.T) {
	census, findings, err := scanDocsListenerAddresses(serviceRoot)
	require.NoError(t, err, "чарт или дерево документации не читаются")

	t.Logf(
		"перепись: объектов Service разобрано %d · портов резолвится %d · не разобрано выражений %d · "+
			"файлов документации %d · строк %d · адресов распознано %d · из них на объявленный объект %d · находок %d",
		census.servicesParsed, census.portsResolved, census.portsUnresolved,
		census.docFilesScanned, census.linesScanned, census.addressesSeen, census.addressesOwned, len(findings),
	)

	require.NotZero(t, census.servicesParsed, "обход пуст: объектов Service не разобрано ни одного — вердикт беспредметен")
	require.NotZero(t, census.portsResolved, "обход пуст: портов не резолвится ни одного — вердикт беспредметен")
	require.NotZero(t, census.docFilesScanned, "обход пуст: файлов документации не осмотрено ни одного — вердикт беспредметен")
	require.NotZero(t, census.addressesOwned, "обход пуст: адресов на объявленный объект не распознано ни одного — распознаватель ослеп")

	for _, f := range findings {
		t.Errorf(
			"%s:%d — назван адрес %s:%d, но порт %d выставляет объект %q, а не %q. "+
				"Команду читают в момент разбора отказа: неверное имя даёт отказ резолва там, где цена максимальна",
			f.file, f.line, f.host, f.port, f.port, f.owner, f.host,
		)
	}
}
