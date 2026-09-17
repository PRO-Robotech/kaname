// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check_test

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// Перечень глаголов с порогом уверенности «2» на клиентской странице модели
// авторизации обязан СХОДИТЬСЯ с контрактом: с опцией `required_acr_min = "2"`
// у RPC в `proto/kaname/cloud/iam/v1/*.proto` (задача kaname#207).
//
// # ПОЧЕМУ ГЕЙТ, А НЕ «ДОПИСАТЬ ЧЕТЫРЕ ГЛАГОЛА»
//
// Страница уже дважды пережила свой предмет: сначала числами («24 из 289»),
// потом выписанным перечнем — к 2026-09-17 в нём не было четырёх глаголов с
// живым порогом (`MembershipService.Create`, `UserService.ResendInvite`,
// `UserService.ResetSecondFactor`, `InternalModuleService.Apply`). Дописанный
// перечень разойдётся снова со следующим RPC, и разойдётся молча: клиент,
// строящий по странице, узнает о пороге отказом на глаголе, которого в
// перечне нет.
//
// # ЧТО СУДИТСЯ — В ОБЕ СТОРОНЫ, ПО УЗЛУ
//
// Контракт читается ПО СТРОКАМ ОБЪЯВЛЕНИЯ, а не по слову: имя службы берётся
// у `service X {`, имя глагола — у `rpc Y (`, порог — у строки опции внутри
// тела этого глагола. Слово `required_acr_min` встречается и в комментариях
// контракта; строка опции от комментария отличима формой (`option (…) = "2";`).
// Страница читается по код-форматированию `<code>Service.Verb</code>` внутри
// раздела «Step-up» — до следующего заголовка второго уровня.
//
// # ГРАНИЦА
//
// Гейт судит СОСТАВ перечня, а не верность колонки «что меняется» и не
// правильность самого порога: он сверяет страницу с контрактом, а не контракт
// с замыслом.
const (
	stepUpPageRel     = "docs/content/architecture/authz.mdx"
	stepUpContractDir = "proto/kaname/cloud/iam/v1"
	stepUpSectionHead = "## Step-up"
)

var (
	reProtoService = regexp.MustCompile(`^service\s+([A-Za-z0-9_]+)\s*\{`)
	reProtoRPC     = regexp.MustCompile(`^\s*rpc\s+([A-Za-z0-9_]+)\s*\(`)
	reProtoACR2    = regexp.MustCompile(`^\s*option\s*\(corelib\.authz\.v1\.required_acr_min\)\s*=\s*"2"\s*;`)
	reProtoClose   = regexp.MustCompile(`^\s*\}`)
	// rePageVerb — глагол в код-форматировании страницы: `Service.Verb`.
	rePageVerb = regexp.MustCompile(`<code>([A-Za-z0-9_]+Service)\.([A-Za-z0-9_]+)</code>`)
)

// stepUpCensus — объём осмотренного.
type stepUpCensus struct {
	contractFiles  int // файлов контракта прочитано
	rpcsRead       int // объявлений rpc прочитано
	flooredInProto int // из них с порогом «2»
	verbsOnPage    int // глаголов в разделе страницы
	missingOnPage  int
	extraOnPage    int
}

// flooredVerbsOf — глаголы с порогом «2» ОДНОГО файла контракта, по строкам.
func flooredVerbsOf(src string) (floored []string, rpcs int) {
	service, rpc := "", ""
	depth := 0 // глубина фигурных скобок внутри тела rpc: опции лежат на глубине 1
	for _, line := range strings.Split(src, "\n") {
		if m := reProtoService.FindStringSubmatch(line); m != nil {
			service = m[1]
			continue
		}
		if m := reProtoRPC.FindStringSubmatch(line); m != nil {
			rpc = m[1]
			rpcs++
			depth = strings.Count(line, "{") - strings.Count(line, "}")
			continue
		}
		if rpc == "" {
			continue
		}
		if reProtoACR2.MatchString(line) && service != "" {
			floored = append(floored, service+"."+rpc)
		}
		depth += strings.Count(line, "{") - strings.Count(line, "}")
		if depth <= 0 && reProtoClose.MatchString(line) {
			rpc = ""
		}
	}
	return floored, rpcs
}

// stepUpSection — текст раздела «Step-up» страницы: от заголовка до следующего
// заголовка второго уровня.
func stepUpSection(page string) string {
	start := strings.Index(page, stepUpSectionHead)
	if start < 0 {
		return ""
	}
	rest := page[start+len(stepUpSectionHead):]
	if end := strings.Index(rest, "\n## "); end >= 0 {
		rest = rest[:end]
	}
	return rest
}

// auditStepUpPage — чистое ядро: контракт (файл → текст) против страницы.
func auditStepUpPage(contract map[string]string, page string) ([]string, stepUpCensus) {
	c := stepUpCensus{contractFiles: len(contract)}
	floored := map[string]bool{}
	for _, name := range sortedKeys(boolKeys(contract)) {
		verbs, rpcs := flooredVerbsOf(contract[name])
		c.rpcsRead += rpcs
		for _, v := range verbs {
			floored[v] = true
		}
	}
	c.flooredInProto = len(floored)

	onPage := map[string]bool{}
	for _, m := range rePageVerb.FindAllStringSubmatch(stepUpSection(page), -1) {
		onPage[m[1]+"."+m[2]] = true
	}
	c.verbsOnPage = len(onPage)

	var findings []string
	for _, v := range sortedKeys(floored) {
		if !onPage[v] {
			c.missingOnPage++
			findings = append(findings, fmt.Sprintf(
				"глагол %s несёт порог «2» в контракте, а раздел Step-up страницы %s его НЕ называет — "+
					"клиент узнает о пороге отказом", v, stepUpPageRel))
		}
	}
	for _, v := range sortedKeys(onPage) {
		if !floored[v] {
			c.extraOnPage++
			findings = append(findings, fmt.Sprintf(
				"страница называет %s глаголом с порогом «2», а контракт порога у него не несёт — "+
					"утверждение пережило свой предмет", v))
		}
	}
	return findings, c
}

func boolKeys(m map[string]string) map[string]bool {
	out := map[string]bool{}
	for k := range m {
		out[k] = true
	}
	return out
}

// TestStepUpPageMatchesTheContract — несущее утверждение.
func TestStepUpPageMatchesTheContract(t *testing.T) {
	dir := platformtree.RequirePath(t, stepUpContractDir)
	names, err := filepath.Glob(filepath.Join(dir, "*.proto"))
	require.NoError(t, err)
	contract := map[string]string{}
	for _, name := range names {
		body, rerr := os.ReadFile(name) // #nosec G304 -- путь собран из корня собственного модуля
		require.NoError(t, rerr)
		contract[filepath.Base(name)] = string(body)
	}
	page, err := os.ReadFile(platformtree.RequirePath(t, stepUpPageRel)) // #nosec G304 -- путь собран из корня собственного модуля
	require.NoError(t, err)

	findings, c := auditStepUpPage(contract, string(page))
	t.Logf("перепись: файлов контракта %d · rpc прочитано %d · с порогом «2» %d · глаголов в разделе страницы %d · "+
		"нет на странице %d · лишних на странице %d · находок %d",
		c.contractFiles, c.rpcsRead, c.flooredInProto, c.verbsOnPage, c.missingOnPage, c.extraOnPage, len(findings))

	require.NotZerof(t, c.rpcsRead, "в %s не прочитано ни одного rpc — вердикт беспредметен", stepUpContractDir)
	require.NotZerof(t, c.flooredInProto, "ни один rpc не несёт порога «2» — вердикт беспредметен")
	require.NotZerof(t, c.verbsOnPage, "в разделе Step-up страницы %s не прочитано ни одного глагола — вердикт беспредметен", stepUpPageRel)
	require.Emptyf(t, findings, "раздел Step-up страницы %s разошёлся с контрактом:\n%s",
		stepUpPageRel, strings.Join(findings, "\n"))
}
