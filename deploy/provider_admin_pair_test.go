// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// provider_admin_pair_test.go — ПЕРЕПИСЬ В ДВЕ КОЛОНКИ: профиль, называющий
// АДРЕС административного контура поставщика личности, обязан сказать и то,
// ЧЕМ этот контур нас аутентифицирует.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Контроль, обращающийся к соседу под своей личностью, обязан нести ПАРУ —
// адрес и удостоверение. Половина пары хуже отсутствия обеих: она выглядит
// настроенной.
//
// Замер, из которого гейт выведен (задача #2471, единица счёта — источник
// профиля, читаемый РАЗОБРАННЫМ, а не подстрокой): источников прочитано 8,
// адрес называют 6, удостоверение — НОЛЬ. Обоснование терпимости —
// «административный порт поставщика в этой посадке не аутентифицирует никого» —
// есть утверждение о НАШЕМ стенде, перенесённое в продукт, который ставят у
// себя другие. Оператор в чужом облаке, чей поставщик свой административный
// доступ аутентифицирует, получал отказ на КАЖДОЙ административной операции
// фасада и НИ ОДНОЙ строки при старте о причине.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ИМЕННО ТРЕБУЕТСЯ: ВЫСКАЗЫВАНИЕ, А НЕ ПРЕДЪЯВИТЕЛЬ
//
// Требовать предъявителя от каждого профиля нельзя: бывает поставщик, чей
// административный порт и правда не аутентифицирует никого, и тогда
// предъявителя не существует. Требуется, чтобы это было СКАЗАНО — ручкой
// `authn.providerAdminAuth` со значением из закрытого словаря. Тогда «не нужен»
// становится решением оператора про его поставщика, а не нашим умолчанием про
// чужую установку.
//
// Вторую половину — объявленный `bearer` без пришедшего предъявителя — судит
// СТРАЖ СТАРТА (`requireProviderAdminCredentialPair` в композиционном корне):
// её нельзя увидеть из профиля, потому что предъявитель приходит объектом
// Secret, которого в дереве нет и быть не должно.
//
// ─────────────────────────────────────────────────────────────────────────────
// ВЕДОМОСТЬ — ПО ПРОФИЛЯМ, И ОНА САМОИСТЕКАЕТ
//
// Профили НАШЕГО стенда высказываться не обязаны: про своего поставщика мы
// знаем, его административный порт не аутентифицирует никого, и эти профили
// правим мы, а не клиент. Каждый назван поимённо с причиной; запись, которой
// больше некого прощать, — находка.
//
// Профили ПОСТАВЛЯЕМОГО чарта в ведомость не идут ни при каком доводе: их
// правит оператор чужого облака, и утверждение про его поставщика мы делать не
// вправе.
package deploy_test

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// adminAddressLeaves / adminAuthLeaves — как ручка называется в ЛИСТЕ дерева
// значений. Префикс источника (алиас подчарта у зонта, корень у поставляемого
// чарта) отбрасывается by construction: сравнивается последний сегмент, поэтому
// перепись не зависит от того, за каким алиасом стоит служба.
var (
	adminAddressLeaves = []string{"hydraadminurl", "kaname_hydra_admin_url"}
	adminAuthLeaves    = []string{"provideradminauth", "kaname_hydra_admin_token", "hydraadmintokenenv"}
)

// standProfilesExcused — профили НАШЕГО стенда, которым высказываться не нужно.
//
// Ключ — путь от корня монорепо; причина обязана называть, ЧЕЙ это поставщик.
var standProfilesExcused = map[string]string{
	"deploy/helm/umbrella/charts/kaname/values.yaml": "профиль НАШЕГО стенда: поставщик " +
		"личности поднимается тем же зонтом, его административный порт не аутентифицирует " +
		"никого, и правим этот файл мы, а не клиент",
	"deploy/helm/umbrella/values.dev.yaml":         "профиль НАШЕГО стенда — см. выше",
	"deploy/helm/umbrella/values.dev-prod.yaml":    "профиль НАШЕГО стенда — см. выше",
	"deploy/helm/umbrella/values.prod.yaml":        "профиль НАШЕГО стенда — см. выше",
	"deploy/helm/umbrella/values.fe3455-prod.yaml": "профиль НАШЕГО стенда — см. выше",
}

// leafNames — имена ЛИСТЬЕВ дерева значений, приведённые к сравнимому виду.
func leafNames(node any, out map[string]bool) {
	switch typed := node.(type) {
	case map[string]any:
		for k, v := range typed {
			key := strings.ToLower(strings.NewReplacer("-", "", ".", "").Replace(k))
			out[key] = true
			leafNames(v, out)
		}
	case []any:
		for _, v := range typed {
			leafNames(v, out)
		}
	}
}

// namesAnyOf — назван ли в профиле хоть один из перечисленных листьев.
func namesAnyOf(leaves map[string]bool, want []string) bool {
	for _, w := range want {
		if leaves[strings.ToLower(strings.NewReplacer("-", "", "_", "").Replace(w))] ||
			leaves[strings.ToLower(w)] {
			return true
		}
	}
	return false
}

// judgeProviderAdminPair — ТЕЛО гейта, вынесенное отдельно, чтобы инъекция
// звала то же, что исполняется на дереве.
func judgeProviderAdminPair(
	addressed, decided map[string]bool, excused map[string]string,
) (findings []string) {
	for profile := range addressed {
		if decided[profile] {
			continue
		}
		if _, ok := excused[profile]; ok {
			continue
		}
		findings = append(findings, "профиль "+profile+" называет АДРЕС административного "+
			"контура и не говорит, ЧЕМ этот контур нас аутентифицирует "+
			"(authn.providerAdminAuth): половина пары выглядит настроенной, а отказ придёт "+
			"на каждой административной операции фасада и ни одной строкой при старте")
	}
	for profile := range excused {
		if !addressed[profile] {
			findings = append(findings, "ведомость называет "+profile+
				", а этот профиль адреса административного контура не называет: запись "+
				"пережила свой предмет")
		}
	}
	sort.Strings(findings)
	return findings
}

func TestProfilesNamingTheProviderAdminAddressAlsoNameItsCredentialChoice(t *testing.T) {
	svcRoot := serviceRoot(t)
	outer := outerRoot(t)

	type source struct{ label, dir string }
	sources := []source{{"чарт продукта", filepath.Join(svcRoot, "deploy")}}
	umbrella := filepath.Join(outer, "deploy", "helm", "umbrella")
	if st, err := os.Stat(umbrella); err == nil && st.IsDir() {
		sources = append(sources,
			source{"зонт платформы", umbrella},
			source{"подчарт зонта", filepath.Join(umbrella, "charts", "kaname")})
	}

	addressed := map[string]bool{}
	decided := map[string]bool{}
	read := 0

	for _, src := range sources {
		entries, err := os.ReadDir(src.dir)
		require.NoErrorf(t, err, "каталог источника не читается: %s", src.dir)
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || !strings.HasPrefix(name, "values") || !strings.HasSuffix(name, ".yaml") {
				continue
			}
			path := filepath.Join(src.dir, name)
			raw, rerr := os.ReadFile(path) // #nosec G304 -- путь из обхода дерева
			require.NoErrorf(t, rerr, "профиль не читается: %s", path)
			var doc any
			require.NoErrorf(t, yaml.Unmarshal(raw, &doc), "профиль не разбирается: %s", path)
			read++

			leaves := map[string]bool{}
			leafNames(doc, leaves)
			rel, relErr := filepath.Rel(outer, path)
			if relErr != nil {
				rel = path
			}
			rel = filepath.ToSlash(rel)
			if namesAnyOf(leaves, adminAddressLeaves) {
				addressed[rel] = true
			}
			if namesAnyOf(leaves, adminAuthLeaves) {
				decided[rel] = true
			}
		}
	}

	require.NotZero(t, read, "обход пуст: профилей прочитано 0 — вердикт беспредметен")
	require.NotEmpty(t, addressed,
		"обход пуст: профилей, называющих адрес административного контура, 0 — "+
			"вердикт беспредметен: гейт заведён ровно про них")

	// Ведомость судится ТОЛЬКО там, где её предмет есть: у арендатора зонта нет
	// вовсе, и записи о его профилях прощают то, чего он не видит. Судить их там
	// значило бы краснеть на факте дерева, а не на находке.
	excused := standProfilesExcused
	if len(sources) == 1 {
		excused = map[string]string{}
		t.Log("зонта платформы в этом дереве нет — ведомость профилей стенда не судится: " +
			"её предмет отсутствует by construction")
	}

	findings := judgeProviderAdminPair(addressed, decided, excused)

	names := make([]string, 0, len(addressed))
	for p := range addressed {
		mark := "—"
		if decided[p] {
			mark = "да"
		}
		names = append(names, p+" (выбор: "+mark+")")
	}
	sort.Strings(names)
	t.Logf("перепись: источников %d · профилей прочитано %d · называют АДРЕС %d · "+
		"называют ВЫБОР %d · названо в ведомости стенда %d",
		len(sources), read, len(addressed), len(decided), len(excused))
	t.Logf("по профилям: %s", strings.Join(names, ", "))

	for _, f := range findings {
		t.Error(f)
	}
}
