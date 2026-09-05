// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// condition_bypass_needs_the_edge_test.go — право, объявленное требующим
// усиленного входа, не выдаётся без него ЦЕЛОМУ КЛАССУ субъектов молча
// (задача продукта #2056).
//
// # ПРЕДМЕТ
//
// Два отношения модели объявлены с условием свежести второго фактора и при этом
// несут безусловную ветвь:
//
//	define ssh:     [user with mfa_fresh, service_account] or admin
//	define console: [user with mfa_fresh] or admin
//
// Левая часть объявляет требование, правая его обходит: распорядителю ресурса
// условие не нужно. Никем это не решалось — ветвь `or admin` приехала формой
// соседних отношений (`viewer`/`editor`/`admin`), где условия нет и быть не
// должно. Различие существенное: соседи — про УПРАВЛЕНИЕ ресурсом, а `ssh` и
// `console` — про вход ВНУТРЬ машины, за которым не наблюдает ни одна проверка
// платформы.
//
// # ПОЧЕМУ ПРОБЫ НА САМО ОТНОШЕНИЕ ЗДЕСЬ НЕТ, А ГЕЙТ ЕСТЬ
//
// Читателя у обоих отношений сегодня НОЛЬ: записей каталога прав, требующих
// `ssh` либо `console`, нет ни одной, RPC входа в машину в контрактах нет вовсе.
// Позвать вердикт нечем, и проба на него была бы формой без содержания.
//
// Но форма отношения уже написана, и в день, когда вход в машину появится, она
// начнёт действовать в том виде, в каком лежит. Поэтому здесь стоит гейт,
// который СЕГОДНЯ МОЛЧИТ и краснеет В ТОТ МОМЕНТ, когда у отношения появляется
// читатель, — то есть ровно тогда, когда решение обязано быть исполнено.
// Послабление истекает от появления предмета, а не от чьей-то памяти.
//
// # ЧТО ИМЕННО ТРЕБУЕТСЯ ОТ ЧИТАТЕЛЯ
//
// Решение записано в
// `services/iam/docs/engineering/architecture/machine-login-condition-is-enforced-at-the-edge.md`:
// энфорсером полосы входа в машину объявлен КРАЙ. Значит запись каталога,
// требующая такого отношения, обязана нести `required_acr_min` — иначе
// требование усиленного входа не исполняет никто: модель его обходит ветвью
// `or admin`, а край о нём не знает.
//
// Почему не «вернуть условие администратору внутри модели»: язык модели
// приписывает условие ТОЛЬКО прямому присвоению (`[тип with условие]`) и не
// умеет приписать его вычисляемой ветви. Замер по дереву: форм `or … with …` в
// каноническом файле — 0. Значит первый исход задачи невыразим средствами
// модели, и остаётся второй.
//
// # ЧЕГО ГЕЙТ НЕ ЛОВИТ (названо, чтобы на него не сослались шире предмета)
//
// Он не судит, ВЕРНА ли величина `required_acr_min`, и не смотрит на энфорс в
// хендлере: пара, решение по которой принимает сам сервис, каталогом не
// выражается by construction. Он утверждает одно — что требование, объявленное
// моделью и ею же обходимое, не уезжает наружу без энфорсера на крае.

package authzmap_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// conditionalDecl — объявление отношения, разобранное по двум осям.
type conditionalDecl struct {
	typeName string
	relation string
	body     string
	// conditioned — прямое присвоение несёт условие (`[… with …]`).
	conditioned bool
	// bypassed — рядом стоит ветвь БЕЗ условия (`or …`).
	bypassed bool
}

func (d conditionalDecl) String() string { return d.typeName + "#" + d.relation }

var (
	reDeclType   = regexp.MustCompile(`^type (\w+)`)
	reDeclDefine = regexp.MustCompile(`^\s+define (\w+):\s*(.*)$`)
	reDirectList = regexp.MustCompile(`\[([^\]]*)\]`)
)

// parseConditionalDecls разбирает DSL модели в объявления отношений.
//
// Разбор судит УЗЛЫ объявления, а не текст строки: условие ищется внутри списка
// прямого присвоения (в квадратных скобках), обходная ветвь — в остатке ПОСЛЕ
// этого списка. Иначе слово `or` внутри имени условия и слово `with` в
// комментарии считались бы предметом.
func parseConditionalDecls(dsl string) (decls []conditionalDecl, types int) {
	cur := ""
	seenTypes := map[string]bool{}
	for _, line := range strings.Split(dsl, "\n") {
		if code := strings.SplitN(line, "#", 2)[0]; strings.TrimSpace(code) == "" && strings.Contains(line, "#") {
			continue // строка-комментарий целиком
		}
		if m := reDeclType.FindStringSubmatch(line); m != nil {
			cur = m[1]
			if !seenTypes[cur] {
				seenTypes[cur] = true
				types++
			}
			continue
		}
		m := reDeclDefine.FindStringSubmatch(line)
		if m == nil || cur == "" {
			continue
		}
		body := strings.TrimSpace(m[2])
		d := conditionalDecl{typeName: cur, relation: m[1], body: body}
		rest := body
		if lm := reDirectList.FindStringSubmatchIndex(body); lm != nil {
			d.conditioned = strings.Contains(body[lm[2]:lm[3]], " with ")
			rest = body[lm[1]:]
		}
		d.bypassed = strings.Contains(" "+rest+" ", " or ")
		decls = append(decls, d)
	}
	return decls, types
}

// catalogReader — запись каталога прав, требующая названного отношения.
type catalogReader struct {
	fqn        string
	relation   string
	objectType string
	acrMin     string
}

// conditionBypassFindings — судья, отделённый от дерева ради инъекции.
//
// Находка одна и только одна: у отношения, чьё условие обходимо, появился
// читатель, и этот читатель НЕ несёт величины усиленного входа.
func conditionBypassFindings(decls []conditionalDecl, readers []catalogReader) []string {
	bypassable := map[string][]conditionalDecl{}
	for _, d := range decls {
		if d.conditioned && d.bypassed {
			bypassable[d.relation] = append(bypassable[d.relation], d)
		}
	}
	var out []string
	for _, r := range readers {
		ds, ok := bypassable[r.relation]
		if !ok || r.acrMin != "" {
			continue
		}
		names := make([]string, 0, len(ds))
		for _, d := range ds {
			names = append(names, d.String())
		}
		sort.Strings(names)
		out = append(out, fmt.Sprintf(
			"%s требует отношения %q (объявлено: %s), чьё условие обходится безусловной "+
				"ветвью, и НЕ несёт required_acr_min — требование усиленного входа не "+
				"исполняет никто: модель его обходит, край о нём не знает",
			r.fqn, r.relation, strings.Join(names, ", ")))
	}
	sort.Strings(out)
	return out
}

// TestConditionBypassedByAnArmNeedsTheEdgeEnforcer — гейт.
func TestConditionBypassedByAnArmNeedsTheEdgeEnforcer(t *testing.T) {
	dsl, err := os.ReadFile(canonicalModelPath(t))
	require.NoError(t, err, "канонический файл модели не прочитан")

	decls, types := parseConditionalDecls(string(dsl))
	require.NotZerof(t, types, "в модели не разобрано ни одного типа — предпосылка гейта сломана")
	require.NotZerof(t, len(decls), "в модели не разобрано ни одного объявления отношения — "+
		"«ноль находок» означало бы «ноль прочитанного»")

	readers := catalogReadersOfAnyRelation(t)
	require.NotZerof(t, len(readers), "каталог прав не дал ни одной записи с требуемым "+
		"отношением — сверять было бы не с чем")

	var bypassable, conditioned int
	names := []string{}
	for _, d := range decls {
		if d.conditioned {
			conditioned++
		}
		if d.conditioned && d.bypassed {
			bypassable++
			names = append(names, d.String())
		}
	}
	sort.Strings(names)

	withReader := 0
	for _, r := range readers {
		for _, d := range decls {
			if d.conditioned && d.bypassed && d.relation == r.relation {
				withReader++
				break
			}
		}
	}

	findings := conditionBypassFindings(decls, readers)

	t.Logf("перепись: типов модели %d, объявлений отношений %d, из них с условием %d, "+
		"из них с обходимым условием %d (%s); записей каталога с требуемым отношением %d, "+
		"из них читающих обходимое отношение %d; находок %d",
		types, len(decls), conditioned, bypassable, strings.Join(names, ", "),
		len(readers), withReader, len(findings))

	require.Empty(t, findings, strings.Join(findings, "\n"))
}

// catalogReadersOfAnyRelation — записи каталога, требующие какого-либо отношения.
func catalogReadersOfAnyRelation(t *testing.T) []catalogReader {
	t.Helper()
	path := filepath.Join(monorepoRoot(t), catalogRelPath)
	data, err := os.ReadFile(path)
	require.NoErrorf(t, err, "каталог прав %s не прочитан", catalogRelPath)

	var entries []struct {
		FQN              string `json:"fqn"`
		RequiredRelation string `json:"required_relation"`
		RequiredACRMin   string `json:"required_acr_min"`
		ScopeExtractor   struct {
			ObjectType string `json:"object_type"`
		} `json:"scope_extractor"`
	}
	require.NoError(t, json.Unmarshal(data, &entries))
	require.NotEmptyf(t, entries, "каталог прав %s разобран в ноль записей", catalogRelPath)

	out := make([]catalogReader, 0, len(entries))
	for _, e := range entries {
		if e.RequiredRelation == "" {
			continue
		}
		out = append(out, catalogReader{
			fqn:        e.FQN,
			relation:   e.RequiredRelation,
			objectType: e.ScopeExtractor.ObjectType,
			acrMin:     e.RequiredACRMin,
		})
	}
	return out
}
