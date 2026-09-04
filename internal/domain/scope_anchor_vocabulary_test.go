// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package domain

// scope_anchor_vocabulary_test.go — вокабуляр ЯКОРЯ ОБЛАСТИ объявлен ОДИН раз, и
// `ResourceType.Validate()` судит по нему, а не по своей копии.
//
// Якорь привязки — один из трёх ярусов иерархии (cluster ▶ account ▶ project);
// это записано у самого объявления (access_binding_scope.go: «Only the three
// hierarchy tiers can anchor a binding»). Публичный Create приводит проволочный
// `scopeType` к голому ярусу через `ScopeTypeFromDotted` — закрытый набор из трёх,
// — поэтому НИЧЕГО, кроме яруса, до `Validate()` не доходит.
//
// Пообъектный тип (`vpc_network`, `iam_user`) якорем не бывает НИКОГДА: он
// называет ОБЪЕКТ ПОД якорем, и для него существует своя ось — `target` (F8),
// чей вокабуляр судит `ValidTargetType` по ленте материализации. Принимать его
// здесь значит держать вторую, разошедшуюся копию вокабуляра: она ничего не
// сужает, потому что производителя у такого входа нет, и молча расширит проверку
// в тот день, когда вызывающий появится.
//
// Отрицательная половина ВЫВЕДЕНА из живой ленты, а не выписана: перечисленный
// список закрыл бы сегодняшние имена и пропустил бы имена следующего домена.

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// bareModelSpelling — голое написание модели для точечного имени каталога
// («vpc.routeTable» → «vpc_route_table»). Так механически производятся якорные
// написания пообъектных типов — то, чем вокабуляр якоря был засорён.
func bareModelSpelling(dotted string) (string, bool) {
	i := strings.IndexByte(dotted, '.')
	if i <= 0 || i == len(dotted)-1 {
		return "", false
	}
	return dotted[:i] + "_" + snakeResource(dotted[i+1:]), true
}

// TestScopeAnchorVocabularyIsTheThreeTiers — положительная половина.
func TestScopeAnchorVocabularyIsTheThreeTiers(t *testing.T) {
	tiers := []string{"cluster", "account", "project"}
	for _, tier := range tiers {
		require.NoErrorf(t, ResourceType(tier).Validate(),
			"ResourceType(%q).Validate() отвергает ярус иерархии — вокабуляр якоря повреждён", tier)
	}

	// Обратная сторона той же оси: каждый ярус обязан иметь проволочную форму, и
	// она обязана вернуться тем же голым ярусом. Без этого «принимается» и
	// «доезжает» неотличимы.
	for _, tier := range tiers {
		back, ok := ScopeTypeFromDotted(ScopeTypeToDotted(tier))
		require.Truef(t, ok, "ярус %q не имеет проволочной формы", tier)
		require.Equalf(t, tier, back, "ярус %q не переживает круг «голый → точечный → голый»", tier)
	}
	t.Logf("перепись: ярусов якоря %d", len(tiers))
}

// TestScopeAnchorVocabularyRefusesPerObjectTypes — отрицательная половина,
// выведенная из живой ленты материализации.
//
// Каждый пообъектный тип, переписанный в якорное написание, обязан быть отвергнут:
// произвести его не может ни один путь записи, а принять — значит объявить
// поверхность, которой нет.
func TestScopeAnchorVocabularyRefusesPerObjectTypes(t *testing.T) {
	feed := AllMaterializableTypes()
	require.NotEmpty(t, feed, "AllMaterializableTypes() пуста — гейт не утверждал бы ничего")

	tier := map[string]bool{"cluster": true, "account": true, "project": true}

	var candidates, accepted []string
	for _, dotted := range feed {
		bare, ok := bareModelSpelling(dotted)
		require.Truef(t, ok, "негодное точечное имя %q в ленте материализации", dotted)
		if tier[bare] {
			continue // ярус: у него своя, законная запись
		}
		candidates = append(candidates, bare)
		if ResourceType(bare).Validate() == nil {
			accepted = append(accepted, bare)
		}
	}
	require.NotEmptyf(t, candidates,
		"из %d живых типов не выведено ни одного якорного написания — у гейта не осталось предмета", len(feed))
	t.Logf("перепись: типов ленты %d, выведено якорных написаний %d, принято %d",
		len(feed), len(candidates), len(accepted))

	require.Emptyf(t, accepted,
		"%d пообъектных типов принимаются как ЯКОРЬ области, хотя якорем бывает только ярус иерархии; "+
			"проверка выглядит сужением, ничего не сужая: %v", len(accepted), accepted)
}

// TestScopeAnchorVocabularyRefusesLegacyWordForms — написания, до которых
// переписывание ленты не достаёт: они отличаются СЛОВОМ, а не регистром.
func TestScopeAnchorVocabularyRefusesLegacyWordForms(t *testing.T) {
	legacy := []string{
		"iam_account", "iam_project", // ярус, записанный с приставкой модуля
		"loadbalancer_nlb", "loadbalancer_target_group", // имя домена, которого модель не знает
		"*",               // подстановочный якорь: производителя нет
		"cloud", "folder", // чужие имена ярусов
		"", "Account", "vpc.network",
	}
	for _, bad := range legacy {
		require.Errorf(t, ResourceType(bad).Validate(),
			"ResourceType(%q).Validate() принимает написание, которого не производит ни один путь записи", bad)
	}
	t.Logf("перепись: осмотрено легаси-написаний %d", len(legacy))
}
