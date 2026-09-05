// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package publicauthzcensus_test

// exempt_test.go — гейт: ОСВОБОЖДЕНИЕ от пообъектного вопроса обязано быть
// ДОКАЗАННЫМ, а не объявленным.
//
// # Предмет
//
// Соседний гейт (census_test.go) считает освобождённый контрактом RPC нормой и
// печатает его перечень. Этого достаточно, пока iam стоит за нашим краем: там
// освобождение означает «край не задаёт единичного вопроса», а не «вопроса не
// задаёт никто».
//
// Вынесенный в чужое облако iam края не имеет BY CONSTRUCTION, и тогда
// освобождённые RPC — вся оставшаяся поверхность, к которой пообъектного
// вопроса не задаётся ВООБЩЕ. «Освобождён» превращается из записанного решения
// в открытую дверь с объяснением, и отличить одно от другого можно ровно одним
// способом: спросить, есть ли на пути обслуживания РЕШАТЕЛЬ, и назвать его.
//
// # Что здесь утверждается
//
// У КАЖДОГО освобождённого публичного RPC свидетельство переписи называет
// решателя, найденного на его пути обслуживания, а не факт освобождения.

import (
	"sort"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho-iam/internal/publicauthzcensus"
)

func TestEveryExemptPublicRPCNamesItsDecider(t *testing.T) {
	root := repoRoot(t)
	c, err := publicauthzcensus.Collect(root)
	if err != nil {
		t.Fatalf("перепись не состоялась: %v", err)
	}
	t.Log(c.Summary())

	// Пустой обход — «беспредметно», а не «чисто».
	if c.Inspected == 0 {
		t.Fatal("обход пуст: публичных RPC осмотрено 0 — вердикт беспредметен")
	}
	if c.GoFiles == 0 {
		t.Fatal("обход пуст: файлов Go разобрано 0 — вердикт беспредметен")
	}

	var (
		exempt  int
		unnamed []string
	)
	for _, v := range c.Verdicts {
		if v.Category != publicauthzcensus.CategoryExempt {
			continue
		}
		exempt++
		if !strings.Contains(v.Evidence, "решатель") {
			unnamed = append(unnamed, v.RPC.String()+" — свидетельство: "+v.Evidence)
		}
	}
	t.Logf("освобождённых публичных RPC осмотрено %d · решатель назван у %d · не назван у %d",
		exempt, exempt-len(unnamed), len(unnamed))

	sort.Strings(unnamed)
	if len(unnamed) > 0 {
		t.Errorf("освобождение ОБЪЯВЛЕНО, но не доказано у %d RPC из %d освобождённых.\n"+
			"На вынесенном iam это открытая дверь: пообъектного вопроса не задаёт ни край "+
			"(его нет), ни дверь (RPC освобождён), ни путь обслуживания (решатель не найден):\n  %s",
			len(unnamed), exempt, strings.Join(unnamed, "\n  "))
	}
}
