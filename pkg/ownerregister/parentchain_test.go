// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: Apache-2.0

package ownerregister_test

import (
	"reflect"
	"testing"

	"github.com/PRO-Robotech/kaname/pkg/ownerregister"
)

// parentchain_test.go — цепь предков одной доставки: что она утверждает и чего
// НЕ выдумывает.
//
// Функция существует, потому что четыре потребителя из пяти не называли предков
// вовсе, а принимающая сторона заменяет набор рёбер объекта целиком: неназванная
// цепь стирала уже записанных предков и не ставила новых. Отсюда два требования,
// проверяемых ниже вместе, а не по отдельности:
//
//   - цепь, НАЗВАННУЮ владельцем, функция не трогает (у него иерархия глубже
//     двух уровней, и вывести её из области нельзя);
//   - цепь, владельцем не названную, выводится ИЗ ОБЛАСТИ ЭТОЙ ЖЕ ДОСТАВКИ, а не
//     из чужого состояния и не из часов.

func TestParentChain_ExplicitChainWins(t *testing.T) {
	explicit := []string{"registry_registry:reg-1", "project:prj-1"}

	got := ownerregister.ParentChain(explicit, "prj-9", "acc-9")

	if !reflect.DeepEqual(got, explicit) {
		t.Fatalf("названная владельцем цепь подменена выводом из области:\n"+
			"  получено: %v\n  ожидалось: %v\n"+
			"Промежуточное звено (реестр над репозиторием) из области НЕ выводится: "+
			"область знает только проект и аккаунт, и подмена укоротила бы цепь до "+
			"той, которую объект не имеет.", got, explicit)
	}
}

func TestParentChain_DerivedFromScopeOfTheSameDelivery(t *testing.T) {
	cases := []struct {
		name      string
		projectID string
		accountID string
		want      []string
	}{
		{
			name:      "проект и аккаунт — от ближайшего к дальнему",
			projectID: "prj-1",
			accountID: "acc-1",
			want:      []string{"project:prj-1", "account:acc-1"},
		},
		{
			// Большинство потребителей аккаунт на горячем пути не резолвят.
			// Цепь из одного проекта — полноценная: аккаунт достигается с самого
			// проекта его собственным ребром.
			name:      "только проект",
			projectID: "prj-1",
			want:      []string{"project:prj-1"},
		},
		{
			// Цепь обязана быть НЕПРЕРЫВНОЙ: без проекта аккаунт становится
			// ближайшим предком, а не остаётся на второй ступени. Дыра в цепи
			// остановила бы обход вверх и объявила объект не принадлежащим
			// аккаунту.
			name:      "только аккаунт — он и есть ближайший предок",
			accountID: "acc-1",
			want:      []string{"account:acc-1"},
		},
		{
			// «Предков нет» — законное УТВЕРЖДЕНИЕ владельца, а не пропуск: так
			// выглядит объект корневого уровня. Придумывать ему предка нельзя.
			name: "область не объявлена — предков нет",
			want: nil,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ownerregister.ParentChain(nil, c.projectID, c.accountID)
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("цепь из области (проект %q, аккаунт %q):\n  получено: %v\n  ожидалось: %v",
					c.projectID, c.accountID, got, c.want)
			}
		})
	}
}

// TestParentChain_EmptyExplicitIsNotAnAssertion — пустой срез от владельца
// означает «не назвал», а не «предков нет».
//
// Разница видна ровно здесь: приди пустой срез вместо nil из декодера очереди,
// цепь обязана вывестись из области, а не остаться пустой. Иначе строка,
// поставленная в очередь до появления поля, стирала бы предков на каждом
// повторе — то есть ровно тот дефект, ради которого функция и написана.
func TestParentChain_EmptyExplicitIsNotAnAssertion(t *testing.T) {
	got := ownerregister.ParentChain([]string{}, "prj-1", "")

	want := []string{"project:prj-1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("пустая цепь из очереди принята за утверждение «предков нет»:\n"+
			"  получено: %v\n  ожидалось: %v", got, want)
	}
}
