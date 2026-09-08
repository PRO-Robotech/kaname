// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

// provider_compensation_retention_premise_injection_test.go — доказательство,
// что гейт предпосылки СПОСОБЕН упасть и способен смолчать (#2069).
//
// Инъекция подаёт синтетический корпус в ЧИСТЫЙ разбор (`redriveSitesOfTree`) и
// в чистый распознаватель (`namesCompensationQueue`): на настоящем дереве ни
// того, ни другого не показать, не сломав его.
//
// Обе стороны по каждой оси, и мир каждого случая отличается от близнеца ОДНИМ
// названным фактом — иначе неизвестно, что дало красное.
//
// # Осей ТРИ, и третья — про форму записи предмета
//
// Ту же таблицу код называет ДВУМЯ законными формами: литералом и именем
// константы её единственного объявления. Форма, о которой распознаватель не
// знает, даёт не красное и не зелёное, а молчание, — поэтому обе утверждаются
// порознь, а не «одной за обе».

import "testing"

// redriveOverCompensationLiteral — оживитель над стерегомой очередью, таблица
// названа ЛИТЕРАЛОМ.
const redriveOverCompensationLiteral = `package fixture

import "x/reconciler"

func wire(pool any) {
	rc, _ := reconciler.NewRedriveOnly(pool, reconciler.Config{
		Table:           "kaname.provider_compensation_outbox",
		PartitionColumn: "resource_id",
	})
	_ = rc
}
`

// redriveOverCompensationConst — тот же мир, отличающийся ОДНИМ фактом: та же
// таблица названа ИМЕНЕМ КОНСТАНТЫ. Именно этой формой её называет прод-код.
const redriveOverCompensationConst = `package fixture

import "x/reconciler"

func wire(pool any) {
	rc, _ := reconciler.NewRedriveOnly(pool, reconciler.Config{
		Table:           clients.ProviderCompensationTable,
		PartitionColumn: "resource_id",
	})
	_ = rc
}
`

// redriveOverNeighbourQueue — ЗАКОННЫЙ БЛИЗНЕЦ: оживитель над соседней
// очередью. Отличается от обоих выше ровно названной таблицей и обязан МОЛЧАТЬ.
const redriveOverNeighbourQueue = `package fixture

import "x/reconciler"

func wire(pool any) {
	rc, _ := reconciler.NewRedriveOnly(pool, reconciler.Config{
		Table:           clients.InviteMailTable,
		PartitionColumn: "resource_id",
	})
	_ = rc
}
`

// TestCompensationPremiseGateSeesBothFormsOfTheSubject — распознаватель узнаёт
// стерегомую очередь в ОБЕИХ законных формах и не путает её с соседней.
func TestCompensationPremiseGateSeesBothFormsOfTheSubject(t *testing.T) {
	cases := []struct {
		name   string
		body   string
		finds  bool
		reason string
	}{
		{
			name:   "литерал — находка",
			body:   redriveOverCompensationLiteral,
			finds:  true,
			reason: "оживитель над стерегомой таблицей, названной литералом",
		},
		{
			name:   "константа — находка",
			body:   redriveOverCompensationConst,
			finds:  true,
			reason: "та же таблица, названная именем константы: форма, которой её называет прод-код",
		},
		{
			name:   "соседняя очередь — молчание",
			body:   redriveOverNeighbourQueue,
			finds:  false,
			reason: "законный близнец: у очереди писем свой ключ партиции и общий уборщик платформы",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// Свой каталог на случай: миры кейсов не смешиваются, и «что дало
			// красное» остаётся однозначным.
			sub := t.TempDir()
			path := writeGoFixture(t, sub, "wiring.go", c.body)

			sites, read, err := redriveSitesOfTree(sub, []string{path})
			if err != nil {
				t.Fatalf("разбор фикстуры: %v", err)
			}
			if read != 1 {
				t.Fatalf("прочитано файлов %d, ожидался 1 — фикстура не дошла до разбора", read)
			}
			if len(sites) != 1 {
				t.Fatalf("мест построения оживителя %d, ожидалось 1: разбор не узнал конструктора, "+
					"и тогда любой вердикт ниже беспредметен", len(sites))
			}

			got := namesCompensationQueue(sites[0].table)
			if got != c.finds {
				t.Fatalf("распознаватель ответил %v, ожидалось %v (%s). Названная таблица: %q",
					got, c.finds, c.reason, sites[0].table)
			}
			t.Logf("перепись: файлов подано 1 · прочитано %d · мест оживителя %d · "+
				"таблица %q · находка %v", read, len(sites), sites[0].table, got)
		})
	}
}
