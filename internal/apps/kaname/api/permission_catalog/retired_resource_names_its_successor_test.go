// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// retired_resource_names_its_successor_test.go — снятый ресурс НАЗЫВАЕТ
// преемника, и узнаёт его арендатор ОДНИМ чтением витрины (kacho#1814,
// приёмка `docs/engineering/acceptance/retired-resource-names-its-successor.md`,
// сценарии IAM-SUC-01 · -02 · -03 · -05a).
//
// # Предмет
//
// Преемник снятого ресурса существовал ДАННЫМИ (колонка `superseded_by`,
// посеянная миграцией, проверяемая гейтом посева) и не доезжал до арендатора НИ
// ОДНИМ путём чтения: витрина читала только живую половину, а контракт о снятии
// молчал вовсе. Клиент, чьё правило отвергнуто на `compute.disk`, узнать
// `storage.volumes` мог только чтением исходников — догадка по имени неверна
// ровно там, где нужна: имена намеренно не единообразны (`compute.instance`
// единственного числа, `storage.volumes` множественного).
//
// # Почему утверждается ОТВЕТ, а не вызов
//
// Пробы здесь идут через хендлер и судят ТЕЛО ответа — то, что увидит клиент.
// Утверждение «use-case спросил снятую половину» зеленело бы на проекции,
// которая спросила и выбросила: предмет задачи в том, что доезжает, а не в том,
// что читается.
package permission_catalog

import (
	"testing"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/catalog"
)

// retiredHalves — каталог, у которого ОБЕ половины непусты.
//
// Живая половина здесь — положительный контроль, и без неё утверждения о снятой
// зеленели бы на витрине, отдающей всё подряд либо не отдающей ничего. Пара
// `storage.volumes` живая НАМЕРЕННО: она преемник снятой `compute.disk`, и
// `IAM-SUC-03` требует найти её в перечне грантуемого ТОГО ЖЕ ответа.
//
// Снятых строк ТРИ, и третья (`compute.snapshot`) преемника НЕ несёт: без неё
// «преемник пуст» было бы непредставимо, и проекция, молча выбрасывающая снятое
// без преемника, прошла бы незамеченной (`IAM-SUC-05a`).
//
// Порядок строк здесь НАМЕРЕННО обратный ожидаемому: витрина обязана
// упорядочить их сама, по точечному имени. Подай я их уже отсортированными —
// утверждение о порядке зеленело бы на реализации, которая порядка не задаёт
// вовсе.
func retiredHalves() catalog.Halves {
	return catalog.Halves{
		Live: catalog.Rows{
			Modules: []string{"compute", "storage"},
			Resources: []catalog.ResourceRow{
				{Module: "compute", Resource: "instance", ObjectType: "compute_instance"},
				{Module: "storage", Resource: "volumes", ObjectType: "storage_volume"},
			},
			Verbs: []catalog.VerbRow{
				{Module: "compute", Resource: "instance", Verb: "get", PerObject: true},
				{Module: "storage", Resource: "volumes", Verb: "get", PerObject: true},
			},
		},
		Retired: catalog.Rows{
			Modules: nil,
			Resources: []catalog.ResourceRow{
				{Module: "compute", Resource: "snapshot", ObjectType: "compute_snapshot"},
				{Module: "compute", Resource: "disk", ObjectType: "compute_disk",
					SupersededBy: "storage.volumes"},
			},
			// Глаголы снятых строк каталог несёт, а витрина их не показывает:
			// набор снятого типа спрашивать не у кого. Фикстура их даёт затем,
			// чтобы «глаголов у записи нет» не выполнялось тривиально.
			Verbs: []catalog.VerbRow{
				{Module: "compute", Resource: "disk", Verb: "get", PerObject: true},
			},
		},
	}
}

// TestIAMSUC02_RetiredResourceIsNamedWithItsSuccessor — `IAM-SUC-02`.
//
// Снятый ресурс назван СВОИМ перечнем, несёт преемника и стоит в
// детерминированном порядке.
func TestIAMSUC02_RetiredResourceIsNamedWithItsSuccessor(t *testing.T) {
	resp := catalogOverHalves(t, retiredHalves())

	got := resp.GetRetiredResources()
	if len(got) != 2 {
		t.Fatalf("витрина назвала %d снятых ресурсов, в каталоге их 2: %v",
			len(got), dottedRetired(got))
	}
	// Порядок — по точечному имени снятого, а не по порядку чтения: фикстура
	// подаёт строки в обратном порядке.
	if got[0].GetResource() != "compute.disk" || got[1].GetResource() != "compute.snapshot" {
		t.Errorf("порядок перечня снятого не детерминирован: %v — ожидался по точечному имени",
			dottedRetired(got))
	}
	if s := got[0].GetSupersededBy(); s != "storage.volumes" {
		t.Errorf("преемник compute.disk на проводе %q, в строке каталога storage.volumes — "+
			"значение существует данными и до арендатора не доезжает", s)
	}
}

// TestIAMSUC05a_RetiredWithoutSuccessorIsNamedAndPromisesNothing — `IAM-SUC-05a`.
//
// Снятая строка БЕЗ преемника названа, а поле преемника пусто. Пустое означает
// «преемник не назван», и отличает это клиент по САМОМУ полю, а не по длине
// перечня: выброси мы такую строку — от клиента скрылся бы сам факт снятия.
func TestIAMSUC05a_RetiredWithoutSuccessorIsNamedAndPromisesNothing(t *testing.T) {
	resp := catalogOverHalves(t, retiredHalves())

	var found *iamv1.RetiredResource
	for _, r := range resp.GetRetiredResources() {
		if r.GetResource() == "compute.snapshot" {
			found = r
		}
	}
	if found == nil {
		t.Fatalf("снятый БЕЗ преемника не назван вовсе: %v — от клиента скрыт сам факт снятия",
			dottedRetired(resp.GetRetiredResources()))
	}
	if s := found.GetSupersededBy(); s != "" {
		t.Errorf("у снятого без преемника поле преемника %q — витрина обещает шаг, "+
			"которого строка каталога не называла", s)
	}
}

// TestIAMSUC01_RetiredIsNotOfferedAsGrantable — `IAM-SUC-01`, положительный
// контроль посаженного решения `#1976`.
//
// Перечень ГРАНТУЕМОГО снятого не называет — и не начинает называть оттого, что
// снятое поехало своим полем. Без этого контроля `IAM-SUC-02` зеленел бы на
// реализации, положившей снятое в `modules[]`, то есть отзывающей чужую посадку.
func TestIAMSUC01_RetiredIsNotOfferedAsGrantable(t *testing.T) {
	resp := catalogOverHalves(t, retiredHalves())

	grantable := dottedGrantable(resp)
	// Положительный контроль: перечень грантуемого НЕПУСТ. Без него утверждение
	// об отсутствии выполнялось бы на пустом ответе.
	if len(grantable) == 0 {
		t.Fatalf("перечень грантуемого пуст — утверждение об отсутствии снятого стало бы вакуумным")
	}
	for _, dotted := range grantable {
		if dotted == "compute.disk" || dotted == "compute.snapshot" {
			t.Errorf("снятый %s попал в перечень ГРАНТУЕМОГО: витрина предлагает выдать то, "+
				"что домен отвергнет, — перечень грантуемого %v", dotted, grantable)
		}
	}
	t.Logf("перепись: грантуемых пар %d, снятых записей %d",
		len(grantable), len(resp.GetRetiredResources()))
}

// TestIAMSUC03_SuccessorIsAliveInTheSameResponse — `IAM-SUC-03`.
//
// Преемник — ЖИВОЙ ключ каталога, и клиент находит его в перечне грантуемого
// ТОГО ЖЕ ответа. Без этого `IAM-SUC-02` был бы исполним преемником,
// указывающим на снятое, — то есть восстанавливал бы шаг, которого нет.
func TestIAMSUC03_SuccessorIsAliveInTheSameResponse(t *testing.T) {
	resp := catalogOverHalves(t, retiredHalves())

	grantable := make(map[string]bool)
	for _, d := range dottedGrantable(resp) {
		grantable[d] = true
	}

	named := 0
	for _, r := range resp.GetRetiredResources() {
		s := r.GetSupersededBy()
		if s == "" {
			continue
		}
		named++
		if !grantable[s] {
			t.Errorf("преемник %s ресурса %s не найден в перечне грантуемого того же ответа — "+
				"клиент отослан к тому, чего платформа не выдаёт", s, r.GetResource())
		}
	}
	// Положительный контроль: хоть один преемник назван. Иначе цикл выше
	// зеленел бы на ответе, где преемников нет ни у кого.
	if named == 0 {
		t.Fatalf("ни один снятый ресурс преемника не назвал — утверждение вакуумно")
	}
	t.Logf("перепись: снятых записей %d, из них с названным преемником %d",
		len(resp.GetRetiredResources()), named)
}

// dottedRetired — точечные имена снятого из ответа, для текстов отказа.
func dottedRetired(rs []*iamv1.RetiredResource) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.GetResource()+"→"+r.GetSupersededBy())
	}
	return out
}

// dottedGrantable — точечные имена перечня ГРАНТУЕМОГО из ответа.
func dottedGrantable(resp *iamv1.ListPermissionCatalogResponse) []string {
	var out []string
	for _, m := range resp.GetModules() {
		for _, r := range m.GetResources() {
			out = append(out, m.GetModule()+"."+r.GetResource())
		}
	}
	return out
}
