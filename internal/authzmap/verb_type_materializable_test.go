// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// verb_type_materializable_test.go — гейт против глагольного типа, которого нет
// в проекции системных ролей.
//
// # Предмет
//
// Глагольные отношения (`v_get`/`v_update`/…) объявляются НА ТИПЕ модели прав, а
// материализуются пообъектно реконсайлером — и только для типов, попадающих в
// множество раскрытия подстановки `domain.AllMaterializableTypes()`. Это
// множество boot-backfill `seed.SyncAllSystemRoleSelectors` проецирует в
// `kacho_iam.role_rule_selectors` — индекс, по которому подбор находит привязку,
// материализующую глаголы на свежесозданном объекте.
//
// Тип, объявивший глаголы, но отсутствующий в этом множестве, выглядит полностью
// заведённым: модель его знает, таблицы authzmap его знают, очередь регистраций
// доставляет его кортеж принадлежности, каталог прав отдаёт его RPC. Не работает
// ровно одно — и незаметно: привязка НЕВИДИМА подбору, глаголы на объекте не
// материализуются, и создатель с project-охватом получает отказ **на своём
// только что созданном ресурсе** (`no authorization path to the resource`),
// притом что всё остальное про этот ресурс исправно.
//
// # Почему гейт, а не проба на тип
//
// Класс уже находили и чинили ПОЭКЗЕМПЛЯРНО: #71 (storage volume/snapshot/image)
// закрыт правкой того же множества и пробой ИМЕННО про storage
// (domain/feed_registry_storage_test.go). Проба про storage не могла покраснеть
// на следующем ресурсе — и не покраснела: тот же класс повторился на
// `vpc_cidr_group` (именованный набор префиксов), где отказ выглядел как
// «сломался authz набора префиксов», а очередь регистраций при этом была
// здорова: 2322 доставленных строки, 0 ждущих, записи нового типа на месте.
// Свойство принадлежит ДЕРЕВУ, поэтому его держит перепись по модели, а не
// перечень пообъектных проб.
//
// # Исключение — только машинно различимое и самоистекающее
//
// Тип, у которого НЕТ производителя (никто не регистрирует его объекты у
// владельца прав), материализовать нечего by construction. Такое состояние уже
// имеет в дереве машинную пометку — `# kacho:latent` в блоке типа канонической
// модели, с причиной, — и её содержит гейт производителей
// (internal/repohygiene/modelrelationproducer_test.go), который краснеет, как
// только производитель появляется. Здесь пометка ЧИТАЕТСЯ, а не заводится
// заново, и вторая половина этой пробы требует обратного: помеченный спящим тип,
// который ВСЁ ЖЕ попал в множество материализации, — находка. Так послабление
// не может пережить свой предмет: появился производитель ⇒ соседний гейт требует
// снять пометку ⇒ снятая пометка немедленно вводит тип под требование этого.
package authzmap_test

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho-iam/internal/authzmap"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
)

// latentTypeMarker — машинно различимая пометка спящего состояния в блоке типа
// канонической модели. Значение и написание принадлежат гейту производителей
// (internal/repohygiene, const latentMarker); здесь оно ЧИТАЕТСЯ. Расхождение
// написания невозможно оставить незамеченным: пометка, которую этот гейт не
// узнает, перестаёт быть послаблением, и тип краснеет по основной половине.
const latentTypeMarker = "# kacho:latent"

var reModelTypeHead = regexp.MustCompile(`^type (\w+)`)

// latentModelTypes — типы канонической модели, в чьём блоке стоит пометка
// спящего. Разбор идёт по тем же признакам, что и parseModel (строка `type X` в
// нулевой колонке открывает блок, `condition …` закрывает его), поэтому пометка
// не может «протечь» на соседний тип.
func latentModelTypes(t *testing.T) map[string]string {
	t.Helper()
	data, err := os.ReadFile(canonicalModelPath(t))
	if err != nil {
		t.Fatalf("читаю каноническую модель: %v", err)
	}
	out := map[string]string{}
	var cur string
	for _, line := range strings.Split(string(data), "\n") {
		if m := reModelTypeHead.FindStringSubmatch(line); m != nil {
			cur = m[1]
			continue
		}
		if strings.HasPrefix(line, "condition ") {
			cur = ""
			continue
		}
		if cur == "" {
			continue
		}
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, latentTypeMarker) {
			continue
		}
		if _, seen := out[cur]; !seen {
			reason := strings.TrimSpace(strings.TrimPrefix(trimmed, latentTypeMarker))
			out[cur] = strings.TrimLeft(reason, "—- ")
		}
	}
	return out
}

// dottedByFGAType — обратная таблица «FGA-тип → dotted-ключ каталога». Строится
// из ЭКСПОРТИРОВАННОЙ поверхности (Catalog + ObjectType), а не из литерала:
// литерал был бы третьим написанием того же набора и разошёлся бы молча.
func dottedByFGAType(t *testing.T) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	for _, e := range authzmap.Catalog() {
		fgaType, ok := authzmap.ObjectType(e.Module, e.Resource)
		if !ok {
			t.Fatalf("каталог отдал пару %s.%s, для которой ObjectType не резолвится — "+
				"обратная таблица гейта не может быть построена", e.Module, e.Resource)
		}
		out[fgaType] = append(out[fgaType], e.Module+"."+e.Resource)
	}
	for _, v := range out {
		sort.Strings(v)
	}
	return out
}

// TestEveryVerbBearingTypeIsMaterializable — у КАЖДОГО типа канонической модели,
// объявляющего хотя бы одно `v_*`-отношение, есть запись в множестве
// материализации, из которого boot-backfill строит проекцию системных ролей.
//
// Инъекция проверена в обе стороны: снятие любого типа из labelSelectableTypes
// (domain/feed_registry.go) краснит пробу С ЕГО ИМЕНЕМ; законный близнец той же
// формы — глагольный тип БЕЗ производителя, помеченный `# kacho:latent`
// (`vpc_address_pool`), — молчит.
func TestEveryVerbBearingTypeIsMaterializable(t *testing.T) {
	f := parseModel(t)
	dotted := dottedByFGAType(t)
	latent := latentModelTypes(t)

	materializable := map[string]struct{}{}
	for _, ty := range domain.AllMaterializableTypes() {
		materializable[ty] = struct{}{}
	}

	// Перепись — отдельное утверждение: «ноль находок» обязано быть отличимо от
	// «ноль прочитанного».
	var (
		typesSeen    int
		verbBearing  int
		covered      int
		excused      []string
		missing      []string
		uncatalogued []string
	)
	modelTypes := make([]string, 0, len(f.types))
	for typ := range f.types {
		modelTypes = append(modelTypes, typ)
	}
	sort.Strings(modelTypes)

	for _, typ := range modelTypes {
		typesSeen++
		if !f.hasAnyVerbRelation(typ) {
			continue
		}
		verbBearing++

		keys := dotted[typ]
		if len(keys) == 0 {
			uncatalogued = append(uncatalogued, typ)
			continue
		}
		hit := false
		for _, k := range keys {
			if _, ok := materializable[k]; ok {
				hit = true
				break
			}
		}
		if hit {
			covered++
			continue
		}
		if reason, isLatent := latent[typ]; isLatent {
			excused = append(excused, fmt.Sprintf("%s (%v) — спящий: %s", typ, keys, reason))
			continue
		}
		missing = append(missing, fmt.Sprintf(
			"%s — глаголы модели: %v; dotted-ключи каталога: %v; НИ ОДНОГО в AllMaterializableTypes()",
			typ, f.verbRelationsOfType(typ), keys))
	}

	t.Logf("осмотрено типов модели: %d; глагольных: %d; из них материализуемых: %d; "+
		"извинено пометкой спящего: %d; записей каталога: %d; "+
		"типов в AllMaterializableTypes(): %d",
		typesSeen, verbBearing, covered, len(excused), len(authzmap.Catalog()), len(materializable))
	for _, e := range excused {
		t.Logf("  спящий, извинён: %s", e)
	}

	// Положительный контроль: у гейта есть вход. Молчание при нулевом входе
	// означало бы «ничего не прочитано», а не «всё в порядке».
	if typesSeen == 0 || verbBearing == 0 {
		t.Fatalf("у гейта нет входа: типов модели %d, глагольных %d. Либо разбор модели "+
			"перестал совпадать с её синтаксисом, либо канонический файл подменён", typesSeen, verbBearing)
	}
	if len(materializable) == 0 {
		t.Fatal("AllMaterializableTypes() пусто — сравнивать не с чем; проверка выродилась бы " +
			"в тождественно-истинную")
	}
	if covered == 0 {
		t.Fatal("НИ ОДИН глагольный тип не материализуем — это не находка про один ресурс, " +
			"а обрыв связи между моделью и множеством материализации")
	}

	if len(uncatalogued) > 0 {
		sort.Strings(uncatalogued)
		t.Fatalf("глагольный тип модели вне каталога authzmap (%d): %s\n\n"+
			"Такой тип нельзя даже спросить про материализацию: dotted-ключа у него нет. "+
			"Это предмет гейта дрейфа (R-2), здесь он назван, чтобы отсутствие ключа не "+
			"читалось как отсутствие находки.", len(uncatalogued), strings.Join(uncatalogued, ", "))
	}

	if len(missing) > 0 {
		sort.Strings(missing)
		t.Fatalf("глагольный тип НЕ попадает в проекцию системных ролей (%d):\n  %s\n\n"+
			"Следствие ровно одно и оно наблюдается у арендатора: привязка невидима подбору "+
			"(SelectorBindingsMatchingObject), реконсайлер не материализует `v_*` на свежем "+
			"объекте, и создатель с project-охватом получает отказ НА СВОЁМ ресурсе "+
			"(`no authorization path to the resource`) — при исправной очереди регистраций и "+
			"верно объявленном типе модели.\n\n"+
			"Исход один из двух, третьего нет:\n"+
			"  · внести dotted-ключ в labelSelectableTypes (services/iam/internal/domain/"+
			"feed_registry.go) — если ресурс зеркалится у владельца прав (RegisterResource) "+
			"и несёт собственные labels; либо в materializableTypes отдельно, если labels "+
			"у него нет by construction (образец — registry.repositories);\n"+
			"  · поставить `%s — <причина>` над структурным отношением типа в канонической "+
			"модели, если производителя у него ещё нет. Пометка истекает сама: гейт "+
			"производителей потребует снять её в тот момент, когда производитель появится.",
			len(missing), strings.Join(missing, "\n  "), latentTypeMarker)
	}
}

// TestLatentTypeIsNotAlsoMaterializable — зеркальная половина: пометка спящего,
// которой больше нечего извинять, — находка.
//
// Без неё послабление переживает свой предмет: тип получил производителя и вошёл
// в множество материализации, а пометка осталась и молча разрешает следующему
// автору вынуть его обратно — уже без красного.
func TestLatentTypeIsNotAlsoMaterializable(t *testing.T) {
	f := parseModel(t)
	dotted := dottedByFGAType(t)
	latent := latentModelTypes(t)

	materializable := map[string]struct{}{}
	for _, ty := range domain.AllMaterializableTypes() {
		materializable[ty] = struct{}{}
	}

	var stale []string
	checked := 0
	for typ := range latent {
		if !f.hasAnyVerbRelation(typ) {
			continue
		}
		checked++
		for _, k := range dotted[typ] {
			if _, ok := materializable[k]; ok {
				stale = append(stale, fmt.Sprintf("%s — помечен спящим, но %s есть в AllMaterializableTypes()", typ, k))
			}
		}
	}

	t.Logf("пометок спящего в модели: %d; из них на глагольных типах: %d; просроченных: %d",
		len(latent), checked, len(stale))

	if len(stale) > 0 {
		sort.Strings(stale)
		t.Fatalf("пометка спящего пережила свой предмет (%d):\n  %s\n\n"+
			"Тип материализуется, значит производитель у него есть. Снять пометку.",
			len(stale), strings.Join(stale, "\n  "))
	}
}
