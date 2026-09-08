// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package modelrender_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/modelrender"
)

// canonforms_test.go — формы блока, которые НЕСЁТ действующий канон, обязаны быть
// выразимы разделом `resources` и воспроизводимы рендером.
//
// # Почему пробы идут через ЗАГРУЗЧИК, а не собирают структуру в памяти
//
// Форма считается выразимой, когда существует ВХОД МАНИФЕСТА, на котором она
// доезжает до рендера. Структура, собранная в памяти, минует разбор и его отказы,
// поэтому проба, зелёная на ней, ничего не говорит о том, примет ли загрузчик тот
// же документ: ровно так возможность и оказывается объявленной и неисполнимой
// (`api-conventions.md` §«Неисполнимая возможность»).
//
// # Что здесь утверждается — СТРОКИ, а не весь блок
//
// Блок канона обычно требует нескольких форм сразу, поэтому побайтовое равенство
// целого блока утверждается ОДИН раз — переписью достижимости (reach_test.go).
// Здесь каждая проба отвечает за СВОЮ форму и называет ту строку канона, которую
// эта форма производит; рядом стоит положительный контроль — умолчательная форма
// того же места. Без него «строка появилась» было бы неотличимо от «рендер
// печатает что угодно».

// renderFromYAML — загружает манифест и рендерит его ЕДИНСТВЕННЫЙ ресурс.
//
// Отказ загрузчика печатается целиком: он называет поле, правило и координату, и
// это ровно то, что нужно читателю красной пробы.
func renderFromYAML(t *testing.T, doc string) string {
	t.Helper()
	m, err := manifest.Load([]byte(doc))
	if err != nil {
		t.Fatalf("загрузчик отверг вход:\n%v\nвход:\n%s", err, doc)
	}
	if len(m.Resources) != 1 {
		t.Fatalf("ресурсов в манифесте %d, ожидался один", len(m.Resources))
	}
	got, err := modelrender.Render(m.Resources[0])
	if err != nil {
		t.Fatalf("рендер отказал: %v", err)
	}
	return string(got)
}

// mustContainLine требует строку ДОСЛОВНО, вместе с отступом и переводом строки.
func mustContainLine(t *testing.T, block, line string) {
	t.Helper()
	if !strings.Contains(block, line) {
		t.Fatalf("строка не порождена дословно:\n  ожидалось %q\nпорождённый блок:\n%s", line, block)
	}
}

// TestMODMR28APointerWhoseNameDiffersFromItsTypeIsExpressible — имя указателя и
// тип объекта, на который он указывает, суть РАЗНЫЕ строки (#1860).
//
// Замер, из которого проба выведена: `registry_repository` несёт
// `define parent: [registry_registry]` — единственный блок канона, у которого имя
// указателя не равно типу. Пока имя выводилось из типа, эта пара не порождалась
// НИ ПРИ КАКОМ значении ключа, то есть блок был недостижим by construction.
// ЗДЕСЬ ФИКСТУРЫ НАЗЫВАЛИ РЕСУРС `repository` при типе `registry_repository`.
// После размыкания таблицы типов (#2015) это стало НАХОДКОЙ: образ адресует
// `registry_repository` строкой `registry.repositories`, то есть фикстура
// присваивала чужой тип ДРУГОЙ строке, и загрузчик такое отвергает. Имя
// приведено к тому, каким его несёт образ; предмет проб — форма указателя и
// форма отношения действия — не изменился, и изменённый факт ровно один.
func TestMODMR28APointerWhoseNameDiffersFromItsTypeIsExpressible(t *testing.T) {
	block := renderFromYAML(t, `apiVersion: iam/v1
module: registry
resources:
  - name: repositories
    objectType: registry_repository
    parents:
      - {name: parent, type: registry_registry}
    producer: authored
    verbs: [get]
`)
	mustContainLine(t, block, "    define parent: [registry_registry]\n")
	// Каскад берёт ИМЯ указателя, а не его тип: `super_admin from parent`.
	mustContainLine(t, block, "    define super_admin: super_admin from parent\n")
}

// TestMODMR28ThePointerWhoseNameEqualsItsTypeStaysAShortString — положительный
// контроль к пробе выше.
//
// Без него «имя и тип разделены» было бы неотличимо от «раздел принимает что
// угодно»: отрицание, не имеющее пары, зеленеет на любой сломанной форме.
func TestMODMR28ThePointerWhoseNameEqualsItsTypeStaysAShortString(t *testing.T) {
	block := renderFromYAML(t, `apiVersion: iam/v1
module: vpc
resources:
  - name: gateway
    objectType: vpc_gateway
    parents: [project]
    producer: derived
    verbs: [get, list, update, delete]
`)
	mustContainLine(t, block, "    define project: [project]\n")
	mustContainLine(t, block, "    define super_admin: super_admin from project\n")
}

// TestMODMR29ASecondScopePointerIsExpressible — указателей у блока бывает
// БОЛЬШЕ ОДНОГО (#1858).
//
// Замер по канону: `project` несёт `define cluster: [cluster]` сверх `account`,
// `iam_access_binding` — `account` и `cluster` сверх `project`. Пока указатель
// был один, эти строки не порождались ничем.
func TestMODMR29ASecondScopePointerIsExpressible(t *testing.T) {
	block := renderFromYAML(t, `apiVersion: iam/v1
module: iam
resources:
  - name: accessBinding
    objectType: iam_access_binding
    parents: [project, account, cluster]
    producer: derived
    verbs: [get, list, update, delete]
`)
	for _, line := range []string{
		"    define project: [project]\n",
		"    define account: [account]\n",
		"    define cluster: [cluster]\n",
	} {
		mustContainLine(t, block, line)
	}
	// Порядок указателей — порядок манифеста, а не сортировка: канон ставит
	// `project` первым, и перестановка дала бы другой блок.
	first := strings.Index(block, "define project:")
	second := strings.Index(block, "define account:")
	third := strings.Index(block, "define cluster:")
	if !(first < second && second < third) {
		t.Fatalf("порядок указателей не совпал с порядком манифеста:\n%s", block)
	}
}

// ── Каскад супер-доступа и источники яруса (#1858) ───────────────────────────

// TestMODMR30TheCascadeIsDeclaredByTheManifest — написаний каскада в каноне
// ЧЕТЫРЕ, и рендер знал одно.
//
// Замер по канону: `super_admin from <указатель>` — 19 блоков (это и есть
// умолчание), `any_admin from cluster` — 2, `admin from account` — 4,
// `admin from account or any_admin from cluster` — 1,
// `super_admin from project or admin from account or any_admin from cluster` — 1.
// Итого восемь блоков несут написание, которого рендер произвести не мог.
func TestMODMR30TheCascadeIsDeclaredByTheManifest(t *testing.T) {
	// Одиночный терм, отличный от умолчания: так написан vpc_address_pool.
	block := renderFromYAML(t, `apiVersion: iam/v1
module: vpc
resources:
  - name: addressPool
    objectType: vpc_address_pool
    parents: [cluster]
    producer: authored
    cascade:
      - {relation: any_admin, from: cluster}
    verbs: [get]
`)
	mustContainLine(t, block, "    define super_admin: any_admin from cluster\n")

	// Дизъюнкция термов: так написан iam_access_binding.
	block = renderFromYAML(t, `apiVersion: iam/v1
module: iam
resources:
  - name: accessBinding
    objectType: iam_access_binding
    parents: [project, account, cluster]
    producer: derived
    cascade:
      - {relation: super_admin, from: project}
      - {relation: admin, from: account}
      - {relation: any_admin, from: cluster}
    verbs: [get]
`)
	mustContainLine(t, block,
		"    define super_admin: super_admin from project or admin from account or any_admin from cluster\n")
}

// TestMODMR30TheDefaultCascadeStaysUnwritten — положительный контроль: 19 блоков
// канона из 27 несут умолчание, и оно остаётся неписаным.
func TestMODMR30TheDefaultCascadeStaysUnwritten(t *testing.T) {
	block := renderFromYAML(t, `apiVersion: iam/v1
module: vpc
resources:
  - name: gateway
    objectType: vpc_gateway
    parents: [project]
    producer: derived
    verbs: [get, list, update, delete]
`)
	mustContainLine(t, block, "    define super_admin: super_admin from project\n")
}

// TestMODMR31ATierMayDeriveFromMoreThanTheChain — ярус выводится не только от
// предыдущего.
//
// Замер: `account` несёт `define admin: [...] or owner or super_admin`,
// `iam_user` — `define viewer: [...] or subject or editor`. Цепочка ярусов у
// рендера была одна, и оба написания она не давала ни при каком входе.
func TestMODMR31ATierMayDeriveFromMoreThanTheChain(t *testing.T) {
	block := renderFromYAML(t, `apiVersion: iam/v1
module: iam
resources:
  - name: account
    objectType: account
    parents: [cluster]
    producer: derived
    cascade:
      - {relation: any_admin, from: cluster}
    relations:
      - {name: owner, definition: "[user]"}
    tiers:
      - {name: admin, from: [owner, super_admin]}
      - editor
      - viewer
    verbs: [get]
`)
	mustContainLine(t, block,
		"    define admin: [user, service_account, group#member] or owner or super_admin\n")
	// Цепочка после нестандартного яруса продолжается от него же.
	mustContainLine(t, block,
		"    define editor: [user, service_account, group#member] or admin\n")
}

// TestMODMR31TheDefaultTierChainStaysAShortString — положительный контроль:
// ярус, выводимый от предыдущего, пишется именем и ничем больше.
func TestMODMR31TheDefaultTierChainStaysAShortString(t *testing.T) {
	block := renderFromYAML(t, `apiVersion: iam/v1
module: vpc
resources:
  - name: addressPool
    objectType: vpc_address_pool
    parents: [cluster]
    producer: authored
    cascade:
      - {relation: any_admin, from: cluster}
    subjects: [user, service_account]
    tiers: [admin, viewer]
    verbs: [get]
`)
	mustContainLine(t, block, "    define admin: [user, service_account] or super_admin\n")
	mustContainLine(t, block, "    define viewer: [user, service_account] or admin\n")
}

// ── Отношение действия сверх умолчания (#1846) ───────────────────────────────

// TestMODMR33AVerbRelationMayCarryItsOwnSubjectsAndSources — `v_*`, отличный от
// умолчания, выразим манифестом.
//
// Замер по канону: `registry_repository` несёт
// `define v_get: [user:*, user, service_account, group#member] or owner or super_admin`
// — анонимное чтение публичного репозитория, — и остальные его действия выводятся
// ещё и от `owner`. Умолчательная форма этого не давала, а объявить `v_get`
// авторским отношением загрузчик не позволяет (имя порождается глаголом того же
// ресурса): возможность была объявлена и неисполнима ни одним входом.
func TestMODMR33AVerbRelationMayCarryItsOwnSubjectsAndSources(t *testing.T) {
	block := renderFromYAML(t, `apiVersion: iam/v1
module: registry
resources:
  - name: repositories
    objectType: registry_repository
    parents:
      - {name: parent, type: registry_registry}
    producer: authored
    relations:
      - {name: owner, definition: "[user, service_account]"}
    verbs:
      - {name: get, subjects: ["user:*", user, service_account, "group#member"], from: [owner, super_admin]}
      - {name: list, from: [owner, super_admin]}
      - {name: update, from: [owner, super_admin]}
      - {name: delete, from: [owner, super_admin]}
`)
	mustContainLine(t, block,
		"    define v_get: [user:*, user, service_account, group#member] or owner or super_admin\n")
	mustContainLine(t, block,
		"    define v_list: [user, service_account, group#member] or owner or super_admin\n")
}

// TestMODMR33AVerbMayDeriveFromAnotherVerb — источник действия бывает ДРУГИМ
// действием, а не только супер-доступом.
//
// Замер: `nlb_target_group` несёт
// `define v_addtargets: [user, service_account, group#member] or v_update` —
// надмножество права правки, объявленное односторонне. Форма та же, что у пробы
// выше, поэтому отдельного ключа она не заводит (сам блок целиком — предмет
// #1091).
func TestMODMR33AVerbMayDeriveFromAnotherVerb(t *testing.T) {
	block := renderFromYAML(t, `apiVersion: iam/v1
module: loadbalancer
resources:
  - name: targetGroups
    objectType: nlb_target_group
    parents: [project]
    producer: derived
    verbs:
      - get
      - list
      - update
      - delete
      - {name: addTargets, class: addtargets, from: [v_update]}
      - {name: removeTargets, class: removetargets, from: [v_update]}
`)
	mustContainLine(t, block,
		"    define v_addtargets: [user, service_account, group#member] or v_update\n")
	mustContainLine(t, block,
		"    define v_removetargets: [user, service_account, group#member] or v_update\n")
}

// TestMODMR33TheDefaultVerbRelationStaysUnwritten — положительный контроль:
// умолчательная форма остаётся неписаной, и субъекты действия НЕ сужаются
// ключом `subjects` ресурса.
//
// Замер: у `vpc_address_pool` ярусы несут [user, service_account], а его же
// `v_get` — полный набор с `group#member`. Сузив заодно действия, рендер отнял
// бы живое право у групп — молча, при действующей на вид привязке.
func TestMODMR33TheDefaultVerbRelationStaysUnwritten(t *testing.T) {
	block := renderFromYAML(t, `apiVersion: iam/v1
module: vpc
resources:
  - name: addressPool
    objectType: vpc_address_pool
    parents: [cluster]
    producer: authored
    cascade:
      - {relation: any_admin, from: cluster}
    subjects: [user, service_account]
    tiers: [admin, viewer]
    verbs: [get, list, update, delete]
`)
	mustContainLine(t, block, "    define admin: [user, service_account] or super_admin\n")
	mustContainLine(t, block,
		"    define v_get: [user, service_account, group#member] or super_admin\n")
}

// ── Место авторского отношения в блоке (#1862) ───────────────────────────────

// TestMODMR34ThePlaceOfAnAuthoredRelationComesFromTheManifest — раскладок в
// каноне ТРИ, и постоянная рендера знала одну.
//
// Замер по канону: авторское отношение стоит ПЕРЕД ярусами у пяти блоков
// (`owner` у account, registry_registry и registry_repository, `subject` у
// iam_user, `member` у iam_group), МЕЖДУ ярусами и действиями у одного
// (`ssh`/`console` у compute_instance — это и есть постоянная рендера) и ПОСЛЕ
// действий у четырёх (`member_remover` у account, шесть отношений распоряжения
// у iam_user, `realization_writer` у compute_instance, `announce_writer` у
// nlb_network_load_balancer).
//
// Пока место задавала постоянная, побайтовая сверка объявляла расхождением то, о
// чём никто не решал: канон несёт все три раскладки законно.
func TestMODMR34ThePlaceOfAnAuthoredRelationComesFromTheManifest(t *testing.T) {
	block := renderFromYAML(t, `apiVersion: iam/v1
module: iam
resources:
  - name: account
    objectType: account
    parents: [cluster]
    producer: derived
    cascade:
      - {relation: any_admin, from: cluster}
    relations:
      - {name: owner, definition: "[user]", position: beforeTiers}
      - {name: member_remover, definition: "editor", position: afterVerbs}
    tiers:
      - {name: admin, from: [owner, super_admin]}
      - editor
      - viewer
    verbs:
      - {name: get, from: [owner, super_admin]}
      - {name: list, from: [owner, super_admin]}
`)
	owner := strings.Index(block, "define owner:")
	admin := strings.Index(block, "define admin:")
	verb := strings.Index(block, "define v_get:")
	remover := strings.Index(block, "define member_remover:")
	if owner < 0 || admin < 0 || verb < 0 || remover < 0 {
		t.Fatalf("не все отношения порождены:\n%s", block)
	}
	if !(owner < admin) {
		t.Fatalf("отношение с якорем beforeTiers стоит не перед ярусами:\n%s", block)
	}
	if !(verb < remover) {
		t.Fatalf("отношение с якорем afterVerbs стоит не после действий:\n%s", block)
	}
}

// TestMODMR34TheDefaultPlaceIsBetweenTiersAndVerbs — положительный контроль:
// умолчание остаётся тем же, каким было постоянной, и пишется неявно.
//
// Замер: так стоят `ssh` и `console` у compute_instance.
func TestMODMR34TheDefaultPlaceIsBetweenTiersAndVerbs(t *testing.T) {
	block := renderFromYAML(t, `apiVersion: iam/v1
module: compute
resources:
  - name: instance
    objectType: compute_instance
    parents: [project]
    producer: derived
    relations:
      - {name: ssh, definition: "[user with mfa_fresh, service_account] or admin"}
    tiers: [admin, editor, viewer]
    verbs: [get, list, update, delete]
`)
	viewer := strings.Index(block, "define viewer:")
	ssh := strings.Index(block, "define ssh:")
	verb := strings.Index(block, "define v_get:")
	if !(viewer < ssh && ssh < verb) {
		t.Fatalf("умолчательное место авторского отношения сдвинулось:\n%s", block)
	}
}

// ── Проза блока: примечание с ЯКОРЕМ (#1845) ─────────────────────────────────

// TestMODMR35ProseIsAnchoredToTheRelationItPrecedes — внутриблочная проза стоит
// там, где её ставит канон, а не в одном месте на весь блок.
//
// Замер по канону: примечаний в модульных блоках 15 штук на 634 строки, и
// якорями им служат ДЕВЯТЬ разных отношений — `project`, `cluster`, `super_admin`,
// `editor`, `viewer`, `v_get`, `v_addtargets`, `member_remover`,
// `realization_writer` и другие авторские. Пока `doc` был одним текстом без
// координаты, рендер обязан был выбрать ОДНУ позицию, и всякий блок с иным
// расположением прозы был недостижим by construction.
//
// Примечания несут самоистекающие маркеры и ссылки на задачи: потерять их
// перегенерацией значило бы снять условие, о котором никто не решал.
func TestMODMR35ProseIsAnchoredToTheRelationItPrecedes(t *testing.T) {
	block := renderFromYAML(t, `apiVersion: iam/v1
module: vpc
resources:
  - name: subnet
    objectType: vpc_subnet
    parents: [project]
    producer: derived
    notes:
      - before: project
        text: |
          # примечание у указателя
      - before: v_get
        text: |
          # первая строка разбора
          #
          # третья строка, со ссылкой #1089
    verbs: [get, list, update, delete]
`)
	mustContainLine(t, block, "    # примечание у указателя\n    define project: [project]\n")
	mustContainLine(t, block, "    # первая строка разбора\n    #\n"+
		"    # третья строка, со ссылкой #1089\n    define v_get: ")

	// Знак комментария принадлежит ТЕКСТУ: рендер воспроизводит строку дословно
	// и своего правила оформления не имеет — иначе оно жило бы в двух местах.
	if strings.Contains(block, "# # ") {
		t.Fatalf("рендер добавил свой знак комментария поверх авторского:\n%s", block)
	}
}

// TestMODMR35ABlockWithoutProseCarriesNoComment — положительный контроль:
// отсутствие примечаний не порождает ни одной строки комментария.
func TestMODMR35ABlockWithoutProseCarriesNoComment(t *testing.T) {
	block := renderFromYAML(t, `apiVersion: iam/v1
module: vpc
resources:
  - name: gateway
    objectType: vpc_gateway
    parents: [project]
    producer: derived
    verbs: [get, list, update, delete]
`)
	// Ищется ЗНАК КОММЕНТАРИЯ в начале строки, а не символ решётки где угодно:
	// он законно стоит внутри субъекта `group#member`, и наивная проверка
	// краснела бы на каждом блоке дерева.
	for _, line := range strings.Split(block, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			t.Fatalf("блок без примечаний несёт комментарий %q:\n%s", line, block)
		}
	}
}
