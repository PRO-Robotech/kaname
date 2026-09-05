// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package permission_catalog — PermissionCatalogService.ListPermissionCatalog
// (RBAC rules-model 2026).
//
// The backend-driven grantable role-rule catalog: a PUBLIC sync read returning
// the grantable-token taxonomy (modules → resources + per-type editor flags),
// the common verb set, and the wildcard policy.
//
// ─────────────────────────────────────────────────────────────────────────────
// ВИТРИНА ОТВЕЧАЕТ ЖИВЫМИ СТРОКАМИ КАТАЛОГА (#1976)
//
// Здесь стояло «проекция ИЗ КОДА: `authzmap.Catalog()` — закрытая таблица
// objectTypes, — базы НЕТ, миграции НЕТ, каталог неизменяем в рантайме». Каждое
// из четырёх утверждений было верно в день записи и перестало им быть: каталог
// живёт СТРОКАМИ (`kacho_iam.catalog_resource` / `catalog_verb`), заводит их
// применение манифеста модуля, а снятие (#1861) делает строку неживой.
//
// Расхождение перечня сборки с живыми строками наблюдаемо арендатору В ОБЕ
// стороны, и обе половины тихие:
//
//	СНЯТИЕ    строка снята, перечень сборки её называет → витрина предлагает
//	          тип, на который выдача отвергается ключом (`role_rule_ref_res_fk` /
//	          `role_verb_type_fk` → `catalog_resource(..., live)`). Доступ не
//	          расширяется — отказ fail-closed, — но клиент читает витрину как
//	          перечень того, что можно выдать, и получает отказ на предложенном;
//	СОЗДАНИЕ  тип заведён применением в РАБОТАЮЩЕМ процессе, сборка о нём не
//	          знает → витрина о нём молчит, и арендатор не находит того, что сам
//	          же объявил. Отказа нет ни одного: есть отсутствие строки, которое
//	          читается как «такого ресурса у платформы нет».
//
// Витрина проецирует живые строки ТОЧНО — без добавлений и без изъятий, — и
// второго чтения этим не заводит: снимок каталога уже собран и обновляется
// фоном (`catalog.Snapshot`), поэтому вызов стоит разыменования указателя.
//
// Что ОСТАЛОСЬ за сборкой и почему это законно: `hasListEndpoint` — свойство
// КРАЯ, а не каталога (публичный ли у типа отфильтрованный список), и живой
// строкой оно не объявляется ни одной колонкой.
//
// Clean-arch: use-case импортирует `domain` + порт `catalog` и НЕ импортирует
// grpc/proto — проекцию на провод делает хендлер.
package permission_catalog

import (
	"context"
	"fmt"

	"github.com/PRO-Robotech/kacho-iam/internal/authzguard"
	"github.com/PRO-Robotech/kacho-iam/internal/catalog"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
)

// Catalog — the grantable taxonomy projection (use-case DTO; the handler maps
// it to ListPermissionCatalogResponse). Fields mirror the grantable taxonomy
// contract, in their backend-domain form.
type Catalog struct {
	// Modules — ordered grantable modules, each with its grantable resources.
	Modules []Module
	// ClosedVerbs — набор, ОБЩИЙ для всех ресурсов, в каноническом порядке.
	// Имя поля сохраняет форму провода (`closed_verbs`); его смысл — пересечение
	// наборов типов, а не платформенный словарь, которого больше нет.
	ClosedVerbs []string
	// Wildcard — platform-wide wildcard policy flags.
	Wildcard WildcardPolicy
}

// Module — a grantable module and the resources grantable within it.
type Module struct {
	Module    string
	Resources []Resource
}

// Resource — one grantable (module,resource) token plus the editor flags.
type Resource struct {
	// Resource — the 2nd token segment, spelled exactly as in catalog_resource.resource.
	Resource string
	// HasVerbRelations — набор глаголов ЖИВОЙ строки непуст: true у глагольных
	// листьев, false у ярусных предков (account/project).
	HasVerbRelations bool
	// HasListEndpoint — true iff the type has a PUBLIC per-object filtered List on
	// the api-gateway EXTERNAL listener (curated closed table; Internal-only List
	// does NOT count). Drives the resourceNames picker vs free-text fallback.
	HasListEndpoint bool
	// LabelSelectable — mirror of domain.IsLabelSelectableType("module.resource"):
	// true iff the type is in the label-selectable feed set (mirror-fed types +
	// iam.project/iam.account). The editor must NOT offer a match_labels
	// (ARM_LABELS) arm on a type where this is false — the rule compiler
	// fail-closed-rejects such a rule (e.g. vpc.addressPool is grantable+
	// verb-bearing but NOT label-selectable). ARM_NAMES is NOT feed-gated.
	LabelSelectable bool
	// Verbs — глаголы, которые правило роли вправе назвать НА ЭТОМ ресурсе, в
	// каноническом порядке показа. Зеркало `catalog.Facts.VerbsOfType(objectType)`;
	// пусто ровно тогда, когда HasVerbRelations = false.
	//
	// ЭТО источник выпадающего списка редактора ролей, а не ClosedVerbs (#1128):
	// набор принадлежит ТИПУ, и пересечение не выражает ни расширения (глагол
	// энфорсится, но не предлагается), ни сужения (снятие у одного ресурса
	// отнимает глагол у всех).
	Verbs []string
}

// WildcardPolicy — the catalog's wildcard policy flags, in parity with the
// rule-compiler enforcement (one source of policy truth).
type WildcardPolicy struct {
	// VerbWildcardAllowedCustom — verb-`*` is grantable in a custom role (bounded
	// "all verbs of the type").
	VerbWildcardAllowedCustom bool
	// ModuleResourceWildcardSystemOnly — module-`*` AND resource-`*` are
	// system-only (custom-role use → INVALID_ARGUMENT).
	ModuleResourceWildcardSystemOnly bool
}

// ListPermissionCatalogUseCase — builds the catalog projection.
type ListPermissionCatalogUseCase struct {
	// catalogSource — ЖИВЫЕ строки каталога, из которых строится витрина.
	catalogSource catalog.Source
}

// NewListPermissionCatalogUseCase — builder.
func NewListPermissionCatalogUseCase(catalogSource catalog.Source) *ListPermissionCatalogUseCase {
	return &ListPermissionCatalogUseCase{catalogSource: catalogSource}
}

// Execute returns the grantable taxonomy. Authenticated-floor: an anonymous
// caller is rejected fail-closed BEFORE any taxonomy is built. The
// catalog is platform-wide metadata — it is NOT scope-filtered per-tenant,
// so every authenticated principal receives the identical full set.
func (u *ListPermissionCatalogUseCase) Execute(ctx context.Context) (Catalog, error) {
	if err := authzguard.RequireAuthenticated(ctx); err != nil {
		return Catalog{}, err
	}

	// Каталожный факт берётся ОДИН раз на весь ответ. Взять его повторно внутри
	// цикла значило бы собрать витрину из двух снимков: перечень пар от одного,
	// набор глаголов от другого — и в окне обновления арендатор получил бы
	// ресурс без глаголов либо глаголы снятого ресурса.
	if u.catalogSource == nil {
		// Провязки НЕТ — отказ, а не пустая витрина. Пустой ответ здесь читался
		// бы как «платформа не даёт выдать ничего», то есть как утверждение о
		// каталоге, которого никто не делал.
		return Catalog{}, fmt.Errorf("каталог разрешений: источник живых строк не провязан — " +
			"ответить перечнем, порождённым сборкой, значило бы назвать снятые типы живыми (#1976)")
	}
	facts := u.catalogSource.Facts()

	var modules []Module
	idxByModule := make(map[string]int)
	for _, e := range facts.Resources() {
		dotted := e.Module + "." + e.Resource
		// Набор ЭТОГО типа читается у живой строки. Пустой набор означает тип без
		// пообъектных отношений действия (ярусный предок иерархии), и он законен:
		// `HasVerbRelations` ровно это и объявляет.
		verbs := facts.VerbsOfType(e.ObjectType)
		res := Resource{
			Resource: e.Resource,
			// HasVerbRelations выводится из набора живой строки, а не спрашивается
			// вторым вопросом: два источника одного факта разошлись бы на типе,
			// у которого глаголы сняли, а признак забыли.
			HasVerbRelations: len(verbs) > 0,
			// HasListEndpoint — свойство КРАЯ, не каталога: живой строкой оно не
			// объявляется, поэтому остаётся закрытой таблицей (см. шапку).
			HasListEndpoint: hasPublicListEndpoint(e.Module, e.Resource),
			// LabelSelectable — the ARM_LABELS feed-gate, projected straight from
			// the domain source of truth (the dotted key matches the catalog form).
			LabelSelectable: domain.IsLabelSelectableType(dotted),
			// Verbs — набор ЭТОГО типа, приведённый к каноническому порядку той же
			// точкой, что и превью роли: порядок поверхности — часть контракта, и
			// второй его источник разошёлся бы с первым молча.
			Verbs: domain.OrderVerbsForDisplay(verbs),
		}
		i, ok := idxByModule[e.Module]
		if !ok {
			i = len(modules)
			idxByModule[e.Module] = i
			modules = append(modules, Module{Module: e.Module})
		}
		modules[i].Resources = append(modules[i].Resources, res)
	}

	// closedVerbs — набор, ОБЩИЙ для всех ресурсов: ПЕРЕСЕЧЕНИЕ наборов всех типов.
	//
	// Прежде поле копировало глобальный словарь глаголов. Пока набор был одинаков у
	// всех типов, значения совпадали; с набором У ТИПА совпадение перестаёт быть
	// определением, и поле обязано сказать, что именно оно показывает. Показывает
	// оно общее — то, что даёт ЛЮБОЙ ресурс. С появлением типа с расширенным набором
	// пересечение сузится, и это верно: обещать глагол, которого часть ресурсов не
	// несёт, поле не вправе. Словарь ПО РЕСУРСУ вводит отдельная под-фаза.
	//
	// Порядок — КАНОНИЧЕСКИЙ, той же точкой, что у превью роли: он часть контракта
	// поля, его читают существующие клиенты. Пересечение приходит отсортированным по
	// алфавиту, поэтому без этого приведения смена источника молча переставила бы
	// значения местами.
	//
	// Считается по ЖИВЫМ строкам тем же фактом, что и наборы типов выше: общее из
	// одного источника, а частное из другого дало бы поле, не являющееся
	// пересечением показанных наборов.
	//
	// CommonVerbVocabulary уже возвращает свежую копию — источник истины не алиасится.
	closedVerbs := domain.OrderVerbsForDisplay(facts.CommonVerbVocabulary())

	return Catalog{
		Modules:     modules,
		ClosedVerbs: closedVerbs,
		Wildcard: WildcardPolicy{
			VerbWildcardAllowedCustom:        true, // verb-`*` bounded.
			ModuleResourceWildcardSystemOnly: true, // module/resource-`*` system-only.
		},
	}, nil
}
