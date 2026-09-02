// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package authzmap

import "sort"

// catalog_resource_spelling.go — ЕДИНСТВЕННОЕ объявление расхождения между двумя
// написаниями имени ресурса, и оно здесь потому, что здесь живёт то написание,
// которое побеждает.
//
// # Написаний ДВА, и второе не объявлено нигде — оно ВЫВОДИТСЯ
//
//	ключ закрытой таблицы   loadbalancer.targetGroups   (fga_types.go, ниже)
//	выведенное из службы    loadbalancer.targetGroup    (`TargetGroupService`
//	                                                     минус суффикс, строчная
//	                                                     первая буква)
//
// Первое написание объявлено; второе производит привязка записей каталога прав
// к действиям модулей (services/iam/internal/manifest/roleexport, attribution.go)
// — из имени СЛУЖБЫ, потому что среднего сегмента `permission` и якоря
// `scope_extractor.object_type` для этого не хватает (разобрано там же). У vpc,
// compute и iam ключи единственного числа, и оба написания совпадают; у
// loadbalancer, registry и storage ключ множественный — и не совпадают.
//
// # Почему побеждает ключ закрытой таблицы, а не выведенное
//
// Не по вкусу и не по старшинству: у ключа таблицы есть ЧИТАТЕЛЬ НА ПУТИ
// ЗАПРОСА, а у выведенного нет. Правило роли, назвавшее ресурс, проходит
// validateRuleCatalog (internal/apps/kacho/api/role/rules_catalog.go), и та
// отвергает пару, которой в закрытой таблице нет:
// `Illegal argument resources (unknown type '<модуль>.<ресурс>')`. Тем же ключом
// эмиттер резолвит тип объекта, на котором материализует пообъектные кортежи.
// То есть выведенное написание в правиле роли не работает НИ В ОДНОМ из двух
// мест, где решается доступ.
//
// # Что было наблюдаемо до этого объявления (#1884)
//
// У балансировщика не существовало написания, при котором его права
// проверяются. Прогон проверки манифеста на настоящем ресурсе, шесть действий:
//
//	name: targetGroups  → не сопоставлено 6   (привязка выводит `targetGroup`)
//	name: targetGroup   → непригодно для роли 5, не сопоставлено 0
//	                      (закрытая таблица пары не знает → типа объекта нет)
//
// Оба прогона выходят кодом 0. В первом шесть действий выведены из ВСЕХ трёх
// проверок — не нарушением, а невидимостью.
//
// # Форма объявления: только РАСХОЖДЕНИЯ, и запись обязана истекать
//
// Совпадающие написания сюда не пишутся: запись, чьи стороны равны, ничего не
// объявляет и делает перечень полнее, чем он есть.
//
// Держат это три пробы соседнего пакета (roleexport, attributionspelling_test.go),
// и вход у них НАСТОЯЩИЙ — встроенный каталог прав, тот самый, что читает посев:
//
//	TestAttributionProducesTheClosedTableSpelling    ключ таблицы, которого
//	                                                привязка не производит
//	TestDeclaredSpellingDivergencesStillHaveASubject запись, чьи стороны совпали
//	                                                либо ведут в никуда
//	TestResourcesWithoutOwnServiceAreStillUnreachable исключение, которому больше
//	                                                нечего исключать

// catalogSpellingByServiceName — написание ключа закрытой таблицы для написания,
// выведенного из имени службы. Ключ и значение — дотированные `модуль.ресурс`;
// перечислены ТОЛЬКО расхождения.
var catalogSpellingByServiceName = map[string]string{
	// kacho-nlb: пакет контрактов `loadbalancer`, ключи таблицы множественные.
	"loadbalancer.networkLoadBalancer": "loadbalancer.networkLoadBalancers",
	"loadbalancer.targetGroup":         "loadbalancer.targetGroups",
	"loadbalancer.listener":            "loadbalancer.listeners",

	// kacho-registry
	"registry.registry": "registry.registries",

	// kacho-storage
	"storage.volume":   "storage.volumes",
	"storage.snapshot": "storage.snapshots",
	"storage.image":    "storage.images",
}

// catalogResourcesWithoutOwnService — грантуемые ресурсы, чьё написание не
// производит НИ ОДНО имя службы, потому что собственной службы в контрактах у
// них нет вовсе. Достижимость такого ключа недостижима by construction, и без
// этой записи гейт требовал бы от дерева службы, которой там не должно быть.
//
// Причина у каждой записи своя и названа: перечень без причин через полгода
// читается как список неисправностей.
//
// Запись ИСТЕКАЕТ САМА: гейт краснеет, когда написание ключа всё же начинает
// производиться именем службы, — тогда исключению больше нечего исключать.
var catalogResourcesWithoutOwnService = map[string]string{
	"registry.repositories": "объект составной (`<реестр>/<репозиторий>`), резолвится " +
		"обработчиком, службы `RepositoryService` в контрактах нет — якорю нечего " +
		"извлекать из поля запроса (анти-BOLA)",
}

// CatalogSpelling приводит написание РЕСУРСА, ВЫВЕДЕННОЕ из имени службы, к
// написанию, которым его называет ключ закрытой таблицы типов (модуль не
// возвращается: он у обеих сторон один и тот же). Написание, о котором расхождение не
// объявлено, возвращается как есть — совпадение это общий случай, и запись о нём
// была бы записью без предмета.
//
// Вызывающий — привязка записей каталога; сама таблица типов через неё НЕ
// резолвится, поэтому словарь ключей `ObjectType` не расширяется ни на один
// вход. Расширить его значило бы принять в правиле роли написание, которое
// validateRuleCatalog на пути запроса отвергает, — то есть объявить возможность,
// которой нет.
func CatalogSpelling(module, derived string) string {
	canon, ok := catalogSpellingByServiceName[module+"."+derived]
	if !ok {
		return derived
	}
	// Значение записи — дотированный ключ целиком: так его видно рядом с
	// таблицей и так его сверяет гейт. Вызывающему нужен сегмент ресурса.
	// Негодная запись сюда не доживает — обе стороны каждой записи держит
	// TestDeclaredSpellingDivergencesStillHaveASubject, — но приведение к
	// заведомо неверному написанию было бы хуже отсутствия приведения, поэтому
	// разбор проверяется, а не подразумевается.
	_, resource, split := SplitObjectType(canon)
	if !split {
		return derived
	}
	return resource
}

// CatalogSpellingDivergences отдаёт КОПИЮ объявленных расхождений (выведенное →
// ключ таблицы), для переписей и гейтов.
func CatalogSpellingDivergences() map[string]string {
	out := make(map[string]string, len(catalogSpellingByServiceName))
	for k, v := range catalogSpellingByServiceName {
		out[k] = v
	}
	return out
}

// CatalogResourcesWithoutOwnService отдаёт КОПИЮ перечня грантуемых ресурсов без
// собственной службы: дотированный ключ → причина.
func CatalogResourcesWithoutOwnService() map[string]string {
	out := make(map[string]string, len(catalogResourcesWithoutOwnService))
	for k, v := range catalogResourcesWithoutOwnService {
		out[k] = v
	}
	return out
}

// CatalogKeys — дотированные ключи закрытой таблицы, отсортированные. Отличается
// от Catalog() только формой (строка вместо пары) и заведена ради переписей,
// которым пара не нужна.
func CatalogKeys() []string {
	out := make([]string, 0, len(objectTypes))
	for k := range objectTypes {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
