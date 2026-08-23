// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// verb_relation_has_reader_test.go — перепись ЧИТАТЕЛЕЙ глагольных отношений.
//
// ПРЕДМЕТ. Отношение, которое модель объявляет, реконсайлер материализует, а
// никакой путь запроса не спрашивает, — это не «запас на будущее». Это право, за
// которое платят записью, объёмом и временем реконсиляции, ничего не получая, и о
// котором поэтому никто не думает. Соседние гейты этого файла-собрата
// (fga_model_drift_test.go) сверяют модель с таблицей эмиттера в обе стороны и
// ловят РАСХОЖДЕНИЕ; ни один из них не спрашивает, читает ли объявленное
// отношение хоть кто-нибудь. Согласованно мёртвое отношение проходит их все.
//
// ЧТО СЧИТАЕТСЯ ЧИТАТЕЛЕМ. Пара (тип, отношение), по которой принимается решение
// о доступе к запросу. Два источника, оба машинные:
//
//  1. КАТАЛОГ ПРАВ — `permission_catalog.json`: пара
//     (`scope_extractor.object_type`, `required_relation`). Это перечень
//     per-RPC Check'ов края, сгенерированный из proto; обе встроенные копии
//     байт-идентичны (гейт `make permission-catalog-check`).
//  2. ЭНФОРС В ХЕНДЛЕРЕ — RPC, объявленные `<exempt>` + ScopeFiltered, где
//     решение принимает сам сервис, а не край. Каталог такую пару выразить не
//     может by construction, поэтому она перечисляется ниже ЯВНО, с координатой
//     энфорсящего вызова. Перечень сам себя проверяет на устаревание: запись,
//     чью пару каталог начал выражать (или чей тип перестал её объявлять), —
//     находка, а не тихо лишняя строка.
//
// ЧТО УТВЕРЖДАЕТСЯ. Множество объявленных-но-нечитаемых пар РАВНО объявленному
// ниже перечню `declaredWithoutReader`. Равенство, а не включение: пара, у
// которой появился читатель, обязана из перечня уйти (иначе перечень
// переживает свой предмет), а новая мёртвая пара обязана в него не поместиться.
//
// ПОЧЕМУ РАВЕНСТВО, А НЕ «ПУСТО». Шесть пар в перечне мёртвы и на сегодня НЕ
// сняты: у `vpc_address_pool` все RPC гейтятся `system_admin@cluster`, у
// `iam_role` чтение единичного объекта энфорсится тем же предикатом, что
// страница (`viewer ∪ v_list`), у `storage_snapshot` списочный фильтр
// спрашивает только `v_get`. Снятие каждой — отдельное решение со своим
// разбором; пока оно не принято, число обязано быть ЗАФИКСИРОВАНО, чтобы не
// росло молча. Перечень с причиной честнее, чем «ноль находок» из проверки,
// которая этих пар не рассматривает.
package authzmap_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/services/iam/internal/authzmap"
)

// catalogRelPath — встроенная копия каталога прав на стороне iam. Вторая копия
// (gateway/internal/middleware/embed/) байт-идентична ей — это отдельный,
// уже существующий гейт (`make permission-catalog-check`), поэтому читать здесь
// обе значило бы дублировать его утверждение, а не усиливать своё.
const catalogRelPath = "services/iam/internal/apps/kacho/seed/embedded/permission_catalog.json"

// verbPair — (FGA object type, имя глагольного отношения).
type verbPair struct {
	Type     string
	Relation string
}

func (p verbPair) String() string { return p.Type + "#" + p.Relation }

// handlerEnforcedPairs — пары, решение по которым принимает СЕРВИС, а не край.
// RPC объявлен `<exempt>` в каталоге и `ScopeFiltered` в карте сервиса, поэтому
// пара в каталоге отсутствует by construction, а читатель есть.
//
// Координата обязательна: без неё запись неотличима от отговорки, и следующий
// читатель не может проверить, что энфорс на месте.
var handlerEnforcedPairs = map[verbPair]string{
	// CreateRepository / RenameRepository — namespace-гейт «создать репозиторий в
	// этом реестре» (`registryGate(..., relationVCreate)`), плюс data-plane docker:
	// push в НОВЫЙ repo, mount в новый dst, и раскрытие собственного свежего блоба.
	{Type: "registry_registry", Relation: "v_create"}: "services/registry/internal/handler/repository.go (CreateRepository, RenameRepository) + services/registry/internal/dataplane/handler.go (servePush new-repo, serveMount dst, pushContextRevealsBlob)",

	// Per-repo энфорс с сокрытием существования: deny → NOT_FOUND, поэтому
	// единичный Check края здесь семантически неверен (он ответил бы
	// PERMISSION_DENIED и тем раскрыл чужой repo).
	{Type: "registry_repository", Relation: "v_get"}:    "services/registry/internal/handler/repository.go (GetRepository, ListReferrers) + dataplane pull/mount-src",
	{Type: "registry_repository", Relation: "v_list"}:   "services/registry/internal/handler/listauthz.go (filterRepos — ListRepositories/ListTags/_catalog)",
	{Type: "registry_repository", Relation: "v_update"}: "services/registry/internal/handler/repository.go (UpdateRepository, RenameRepository) + dataplane push в СУЩЕСТВУЮЩИЙ repo",
	{Type: "registry_repository", Relation: "v_delete"}: "services/registry/internal/handler/repository.go (DeleteRepository) + DeleteTag",
}

// declaredWithoutReader — пары, которые модель объявляет и НИКТО не спрашивает.
//
// Каждая запись несёт причину, по которой она ещё здесь. Запись без предмета
// (пара перестала быть мёртвой либо тип перестал её объявлять) — находка: см.
// утверждение о равенстве ниже.
var declaredWithoutReader = map[verbPair]string{

	// AddressPool — admin-only ресурс (`security.md` §Internal-vs-external): все 11
	// RPC `InternalAddressPoolService` гейтятся `system_admin@cluster`, и ни один
	// путь запроса не спрашивает пообъектный глагол на самом пуле. Тип объявлен
	// глагольным, потому что он в грантабельном каталоге; снятие глаголов у него —
	// отдельное решение (грантабельность admin-ресурса пообъектно).
	{Type: "vpc_address_pool", Relation: "v_get"}:    "все RPC — system_admin@cluster (admin-only ресурс)",
	{Type: "vpc_address_pool", Relation: "v_list"}:   "все RPC — system_admin@cluster (admin-only ресурс)",
	{Type: "vpc_address_pool", Relation: "v_update"}: "все RPC — system_admin@cluster (admin-only ресурс)",
	{Type: "vpc_address_pool", Relation: "v_delete"}: "все RPC — system_admin@cluster (admin-only ресурс)",

	// RoleService/Get стоит на полосе `scope_filtered` (#973; прежде — `<exempt>`
	// с неверно названной причиной). Единичное чтение роли энфорсится ТЕМ ЖЕ
	// предикатом, что страница (`iam_role` → {viewer, v_list} в
	// internal/authzfilter/visibility.go), поэтому страница и чтение не могут
	// разойтись. Отдельного `v_get` на роли не спрашивает никто.
	{Type: "iam_role", Relation: "v_get"}: "Get энфорсится предикатом страницы {viewer, v_list}, не v_get",

	// iam_user#v_update — читателя нет с #1102: правку записи личности спрашивает
	// `record_writer`, а запрет и снятие запрета — `identity_suspender`; ни у того,
	// ни у другого источников уровня аккаунта нет. Человек есть ГЛОБАЛЬНАЯ личность
	// (одна строка на все его аккаунты), и распоряжаться этой строкой аккаунт не
	// вправе — это вторая половина директивы владельца 2026-08-23.
	//
	// ПОЧЕМУ ОТНОШЕНИЕ ОСТАЛОСЬ ОБЪЯВЛЕННЫМ, хотя гейт предлагает его снять. Снятие
	// проверено и отвергнуто ЗАМЕРОМ, а не соображением: `closed_verbs` каталога
	// прав — ПЕРЕСЕЧЕНИЕ наборов всех типов, и редактор ролей строит из него
	// выпадающий список. Убрав `update` у одного типа, мы убираем глагол из словаря
	// для ВСЕХ 26 остальных: он остаётся энфорсимым, но перестаёт предлагаться, и
	// роль с ним авторуется только через API. Проба
	// TestVerbRelation_EnforcedVerbsAbsentFromClosedVerbs называет это поимённо —
	// прогон на снятом глаголе дал ровно эти 26 пар.
	//
	// ЦЕНА, КОТОРУЮ ЭТА ЗАПИСЬ УДЕРЖИВАЕТ, названа честно: правило роли с глаголом
	// `update` на `iam.user` продолжает материализовать кортеж, который никто не
	// спрашивает, и вместе с ним — выводимое «правка влечёт удаление». То есть роль
	// `iam.user.edit` даёт сегодня только удаление, а её имя обещает иное.
	//
	// ПРЕДИКАТ СНЯТИЯ: словарь глаголов ПО РЕСУРСУ (`CatalogResource.verbs`,
	// названный в proto каталога как отдельная под-фаза) — тогда набор типа можно
	// сузить, не отнимая глагол у остальных, и эта запись снимается вместе с
	// `v_update` у `iam_user`. Предмет — #1128.
	{Type: "iam_user", Relation: "v_update"}: "правку записи спрашивает record_writer, запрет — identity_suspender (#1102); снятие глагола ждёт словаря по ресурсу (#1128)",

	// iam_user#v_delete — читателя нет с #1131. Снятие строки личности спрашивает
	// `identity_remover` (сам человек и надзор облака), и источников уровня аккаунта
	// у него нет: строка `iam_user` — ГЛОБАЛЬНАЯ личность, одна на все аккаунты
	// человека, поэтому удаление её из аккаунта A стирает человека и в аккаунте B.
	// Это строго тяжелее запрета, который #1102 из аккаунта уже вынес.
	//
	// ЧТО ПОЛУЧИЛ АККАУНТ ВЗАМЕН — не «ничего»: исключение из аккаунта
	// (`UserService/RemoveFromAccount`, гейт `account.member_remover`, #1127)
	// приходит тем же изменением и делает ровно то, ради чего распорядитель тянулся
	// к удалению: снимает членство, не трогая личность.
	//
	// ПОЧЕМУ ОТНОШЕНИЕ ОСТАЛОСЬ ОБЪЯВЛЕННЫМ — тот же замер, что и у `v_update` выше:
	// `closed_verbs` есть пересечение наборов всех типов, и снятие `delete` у одного
	// типа вынимает глагол из словаря редактора ролей у всех остальных.
	//
	// ЦЕНА, КОТОРУЮ ЭТА ЗАПИСЬ УДЕРЖИВАЕТ, названа целиком: у `iam.user` теперь оба
	// распоряжающихся глагола без читателя, поэтому роли `iam.user.edit` и
	// `iam.user.delete` не дают НИЧЕГО энфорсимого. Это не побочный эффект, а
	// следствие решения — и именно поэтому оно записано здесь, а не выведено из
	// молчания.
	//
	// ПРЕДИКАТ СНЯТИЯ — тот же: словарь глаголов ПО РЕСУРСУ (#1128).
	{Type: "iam_user", Relation: "v_delete"}: "снятие строки спрашивает identity_remover (#1131), исключение из аккаунта — account.member_remover (#1127); снятие глагола ждёт словаря по ресурсу (#1128)",

	// Здесь стояло послабление для пары (storage_snapshot, v_list): «у снимка нет
	// ListOperations». Оно снято вместе со своим предметом — RPC заведён, и пара
	// обрела читателя. Гейт сам это и назвал: запись, которой больше нечего
	// исключать, — находка, а не безобидный остаток.
}

// TestVerbRelation_DeclaredOnlyWhereRead — перепись в обе стороны.
//
// Красное здесь означает ровно одно из двух, и сообщение говорит, какое:
// объявлено отношение, которого никто не спрашивает (новое мёртвое право), либо
// перечень исключений пережил свой предмет (у пары появился читатель, а строка
// осталась).
func TestVerbRelation_DeclaredOnlyWhereRead(t *testing.T) {
	declared := declaredVerbPairs(t)
	catalog := catalogEnforcedPairs(t)

	// ПРЕДПОСЫЛКА ГЕЙТА. Перепись читателей идёт по каталогу; если каталог не
	// прочитан или не несёт глагольных пар, «ноль находок» означало бы «ноль
	// прочитанного», и гейт молчал бы на полностью мёртвой модели. Контроль
	// сформулирован на ОТНОШЕНИЯХ, у которых читатель заведомо есть.
	require.NotEmpty(t, declared, "модель не дала ни одной глагольной пары — парсер или модель сломаны")
	require.NotEmpty(t, catalog, "каталог прав не дал ни одной глагольной пары — предпосылка переписи сломана")
	for _, control := range []string{"v_get", "v_delete", "v_update"} {
		n := 0
		for p := range catalog {
			if p.Relation == control {
				n++
			}
		}
		require.GreaterOrEqualf(t, n, 15,
			"контрольное отношение %q дало %d пар каталога — предикат переписи меряет не то, "+
				"и вывод «у v_create нет читателя» из него был бы ложным", control, n)
	}

	// Пары без читателя: объявлено − каталог − энфорс в хендлере.
	unread := map[verbPair]bool{}
	for p := range declared {
		if catalog[p] {
			continue
		}
		if _, ok := handlerEnforcedPairs[p]; ok {
			continue
		}
		unread[p] = true
	}

	// (1) Каждая пара без читателя обязана быть объявлена в перечне.
	var newlyDead []string
	for p := range unread {
		if _, known := declaredWithoutReader[p]; !known {
			newlyDead = append(newlyDead, p.String())
		}
	}
	sort.Strings(newlyDead)
	require.Emptyf(t, newlyDead,
		"модель объявляет %d глагольных отношений, которых НЕ спрашивает ни каталог прав, ни "+
			"энфорс в хендлере: %s\n"+
			"Отношение без читателя материализуется реконсайлером на каждый объект в области "+
			"привязки — за него платят записью, объёмом хранилища прав и временем реконсиляции, "+
			"и оно остаётся правом, которое никто не проверяет. Либо заведи читателя (запись в "+
			"каталоге прав или явный Check в хендлере — тогда добавь координату в "+
			"handlerEnforcedPairs), либо сними отношение с типа в %s и из typeVerbRelations.",
		len(newlyDead), strings.Join(newlyDead, ", "), canonicalModelRelPath)

	// (2) ОБРАТНАЯ сторона: запись перечня, у которой больше нет предмета.
	// Исключение живёт, пока ему есть что исключать (`testing.md` §Гейт на класс, п.5).
	var stale []string
	for p, reason := range declaredWithoutReader {
		require.NotEmptyf(t, reason, "declaredWithoutReader[%s] обязана нести причину", p)
		switch {
		case !declared[p]:
			stale = append(stale, fmt.Sprintf("%s (тип больше не объявляет это отношение)", p))
		case catalog[p]:
			stale = append(stale, fmt.Sprintf("%s (появилась запись в каталоге прав — читатель есть)", p))
		case !unread[p]:
			stale = append(stale, fmt.Sprintf("%s (читатель появился)", p))
		}
	}
	sort.Strings(stale)
	require.Emptyf(t, stale,
		"перечень declaredWithoutReader пережил свой предмет: %s. Убери запись — исключение "+
			"живёт, пока ему есть что исключать.", strings.Join(stale, ", "))

	// (3) Та же обратная проверка для перечня энфорса в хендлере.
	var staleHandler []string
	for p, coord := range handlerEnforcedPairs {
		require.NotEmptyf(t, coord, "handlerEnforcedPairs[%s] обязана нести координату энфорсящего вызова", p)
		switch {
		case !declared[p]:
			staleHandler = append(staleHandler, fmt.Sprintf("%s (тип больше не объявляет это отношение)", p))
		case catalog[p]:
			staleHandler = append(staleHandler, fmt.Sprintf("%s (каталог прав теперь выражает пару — запись лишняя)", p))
		}
	}
	sort.Strings(staleHandler)
	require.Emptyf(t, staleHandler,
		"перечень handlerEnforcedPairs пережил свой предмет: %s", strings.Join(staleHandler, ", "))

	t.Logf("перепись: объявлено пар (тип, v_*): %d; читается каталогом прав: %d; "+
		"энфорсится в хендлере: %d; без читателя: %d",
		len(declared), len(catalog), len(handlerEnforcedPairs), len(unread))
}

// TestVerbRelation_CreateIsDeclaredOnlyWhereEnforced — именной замок предмета
// #52, отдельно от общей переписи выше.
//
// Он проверяет НЕ то же самое: общая перепись допускает мёртвую пару, если она
// перечислена, — а эта требует, чтобы у `v_create` мёртвых пар не осталось
// вовсе. Именно `v_create` был отношением, объявленным ДВАДЦАТЬЮ ЧЕТЫРЬМЯ типами
// при одном-единственном читателе, и цена этого измерена: на боевом стенде на
// него приходилась почти десятая часть всего хранилища кортежей. Замок именной,
// чтобы возврат отношения на тип-лист краснел, называя тип, а не растворялся в
// общем перечне исключений.
func TestVerbRelation_CreateIsDeclaredOnlyWhereEnforced(t *testing.T) {
	declared := declaredVerbPairs(t)
	catalog := catalogEnforcedPairs(t)

	var carriers, dead []string
	for p := range declared {
		if p.Relation != "v_create" {
			continue
		}
		carriers = append(carriers, p.Type)
		if catalog[p] {
			continue
		}
		if _, ok := handlerEnforcedPairs[p]; ok {
			continue
		}
		dead = append(dead, p.Type)
	}
	sort.Strings(carriers)
	sort.Strings(dead)

	require.NotEmpty(t, carriers,
		"ни один тип не объявляет v_create — предпосылка замка сломана: он обязан охранять "+
			"единственного законного носителя, а не пустоту")
	require.Emptyf(t, dead,
		"v_create объявлен на типах, где его не спрашивает никто: %s\n"+
			"Создание ресурса в Kachō авторизуется ярусом записи на РОДИТЕЛЕ (`editor@project`), "+
			"а не пообъектным v_create на самом ресурсе — «создать» не есть операция над уже "+
			"существующим объектом. Единственное исключение — контейнерная семантика реестра "+
			"(`v_create@registry_registry` = «создать репозиторий в этом пространстве имён»), "+
			"и она энфорсится в хендлере и data-plane. Если нужен новый носитель — сначала "+
			"читатель, потом отношение.", strings.Join(dead, ", "))

	t.Logf("перепись: типов, объявляющих v_create: %d (%s)", len(carriers), strings.Join(carriers, ", "))
}

// verbsNotOfferedByClosedVerbs — пары (тип, глагол БЕЗ приставки), которые
// энфорсятся, но которых нет в публичном поле `closed_verbs` каталога прав.
//
// `closed_verbs` — ПЕРЕСЕЧЕНИЕ наборов всех типов, и редактор ролей строит из него
// выпадающий список глаголов. Значит глагол, объявленный не всеми типами, в список
// не попадает: роль с ним авторуется через API, но не через редактор. Это цена
// одного глобального поля там, где набор стал атрибутом типа; закрывает её словарь
// ПО РЕСУРСУ — отдельная под-фаза, названная в proto каталога.
//
// Перечень существует, чтобы цена была СОСЧИТАНА, а не упомянута прозой: четвёртая
// пара обязана покраснеть, и покраснеть же обязана запись, у которой предмет
// исчез (глагол вошёл в пересечение либо тип перестал его объявлять).
var verbsNotOfferedByClosedVerbs = map[verbPair]string{
	{Type: "nlb_target_group", Relation: "addtargets"}:    "NLB-TGT-1: управление составом группы отделено от правки самой группы",
	{Type: "nlb_target_group", Relation: "removetargets"}: "NLB-TGT-1: управление составом группы отделено от правки самой группы",
	{Type: "registry_registry", Relation: "create"}:       "контейнерная семантика: «создать репозиторий в этом пространстве имён»",
}

// TestVerbRelation_EnforcedVerbsAbsentFromClosedVerbs — цена одного глобального
// словаря, посчитанная и прибитая.
func TestVerbRelation_EnforcedVerbsAbsentFromClosedVerbs(t *testing.T) {
	common := map[string]bool{}
	for _, v := range authzmap.CommonVerbVocabulary() {
		common[v] = true
	}
	require.NotEmpty(t, common,
		"общий словарь глаголов пуст — предпосылка сломана, и «ноль находок» ниже означало бы «ноль прочитанного»")

	declared := declaredVerbPairs(t)
	outside := map[verbPair]bool{}
	for p := range declared {
		verb := strings.TrimPrefix(p.Relation, "v_")
		if !common[verb] {
			outside[verbPair{Type: p.Type, Relation: verb}] = true
		}
	}

	var unlisted []string
	for p := range outside {
		if _, known := verbsNotOfferedByClosedVerbs[p]; !known {
			unlisted = append(unlisted, p.String())
		}
	}
	sort.Strings(unlisted)
	require.Emptyf(t, unlisted,
		"тип объявляет глагол, которого нет в общем словаре `closed_verbs`, и это не записано: %s\n"+
			"Редактор ролей строит выпадающий список из `closed_verbs`, поэтому такой глагол "+
			"энфорсится, но не предлагается — роль с ним авторуется только через API. Либо "+
			"внеси пару сюда с причиной, либо закрой класс словарём ПО РЕСУРСУ "+
			"(CatalogResource.verbs — отдельная под-фаза, названная в proto каталога).",
		strings.Join(unlisted, ", "))

	var stale []string
	for p, reason := range verbsNotOfferedByClosedVerbs {
		require.NotEmptyf(t, reason, "verbsNotOfferedByClosedVerbs[%s] обязана нести причину", p)
		if !outside[p] {
			stale = append(stale, p.String())
		}
	}
	sort.Strings(stale)
	require.Emptyf(t, stale,
		"перечень verbsNotOfferedByClosedVerbs пережил свой предмет: %s — глагол вошёл в общий "+
			"словарь либо тип перестал его объявлять", strings.Join(stale, ", "))

	t.Logf("перепись: общий словарь = %v; пар вне него: %d",
		authzmap.CommonVerbVocabulary(), len(outside))
}

// declaredVerbPairs — пары (тип, `v_*`), которые объявляет каноническая модель.
func declaredVerbPairs(t *testing.T) map[verbPair]bool {
	t.Helper()
	f := parseModel(t)
	out := map[verbPair]bool{}
	for typ := range f.types {
		for _, rel := range f.verbRelationsOfType(typ) {
			out[verbPair{Type: typ, Relation: rel}] = true
		}
	}
	return out
}

// catalogEnforcedPairs — пары (scope_extractor.object_type, required_relation)
// из каталога прав, ограниченные глагольными отношениями.
//
// Записи с пустым `required_relation` (`<exempt>`) и с пустым object_type сюда не
// попадают намеренно: они не выражают решения по паре. Именно поэтому энфорс в
// хендлере перечисляется отдельно, а не «подразумевается».
func catalogEnforcedPairs(t *testing.T) map[verbPair]bool {
	t.Helper()
	path := filepath.Join(monorepoRoot(t), catalogRelPath)
	data, err := os.ReadFile(path)
	require.NoErrorf(t, err, "каталог прав %s не прочитан — перепись читателей не имеет источника", catalogRelPath)

	var entries []struct {
		FQN              string `json:"fqn"`
		RequiredRelation string `json:"required_relation"`
		ScopeExtractor   struct {
			ObjectType string `json:"object_type"`
		} `json:"scope_extractor"`
	}
	require.NoError(t, json.Unmarshal(data, &entries))
	require.NotEmptyf(t, entries, "каталог прав %s разобран в ноль записей", catalogRelPath)

	out := map[verbPair]bool{}
	for _, e := range entries {
		rel, ot := e.RequiredRelation, e.ScopeExtractor.ObjectType
		if ot == "" || !strings.HasPrefix(rel, "v_") {
			continue
		}
		out[verbPair{Type: ot, Relation: rel}] = true
	}
	return out
}
