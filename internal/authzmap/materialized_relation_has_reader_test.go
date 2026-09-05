// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// materialized_relation_has_reader_test.go — гейт на КЛАСС: отношение, которое
// материализация ПРОИЗВОДИТ, обязано кем-то ЧИТАТЬСЯ при решении о доступе.
//
// # Предмет
//
// Пообъектная материализация плоской модели пишет на КАЖДЫЙ созданный объект набор
// `v_*` его типа плюс ярусный кортеж. Каждое такое отношение оплачивается ТРИЖДЫ:
// его выводит реконсайлер, его записывает хранилище прав (и дренаж очереди), и оно
// лежит в индексе, через который идёт каждый Check. Отношение, которое производится,
// записывается и дренится, но не участвует НИ В ОДНОМ решении о доступе, — это не
// «запас на будущее», а стоимость на всех трёх звеньях без предмета.
//
// # Почему это гейт, а не разовая перепись
//
// Перепись глазами устаревает в тот же день: набор глаголов типа объявляется у типа,
// каталог прав генерируется из proto, а сервисы вправе завести свою проверку. Три
// подвижных источника — значит утверждение «этот кортеж кто-то читает» обязано
// пересчитываться сборкой, иначе оно переживёт свой предмет.
//
// # Кого считаем ЧИТАТЕЛЕМ (три источника, объединение)
//
//  1. КАТАЛОГ ПРАВ — запись с `required_relation` на этом `object_type`. Это решение,
//     которое принимает край на каждом публичном RPC.
//  2. МОДЕЛЬ — отношение, на которое ССЫЛАЕТСЯ определение другого отношения ТОГО ЖЕ
//     типа (`define v_addtargets: … or v_update`). Такое отношение читается косвенно,
//     и снять его значило бы порвать вывод.
//  3. ПРОД-КОД СЕРВИСА-ВЛАДЕЛЬЦА — литерал отношения в НЕ-тестовом `.go` того сервиса,
//     которому принадлежит тип. Так ловятся проверки, которых нет в каталоге края:
//     data-plane реестра гейтит свои RPC сам.
//
// # Разрешающая способность третьего источника — СЕРВИС, а не тип
//
// Литерал отношения виден в файле, но кому из СВОИХ типов сервис его задаёт — из
// литерала не следует. Поэтому третий источник засчитывает отношение всем типам
// сервиса-владельца сразу, и гейт на этой оси СКОРЕЕ ПРОМОЛЧИТ, чем оговорит лишнее:
// у сервиса с несколькими типами найденное для одного зачтётся всем. Так и выбрано
// намеренно — ложная находка про доступ дороже пропущенной, потому что снимать
// отношение по ошибке значит закрыть работающий доступ.
//
// Практическое следствие, названное числом: реестр читает `v_create` на СВОЁМ
// родительском объекте, но не на дочернем (создание репозитория спрашивается у
// namespace, у которого репозитория ещё нет). Гейт этой разницы не видит и оба типа
// реестра считает читающими. Уточнение потребовало бы разбора аргументов вызова
// Check по типу объекта — это отдельная работа, и до неё граница здесь проходит по
// сервису, а не по типу.
//
// # Чего читателем НЕ считаем — и это половина смысла гейта
//
// Файлы ЭМИССИИ (`fga_types.go` — таблица наборов, `reconcile/tuples.go` — сборщик
// кортежей) содержат имена отношений по построению: они их ПИШУТ. Засчитать их за
// читателя значит получить гейт, который всегда зелёный, потому что писатель сам
// себя объявляет читателем. Первая редакция предиката именно это и делала — и «ноль
// находок» на iam-типах был артефактом самозачёта, а не свойством дерева.
//
// # Что гейт делает с уже известным расхождением
//
// Он его НЕ прощает молча: `knownUnread` перечисляет пары поимённо, и список обязан
// ИСТЕКАТЬ САМ — пара, которая перестала быть написанной ИЛИ обрела читателя, это
// находка, а не «стало лучше». Иначе список переживёт свой предмет ровно так же, как
// пережил бы его комментарий.
package authzmap_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-iam/internal/authzmap"
	"github.com/PRO-Robotech/kacho/pkg/treecorpus"
)

// typeOwner — сервис, которому принадлежит FGA-тип. Нужен, чтобы искать читателя
// ТАМ, где он может быть: проверка на свой тип живёт в своём сервисе. Порядок обхода
// закреплён сортировкой ключей (карта обходится недетерминированно), а самый длинный
// подходящий префикс выигрывает — иначе `iam_` перехватил бы у будущего `iam_x_`.
var typeOwnerPrefix = map[string]string{
	"vpc_":      "vpc",
	"registry_": "registry",
	"storage_":  "storage",
	"nlb_":      "nlb",
	"compute_":  "compute",
	"iam_":      "iam",
}

// typeOwnerExact — типы без служебного префикса (иерархия и кластер принадлежат iam).
var typeOwnerExact = map[string]string{
	"account": "iam",
	"project": "iam",
	"cluster": "iam",
}

func ownerOfType(fgaType string) string {
	if s, ok := typeOwnerExact[fgaType]; ok {
		return s
	}
	prefixes := make([]string, 0, len(typeOwnerPrefix))
	for p := range typeOwnerPrefix {
		prefixes = append(prefixes, p)
	}
	sort.Slice(prefixes, func(i, j int) bool { return len(prefixes[i]) > len(prefixes[j]) })
	for _, p := range prefixes {
		if strings.HasPrefix(fgaType, p) {
			return typeOwnerPrefix[p]
		}
	}
	return ""
}

// emissionSideFiles — файлы, которые отношения ПИШУТ, а не читают. Исключаются из
// поиска читателя (см. шапку: писатель, засчитанный за читателя, делает гейт вечно
// зелёным). Каждый обязан существовать — исчез файл, значит предикат смотрит не туда.
var emissionSideFiles = []string{
	filepath.Join("services", "iam", "internal", "authzmap", "fga_types.go"),
	filepath.Join("services", "iam", "internal", "apps", "kacho", "api", "access_binding", "reconcile", "tuples.go"),
}

// knownUnread — пары (тип, отношение), которые материализация пишет, а НИКТО не
// читает. Это НЕ разрешение и НЕ «так задумано»: это зафиксированная находка с
// известной ценой, которую гейт удерживает от РОСТА, пока она не снята по существу.
//
// СЕГОДНЯ ЗДЕСЬ ТОЛЬКО `v_create`, и вот почему он оказался мёртвым на всех типах,
// кроме реестра. Право «создать ресурс» по построению спрашивается НЕ у ресурса,
// которого ещё нет, а у его РОДИТЕЛЯ: и каталог края, и карты сервисов гейтят Create
// ярусом `editor` на `project`/`account`, а публичный Check приводит глагол `create`
// к `editor` (resolveActionToRelation), а не к `v_create`. Единственное исключение —
// реестр: `CreateRepository`/`RenameRepository` спрашивают `v_create` на РОДИТЕЛЬСКОМ
// `registry_registry`, потому что там родитель сам является объектом модели. Поэтому
// реестра в этом списке нет и быть не должно.
//
// ЦЕНА, ИЗМЕРЕННАЯ НА СТЕНДЕ (kind-kacho, срез 2026-08-06): 41087 кортежей `v_create`
// из 454031 в хранилище — 9.05% всего объёма, который производился, дренился и лежал
// в индексе под каждым Check. На `vpc_network` это было 5790 из 74932 (7.7%).
//
// СПИСОК ПУСТ, И ЭТО ИСХОД, А НЕ ЗАБЫТАЯ СТРОКА. Прежняя редакция несла здесь 22 пары
// с `v_create` и объясняла, почему снять их нельзя одной правкой таблицы: набор
// глаголов типа связан с канонической моделью гейтом дрейфа в обе стороны, поэтому
// снятие требовало убрать `define v_create` из модели для тех же типов, выпустить её
// новую версию и перекатить хранилище прав — изменение модели безопасности с полным
// прогоном e2e. Эта работа СДЕЛАНА: `v_create` снят с типов, `objectVerbRelations` его
// больше не несёт, и единственный оставшийся носитель — `registry_registry`, у которого
// читатель есть по существу семантики (реестр — контейнер, «создать репозиторий в этом
// пространстве» спрашивается именно у него).
//
// Поэтому здесь пусто: у послаблений кончился предмет. Список удерживается от роста
// той же проверкой, что и раньше, — новая пара «пишем и никто не читает» роняет гейт
// с координатой. А запись, которой больше нечего исключать, роняет его как УСТАРЕВШЕЕ
// послабление: ровно так эти 22 и были обнаружены — не глазами, а собственным
// самоистечением списка, сработавшим после снятия `v_create`.
var knownUnread = map[string][]string{
	// Четыре пары материализуются и не спрашиваются никем — и так было ВСЁ ЭТО
	// ВРЕМЯ. Здесь их не было по одной причине: третьим источником «читателя» гейт
	// считает строковый литерал отношения в прод-коде сервиса-владельца, а такие
	// литералы жили константами РУКОПИСНЫХ карт прав (`relationVList` и соседи).
	// Карты стали выводиться из аннотаций, константы ушли — и мнимые читатели
	// вместе с ними.
	//
	// Ничьё поведение не изменилось; изменилось то, что видно. Тот же набор
	// перечислен соседним гейтом (verb_relation_has_reader_test.go,
	// `declaredWithoutReader`) с разбором по каждой паре: пул адресов — admin-only
	// ресурс, все его RPC гейтятся `system_admin@cluster`; у снимка нет
	// ListOperations, а фильтр страницы спрашивает `v_get`. То есть два гейта об
	// одном предмете расходились, и правым был он.
	//
	// Пятая пара соседнего перечня — `vpc_address_pool#v_get` — здесь НЕ значится,
	// и это не описка: у неё читатель есть (её спрашивает прод-код vpc), поэтому
	// внесение её сюда роняет гейт как устаревшее послабление. Два перечня
	// пересекаются, но не равны, и каждый обязан отвечать за СВОЙ предикат.
	//
	// Снятие самих отношений — решение доменов-владельцев со своим разбором.
	// Перечень самоистекает в обе стороны.
	// storage_snapshot отсюда снят: SnapshotService/ListOperations читает v_list,
	// значит послаблению больше нечего исключать.
	"v_list": {"vpc_address_pool"},
	// `iam_user` ОТСЮДА СНЯТ вместе со своим предметом (#1128): глагол `v_update` у
	// типа больше не объявлен, поэтому материализовать его нечему. Предикат снятия
	// был назван в соседнем перечне и выполнен — словарь глаголов стал по ресурсу,
	// и сужение набора у одного типа перестало отнимать глагол у остальных 26.
	"v_update": {"vpc_address_pool"},
	// `iam_user` ОТСЮДА СНЯТ вместе со своим предметом (#1189), как строкой выше снят
	// его же `v_update` (#1128): тип больше не объявляет глагола `v_delete`, поэтому
	// материализовать его нечему, и послаблению нечего исключать.
	//
	// Распоряжение строкой личности выражено ИМЕНОВАННЫМИ отношениями: снятие строки —
	// `identity_remover` (#1131), правку — `record_writer`, запрет — `identity_suspender`
	// (#1102). Аккаунту остаётся читать своих людей и распоряжаться их УЧАСТИЕМ
	// (`account.member_remover`, #1127), а не глобальной строкой личности.
	//
	// Разбор, замер и что держит свойство наблюдаемо — соседний перечень
	// `declaredWithoutReader` (verb_relation_has_reader_test.go); здесь они не
	// пересказываются, иначе два перечня об одном предмете разойдутся при первой правке.
	"v_delete": {"vpc_address_pool"},
}

var reRelationLiteral = regexp.MustCompile(`"(v_\w+)"`)

// TestEveryMaterializedVerbRelationHasAReader — каждое `v_*`, которое материализация
// пишет на тип, обязано читаться каталогом, моделью или прод-кодом владельца типа.
//
// Гейт двусторонний:
//   - новая пара «пишем и никто не читает» → падение с координатой (тип + отношение);
//   - пара из `knownUnread`, которая перестала быть написанной ИЛИ обрела читателя →
//     падение как УСТАРЕВШЕЕ послабление (список истекает сам).
func TestEveryMaterializedVerbRelationHasAReader(t *testing.T) {
	root := monorepoRootForReaders(t)

	catalogReads := catalogRequiredRelations(t, root)
	modelDerived := modelInternalRelationRefs(t, root)
	serviceReads, filesScanned := ownerServiceRelationLiterals(t, root)

	require.NotEmpty(t, catalogReads, "каталог прав пуст — предпосылка гейта сломана")
	require.NotEmpty(t, modelDerived, "модель не разобрана — предпосылка гейта сломана")
	require.Positive(t, filesScanned, "не осмотрено ни одного прод-файла — предпосылка гейта сломана")

	// Написанный набор — из ТОЙ ЖЕ таблицы, что кормит эмиттер (не из литерала).
	type pair struct{ fgaType, relation string }
	var unread []pair
	checkedPairs, checkedTypes := 0, 0
	for _, e := range authzmap.Catalog() {
		fgaType, ok := authzmap.ObjectType(e.Module, e.Resource)
		if !ok {
			continue
		}
		rels := authzmap.VerbRelationsOfType(fgaType)
		if len(rels) == 0 {
			continue // неглагольный тип ничего пообъектного не пишет
		}
		checkedTypes++
		owner := ownerOfType(fgaType)
		require.NotEmptyf(t, owner, "тип %q не отнесён ни к одному сервису — читателя негде искать, "+
			"предикат ослеп бы на нём молча", fgaType)
		for _, rel := range rels {
			checkedPairs++
			if catalogReads[fgaType][rel] || modelDerived[fgaType][rel] || serviceReads[owner][rel] {
				continue
			}
			unread = append(unread, pair{fgaType, rel})
		}
	}

	// Сверяем найденное с зафиксированным — в ОБЕ стороны.
	got := map[string]map[string]bool{}
	for _, p := range unread {
		if got[p.relation] == nil {
			got[p.relation] = map[string]bool{}
		}
		got[p.relation][p.fgaType] = true
	}
	for rel, types := range got {
		known := map[string]bool{}
		for _, tp := range knownUnread[rel] {
			known[tp] = true
		}
		for tp := range types {
			require.Truef(t, known[tp],
				"НОВОЕ отношение без читателя: материализация пишет %q на %q, но его не читает "+
					"ни каталог прав, ни вывод модели, ни прод-код сервиса %q. Такой кортеж "+
					"оплачивается трижды — выводом, записью с дренажом и индексом под каждым "+
					"Check — и не участвует ни в одном решении о доступе. Либо у него должен "+
					"появиться читатель, либо его не должна писать материализация.",
				rel, tp, ownerOfType(tp))
		}
	}
	// Самоистечение: у каждой зафиксированной пары обязан остаться предмет.
	for rel, types := range knownUnread {
		for _, tp := range types {
			require.Truef(t, got[rel][tp],
				"УСТАРЕВШЕЕ послабление: пара (%q, %q) числится «пишем, никто не читает», но это "+
					"больше не так — она либо обрела читателя, либо перестала материализоваться. "+
					"Запись, которой нечего исключать, обязана быть снята здесь: иначе список "+
					"переживёт свой предмет и станет прикрывать следующую находку.", tp, rel)
		}
	}

	t.Logf("перепись: глагольных типов %d; пар (тип,отношение) %d; записей каталога %d; "+
		"прод-файлов сервисов осмотрено %d; без читателя %d",
		checkedTypes, checkedPairs, countCatalogEntries(t, root), filesScanned, len(unread))
}

// catalogRequiredRelations — отношения, которые край РЕАЛЬНО спрашивает, по типу
// объекта. Читается сгенерированный каталог — тот же артефакт, что энфорсит gateway.
func catalogRequiredRelations(t *testing.T, root string) map[string]map[string]bool {
	t.Helper()
	var entries []struct {
		RequiredRelation string `json:"required_relation"`
		ScopeExtractor   struct {
			ObjectType string `json:"object_type"`
		} `json:"scope_extractor"`
	}
	raw, err := os.ReadFile(filepath.Join(root, "gateway", "internal", "middleware", "embed", "permission_catalog.json"))
	require.NoError(t, err, "каталог прав недоступен — гейт обязан быть громким, а не пропущенным")
	require.NoError(t, json.Unmarshal(raw, &entries))
	out := map[string]map[string]bool{}
	for _, e := range entries {
		if e.RequiredRelation == "" || e.ScopeExtractor.ObjectType == "" {
			continue
		}
		if out[e.ScopeExtractor.ObjectType] == nil {
			out[e.ScopeExtractor.ObjectType] = map[string]bool{}
		}
		out[e.ScopeExtractor.ObjectType][e.RequiredRelation] = true
	}
	return out
}

func countCatalogEntries(t *testing.T, root string) int {
	t.Helper()
	var entries []json.RawMessage
	raw, err := os.ReadFile(filepath.Join(root, "gateway", "internal", "middleware", "embed", "permission_catalog.json"))
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, &entries))
	return len(entries)
}

// modelInternalRelationRefs — `v_*`, на которые ссылается определение ДРУГОГО
// отношения того же типа. Такое отношение читается косвенно через вывод модели.
func modelInternalRelationRefs(t *testing.T, root string) map[string]map[string]bool {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, "proto", "kacho", "cloud", "iam", "v1", "fga_model.fga"))
	require.NoError(t, err, "канонической модели нет — предпосылка гейта сломана")
	reType := regexp.MustCompile(`^type\s+(\S+)`)
	reDefine := regexp.MustCompile(`^define\s+(\w+)\s*:\s*(.*)$`)
	reDirect := regexp.MustCompile(`\[[^\]]*\]`)
	reVerbRef := regexp.MustCompile(`\bv_\w+\b`)
	out := map[string]map[string]bool{}
	cur := ""
	for _, line := range strings.Split(string(raw), "\n") {
		s := strings.TrimSpace(line)
		if strings.HasPrefix(s, "#") {
			continue
		}
		if m := reType.FindStringSubmatch(s); m != nil {
			cur = m[1]
			continue
		}
		m := reDefine.FindStringSubmatch(s)
		if m == nil || cur == "" {
			continue
		}
		// Прямые usersets в скобках — это ОБЪЯВЛЕНИЕ отношения, а не ссылка на другое.
		body := reDirect.ReplaceAllString(m[2], "")
		for _, ref := range reVerbRef.FindAllString(body, -1) {
			if ref == m[1] {
				continue // само себя не читает
			}
			if out[cur] == nil {
				out[cur] = map[string]bool{}
			}
			out[cur][ref] = true
		}
	}
	return out
}

// ownerServiceRelationLiterals — литералы `v_*` в НЕ-тестовом прод-коде каждого
// сервиса, БЕЗ файлов эмиссии (см. шапку). Возвращает также объём осмотренного,
// чтобы «ноль находок» было отличимо от «ноль прочитанного».
//
// Состав берётся у treecorpus, то есть у ИНДЕКСА ОТСЛЕЖИВАЕМЫХ файлов, а не обходом
// диска. Разница не косметическая: под `services/` на всякой машине, где поднимали
// стенд, лежат распаковки чартов и отчёты прогонов, — обход диска зачёл бы их в
// «осмотрено», а найденный в них литерал сошёл бы за читателя. Первая редакция
// ходила по диску, и это поймал tree-wide гейт TestTreeWalkersAskTheIndex.
func ownerServiceRelationLiterals(t *testing.T, root string) (map[string]map[string]bool, int) {
	t.Helper()
	skip := map[string]bool{}
	for _, f := range emissionSideFiles {
		abs := filepath.Join(root, f)
		_, err := os.Stat(abs)
		require.NoErrorf(t, err, "файл эмиссии %q не найден: предикат исключает несуществующее, "+
			"то есть перестал исключать писателя — а тогда писатель зачтётся за читателя", f)
		skip[abs] = true
	}
	servicesDir := filepath.Join(root, "services")
	files, err := treecorpus.UnderWithSuffix(servicesDir, ".go")
	require.NoError(t, err, "индекс отслеживаемых файлов под services/")

	out := map[string]map[string]bool{}
	scanned := 0
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") || skip[path] {
			continue
		}
		rel, rerr := filepath.Rel(servicesDir, path)
		require.NoError(t, rerr)
		svc, _, ok := strings.Cut(rel, string(filepath.Separator))
		if !ok {
			continue
		}
		body, rerr := os.ReadFile(path)
		require.NoError(t, rerr)
		scanned++
		for _, m := range reRelationLiteral.FindAllStringSubmatch(string(body), -1) {
			if out[svc] == nil {
				out[svc] = map[string]bool{}
			}
			out[svc][m[1]] = true
		}
	}
	return out, scanned
}

func monorepoRootForReaders(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	require.NoError(t, err)
	dir := wd
	// Корнем берётся САМЫЙ ВНЕШНИЙ `go.mod`, а не первый встречный: у службы
	// теперь СВОЙ модуль (она выносится отдельным репозиторием), и подъём «до
	// первого» останавливался бы в её каталоге. Пути, которые ниже склеиваются с
	// этим корнем, называют место В ДЕРЕВЕ МОНОРЕПО — от корня, — поэтому
	// остановка внутри службы удваивала сегмент и обход искал `services/iam/
	// services/iam/…`, которого не существует.
	outermost := ""
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			outermost = dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			if outermost != "" {
				return outermost
			}
			t.Fatalf("корень монорепо (go.mod) не найден от %s", wd)
		}
		dir = parent
	}
}
