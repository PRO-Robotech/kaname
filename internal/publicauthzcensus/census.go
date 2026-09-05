// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package publicauthzcensus переписывает ПУБЛИЧНЫЕ RPC iam по признаку
// «несёт ли путь обслуживания ПООБЪЕКТНЫЙ вопрос о доступе».
//
// # Зачем перепись, а не правило в прозе
//
// Дверь авторизации у iam сегодня держит КРАЙ: api-gateway проверяет JWT и
// задаёт пообъектный вопрос по записи каталога прав, а сам сервис на своих
// слушателях этот вопрос по большей части не повторяет. Код iam говорит это
// прямым текстом — «iam does NOT re-ReBAC the end user on its own listeners»
// (services/iam/cmd/kacho-iam/serve.go, оба слушателя).
//
// Пока iam стоит за нашим краем, это защитимо. Вынесенный в чужое облако iam
// края не имеет by construction, и каждый публичный RPC без собственного
// вопроса становится открытой дверью: аутентифицированный арендатор получает
// чужой объект. Перепись существует затем, чтобы остаток был назван ЧИСЛОМ, а
// не оценкой, и чтобы новый публичный RPC не заводился без двери молча.
//
// # Единица счёта — ПУБЛИЧНЫЙ RPC, а не файл и не вызов
//
// Файл обслуживает несколько RPC, а один RPC собирается из нескольких файлов,
// поэтому ни та, ни другая единица не отвечает на заданный вопрос. Счёт идёт по
// паре «служба/метод», взятой из контракта.
//
// # Публичность ВЫВОДИТСЯ из регистрации, а не из имени службы
//
// Признак «имя начинается с Internal» негоден: AuthorizeService зарегистрирована
// на ОБОИХ слушателях, и по имени она читалась бы как публичная лишь случайно, а
// InternalOperationsService — как внутренняя, тоже случайно. Перепись судит
// ИСХОД: службы берутся из тела registerPublicServices, то есть оттуда, где
// решение принято. Имя при этом не читается вовсе.
//
// # Законных форм вопроса ДВЕ, и знать надо обе
//
// Точечный путь (Get/Update/Delete/действие над названным объектом) спрашивает
// authzguard.AllowsVGet / AllowsVerb / RequireScopeRelation / IsSelf. Списочный
// путь спрашивает иначе — authzfilter.Visible / VisibleSet сужают СТРАНИЦУ
// построчно, и точечного вопроса там нет by construction. Распознаватель,
// знающий только первую форму, объявил бы семь списков дырами, будучи неверным
// ровно в ту сторону, которая дороже: находка, которой нет, обесценивает
// перепись целиком.
//
// # Категорий исхода ЧЕТЫРЕ, и две из них — не находки
//
//	gated     — путь обслуживания задаёт пообъектный вопрос. Норма;
//	decision  — RPC САМ отвечает на вопрос о доступе (AuthorizeService — это PDP
//	            платформы, PermissionCatalogService — её словарь). Спрашивать у
//	            такого RPC пообъектное разрешение на его собственный ответ значит
//	            требовать от двери, чтобы она открывалась ключом от себя же.
//	            НЕ находка, но и не молчание: категория названа, чтобы «сам себе
//	            PDP» нельзя было приписать обычному RPC незаметно;
//	selfonly  — путь спрашивает лишь тождество вызывающего (IsSelf) без обращения
//	            к модели прав. Для персональных ресурсов это законная дверь, для
//	            остальных — слабая; категория отделена, чтобы её нельзя было
//	            зачесть в gated молча;
//	ungated   — вопроса нет. Находка.
//
// # Разбор идёт по УЗЛАМ, а не по подстроке
//
// Имена вызовов встречаются в комментариях этого же дерева десятками (шапка
// самого authzguard объясняет AllowsVGet прозой), поэтому поиск по слову
// краснел бы на объяснении предмета. Здесь читается синтаксическое дерево, и
// вызовом считается только узел вызова.
package publicauthzcensus

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Category — исход по одному публичному RPC. Значения перечислены в шапке.
type Category string

const (
	// CategoryDoor — вопрос об объекте задаёт СОБСТВЕННАЯ ДВЕРЬ iam: у RPC есть
	// пообъектная запись выведенной карты прав (отношение + извлечение области),
	// и звено спрашивает модель перед обработчиком.
	CategoryDoor Category = "door"
	// CategoryDataAuthorized — RPC авторизуется ПО ДАННЫМ: карта помечает его
	// scope_filtered (единичный вопрос семантически неверен — он отверг бы весь
	// вызов до того, как отработает сужение страницы), и путь обслуживания
	// действительно сужает страницу построчно.
	CategoryDataAuthorized Category = "data"
	// CategoryExempt — контракт объявил RPC освобождённым от пообъектного вопроса
	// (`<exempt>`). НЕ находка — это записанное решение, — но и не молчание:
	// категория печатается числом и перечнем, потому что на вынесенном iam
	// освобождённые RPC и есть вся оставшаяся поверхность без двери.
	CategoryExempt Category = "exempt"
	// CategoryUngated — двери нет: ни записи в карте, ни сужения по данным там,
	// где карта его требует. Находка.
	CategoryUngated Category = "ungated"
)

// RPC — пара «служба/метод» из контракта. Единица счёта переписи.
type RPC struct {
	Service string
	Method  string
}

// String печатает RPC в форме, которой пользуется ведомость и текст находки.
func (r RPC) String() string { return r.Service + "/" + r.Method }

// Verdict — исход по одному публичному RPC вместе с координатой, по которой его
// можно проверить руками.
type Verdict struct {
	RPC RPC
	// Category — исход. См. константы выше.
	Category Category
	// Package — каталог пакета, обслуживающего RPC, относительно корня дерева.
	// Пуст, если обслуживающий пакет не разрешился (Unresolved).
	Package string
	// ExemptReason — причина освобождения, объявленная контрактом
	// (`exempt_reason`). Непуста только у освобождённых RPC.
	ExemptReason string
	// Evidence — имя вызова, по которому вынесен исход gated/selfonly. Пусто у
	// остальных категорий.
	Evidence string
}

// Census — итог обхода. Печатается целиком: «ноль находок» обязано быть отличимо
// от «ноль прочитанного», поэтому объём осмотренного здесь не одно число, а все
// величины сразу.
type Census struct {
	// ProtoFiles — файлов контракта прочитано.
	ProtoFiles int
	// RPCsDeclared — RPC объявлено контрактом всего (публичных и внутренних).
	RPCsDeclared int
	// ServicesPublic — служб зарегистрировано на публичном слушателе.
	ServicesPublic int
	// Inspected — публичных RPC осмотрено. Знаменатель переписи.
	Inspected int
	// GoFiles — не-тестовых файлов Go разобрано в обслуживающих пакетах.
	GoFiles int
	// MapEntries — записей в карте прав, ВЫВЕДЕННОЙ из аннотаций контракта той
	// же функцией, которой её выводит собственная дверь. Ноль означает, что
	// карта не собралась, и тогда о двери не известно НИЧЕГО: вердикт
	// беспредметен, а не чист.
	MapEntries int
	// Verdicts — исход по каждому осмотренному RPC, отсортировано по имени.
	Verdicts []Verdict
	// Unresolved — публичные RPC, чей обслуживающий пакет или метод не
	// разрешился. НЕ находка и НЕ норма: это «не выполнилось», третья
	// категория. Молча зачесть их в любую сторону значило бы выдать незнание за
	// вердикт.
	Unresolved []RPC
}

// Count возвращает число RPC в названной категории.
func (c Census) Count(cat Category) int {
	n := 0
	for _, v := range c.Verdicts {
		if v.Category == cat {
			n++
		}
	}
	return n
}

// InCategory возвращает RPC названной категории, отсортированные по имени.
func (c Census) InCategory(cat Category) []RPC {
	var out []RPC
	for _, v := range c.Verdicts {
		if v.Category == cat {
			out = append(out, v.RPC)
		}
	}
	return out
}

// Summary — строка переписи для вывода теста. Печатает ОБЕ величины по каждой
// оси: одно число скрывает ровно тот случай, ради которого перепись заведена.
func (c Census) Summary() string {
	return fmt.Sprintf(
		"перепись: файлов контракта %d · RPC объявлено %d · служб публичных %d · "+
			"публичных RPC осмотрено %d · файлов Go разобрано %d · записей карты прав %d · "+
			"за СОБСТВЕННОЙ дверью %d · авторизуются по данным %d · освобождены контрактом %d · "+
			"БЕЗ двери %d · не разрешилось %d",
		c.ProtoFiles, c.RPCsDeclared, c.ServicesPublic, c.Inspected, c.GoFiles, c.MapEntries,
		c.Count(CategoryDoor), c.Count(CategoryDataAuthorized),
		c.Count(CategoryExempt), c.Count(CategoryUngated), len(c.Unresolved))
}

// pageNarrowingCalls — вызовы, сужающие СТРАНИЦУ построчно.
//
// Спрашиваются только у полосы `scope_filtered`. На ней единичный вопрос об
// объекте семантически неверен — он отверг бы весь вызов ДО того, как сужение
// отработает, — поэтому дверь его намеренно не задаёт, и авторизацию обязан
// произвести сам путь обслуживания. Здесь проверяется, что он её производит.
//
// Точечная форма (`AllowsVGet` и родня) в этот перечень НЕ входит: точечный
// вопрос теперь задаёт дверь на входе, и требовать его второй раз внутри
// значило бы держать два места об одном предмете. Собственные точечные стражи
// iam при этом остаются и работают — они защита в глубину, а не замена двери.
//
// Перечень закрыт намеренно: форма, о которой распознаватель не знает, даёт не
// красное и не зелёное, а молчание — и всё, записанное в ней, уходит из-под
// наблюдения. Замер по дереву (`git grep -lE 'authzfilter\.(Visible|VisibleSet)\('
// -- 'services/iam/**/*.go'` без проб) — 7 файлов, все в каталогах api/<ресурс>.
var pageNarrowingCalls = map[string]string{
	"authzfilter.Visible":    "сужение страницы",
	"authzfilter.VisibleSet": "сужение страницы",
}

// Сверх-гейт администратора кластера (`SubjectIsClusterAdminE` и родня) в этот
// перечень НЕ входит, и это решение, а не пропуск.
//
// Он спрашивает «ты ли администратор всего», то есть даёт РАННЕЕ РАЗРЕШЕНИЕ, а
// не сужает выдачу. Путь, который только его и задаёт, отдаёт постороннему всё
// — ровно то, что перепись ищет. Первая редакция засчитала его за дверь, и цена
// была измерена немедленно: у девяти списков он ЗАТМИЛ настоящее свидетельство
// (`authzfilter.VisibleSet` сменился на него в выводе, потому что обход
// останавливается на первой найденной форме), а два RPC перешли из находок в
// норму, ничего не изменив в коде. Признак был виден только сравнением ДВУХ
// переписей до и после расширения — само число «БЕЗ двери 0» выглядело
// достижением.

// relationPortQuestion — ТРЕТЬЯ законная форма вопроса, и распознаватель обязан
// знать её наравне с двумя выше.
//
// Часть путей спрашивает модель НАПРЯМУЮ через свой порт отношений, не заходя
// ни в общий фильтр страницы, ни в помощников authzguard: `AuthorizeService`
// именно так и сверяет полномочие вызывающего на запрошенном объекте
// (`h.authority.Check(ctx, subject, relation, object)`), и это полноценная
// дверь, а не её отсутствие.
//
// Распознаётся ЧИСЛОМ АРГУМЕНТОВ, а не именем приёмника: имя поля у порта своё
// в каждом пакете (`authority`, `relations`, `relationQueries`), и перечень имён
// был бы тем местом, которое забывают дополнить. Вопрос к модели опознаётся по
// форме `Check(ctx, субъект, отношение, объект)` — ровно четыре аргумента;
// соседний `Check(ctx, запрос)` use-case-слоя под неё не подпадает и потому не
// засчитывается за дверь.
//
// Цена незнания этой формы измерена: без неё перепись называла находками пять
// RPC, у трёх из которых дверь есть, — то есть 3 ложные находки из 5. Инструмент
// с такой долей перестают читать, и вместе с ним перестают видеть настоящие две.
const relationPortQuestion = "Check"

// relationPortArgs — число аргументов вопроса к модели: контекст, субъект,
// отношение, объект.
const relationPortArgs = 4

// Collect обходит дерево от root и возвращает перепись.
//
// Ошибка возвращается только там, где обход НЕВОЗМОЖЕН (нет контракта, нет
// точки регистрации). Пустой обход ошибкой не является — он является пустым
// обходом, и вызывающий обязан на нём падать сам: «беспредметно» и «чисто»
// различает он, а не эта функция.
func Collect(root string) (Census, error) {
	return CollectFrom(
		filepath.Join(root, "proto", "kacho", "cloud", "iam", "v1"),
		filepath.Join(root, "services", "iam", "cmd", "kacho-iam"),
		root,
	)
}

// CollectFrom — тот же обход с явно названными источниками.
//
// Существует ради ДОКАЗАТЕЛЬСТВА способности гейта упасть: инъекция подаёт
// синтетический контракт и синтетическую точку регистрации, оставляя карту прав
// настоящей. Карту подменить нельзя by construction — она выводится из
// дескрипторов, влинкованных в процесс, — и это правильно: инъекция обязана
// менять РОВНО ОДИН факт, а именно наличие двери у подаваемого RPC.
func CollectFrom(protoDir, cmdDir, root string) (Census, error) {
	var c Census

	rpcs, protoFiles, err := declaredRPCs(protoDir)
	if err != nil {
		return c, fmt.Errorf("контракт iam: %w", err)
	}
	c.ProtoFiles = protoFiles
	for _, methods := range rpcs {
		c.RPCsDeclared += len(methods)
	}

	publicSvcs, err := publicServiceFields(cmdDir)
	if err != nil {
		return c, fmt.Errorf("точка регистрации: %w", err)
	}
	c.ServicesPublic = len(publicSvcs)

	fieldPkg, err := handlerPackages(cmdDir)
	if err != nil {
		return c, fmt.Errorf("сборка сервисов: %w", err)
	}

	svcNames := make([]string, 0, len(publicSvcs))
	for svc := range publicSvcs {
		svcNames = append(svcNames, svc)
	}
	sort.Strings(svcNames)

	reasons, err := exemptReasons()
	if err != nil {
		return c, err
	}

	door, err := doorCoverage()
	if err != nil {
		return c, fmt.Errorf("карта прав собственной двери: %w", err)
	}
	c.MapEntries = len(door)

	pkgCache := map[string]*pkgIndex{}
	for _, svc := range svcNames {
		methods := rpcs[svc]
		sort.Strings(methods)
		field := publicSvcs[svc]
		importPath, okPkg := fieldPkg[field]
		var idx *pkgIndex
		if okPkg {
			if cached, hit := pkgCache[importPath]; hit {
				idx = cached
			} else {
				dir := packageDir(root, importPath)
				loaded, files, lerr := indexPackage(dir)
				if lerr == nil {
					c.GoFiles += files
					idx = loaded
					pkgCache[importPath] = loaded
				}
			}
		}
		relPkg := ""
		if okPkg {
			// Тот же вопрос, что у packageDir: путь дерева по пути импорта.
			relPkg = treeRelOfPackage(importPath)
		}
		for _, m := range methods {
			c.Inspected++
			rpc := RPC{Service: svc, Method: m}
			kind, known := door[rpc]
			if !known {
				// Карта тотальна над названными пакетами, поэтому отсутствие
				// записи означает, что RPC не покрыт дверью ВООБЩЕ, — находка,
				// а не умолчание.
				c.Verdicts = append(c.Verdicts, Verdict{
					RPC: rpc, Category: CategoryUngated, Package: relPkg,
					Evidence: "записи в выведенной карте прав нет",
				})
				continue
			}
			// Ветвление по ИМЕНИ полосы, а не по значению: у вердикта карты есть
			// поле свидетельства, и сравнение структур целиком не совпало бы ни
			// с одной ветвью — RPC исчезал бы из переписи молча, при растущем
			// знаменателе. Так и было в первой редакции: 60 из 78 не попадали
			// ни в одну категорию, а строка итога выглядела правдоподобно.
			switch kind.name {
			case doorObjectScoped.name:
				c.Verdicts = append(c.Verdicts, Verdict{
					RPC: rpc, Category: CategoryDoor, Package: relPkg,
					Evidence: kind.evidence,
				})
			case doorExempt.name:
				// Освобождение — не молчание: у него обязан быть решатель на
				// пути обслуживания, и какой именно, задаёт объявленная
				// причина. Разбор — exempt.go.
				reason := reasons[rpc]
				if reason == reasonInternalListener {
					// Контракт заявил ВНУТРЕННИЙ слушатель, регистрация —
					// публичный. Это либо ban #6, либо неверная причина; ни то,
					// ни другое не снимается никаким решателем.
					c.Verdicts = append(c.Verdicts, Verdict{
						RPC: rpc, Category: CategoryUngated, Package: relPkg,
						ExemptReason: reason,
						Evidence: "контракт освободил RPC признаком ВНУТРЕННЕГО слушателя (`" +
							reason + "`), а зарегистрирован он на ПУБЛИЧНОМ",
					})
					continue
				}
				matcher, knownReason := matcherForReason(reason)
				if !knownReason {
					// Причина не названа либо перечню неизвестна: вердикта по
					// такому RPC нет ни в одну сторону.
					c.Unresolved = append(c.Unresolved, rpc)
					continue
				}
				if idx == nil {
					c.Unresolved = append(c.Unresolved, rpc)
					continue
				}
				deciderEvidence, deciderResolved := idx.findOnServingPath(m, matcher)
				if !deciderResolved {
					c.Unresolved = append(c.Unresolved, rpc)
					continue
				}
				if deciderEvidence == "" {
					c.Verdicts = append(c.Verdicts, Verdict{
						RPC: rpc, Category: CategoryUngated, Package: relPkg,
						ExemptReason: reason,
						Evidence: "освобождение `" + reason + "` объявлено, а решателя " +
							"требуемой им формы на пути обслуживания нет",
					})
					continue
				}
				c.Verdicts = append(c.Verdicts, Verdict{
					RPC: rpc, Category: CategoryExempt, Package: relPkg,
					ExemptReason: reason,
					Evidence:     deciderEvidence + "; освобождение `" + reason + "`",
				})
			case doorScopeFiltered.name:
				// Дверь единичного вопроса тут не задаёт намеренно — значит его
				// обязан задать путь обслуживания, построчно по странице.
				if idx == nil {
					c.Unresolved = append(c.Unresolved, rpc)
					continue
				}
				evidence, resolved := idx.narrowsPage(m)
				if !resolved {
					c.Unresolved = append(c.Unresolved, rpc)
					continue
				}
				if evidence == "" {
					c.Verdicts = append(c.Verdicts, Verdict{
						RPC: rpc, Category: CategoryUngated, Package: relPkg,
						Evidence: "карта объявила авторизацию по данным, а страница не сужается",
					})
					continue
				}
				c.Verdicts = append(c.Verdicts, Verdict{
					RPC: rpc, Category: CategoryDataAuthorized, Package: relPkg,
					Evidence: evidence,
				})
			default:
				// Полоса, о которой перепись не знает. Не норма и не находка —
				// «не выполнилось»: вердикта по такому RPC нет, и молчание о нём
				// было бы выдачей незнания за покрытие.
				c.Unresolved = append(c.Unresolved, rpc)
			}
		}
	}
	sort.Slice(c.Verdicts, func(i, j int) bool {
		return c.Verdicts[i].RPC.String() < c.Verdicts[j].RPC.String()
	})
	sort.Slice(c.Unresolved, func(i, j int) bool {
		return c.Unresolved[i].String() < c.Unresolved[j].String()
	})
	return c, nil
}

// МОДУЛЕЙ В ДЕРЕВЕ ДВА, И ОТОБРАЖЕНИЕ ОБЯЗАНО ЗНАТЬ ОБА.
//
// Служба несёт свой `go.mod` (`github.com/PRO-Robotech/kacho-iam`) — она
// выносится отдельным репозиторием. Отрезание ОДНОГО префикса перестало
// переводить путь импорта в путь дерева: для собственных пакетов службы
// `TrimPrefix` не срабатывал вовсе, путь оставался целым, каталог не находился,
// и перепись честно печатала «файлов Go разобрано 0». Это не находка и не
// чистота — это пустой обход, и падать на нём обязан вызывающий.
const (
	rootModulePrefix    = "github.com/PRO-Robotech/kacho/"
	serviceModulePrefix = "github.com/PRO-Robotech/kacho-iam/"
	serviceTreePrefix   = "services/iam/"
)

// treeRelOfPackage — путь пакета В ДЕРЕВЕ (от корня монорепо) по пути импорта.
func treeRelOfPackage(importPath string) string {
	if rel, ok := strings.CutPrefix(importPath, serviceModulePrefix); ok {
		return serviceTreePrefix + rel
	}
	return strings.TrimPrefix(importPath, rootModulePrefix)
}

func packageDir(root, importPath string) string {
	return filepath.Join(root, filepath.FromSlash(treeRelOfPackage(importPath)))
}

// --- контракт -------------------------------------------------------------

var (
	reService = regexp.MustCompile(`^service\s+([A-Za-z][A-Za-z0-9_]*)\s*\{`)
	reRPC     = regexp.MustCompile(`^\s*rpc\s+([A-Za-z][A-Za-z0-9_]*)\s*\(`)
)

// declaredRPCs читает контракт и возвращает служба → методы.
//
// Комментарии снимаются ДО разбора: слово rpc стоит в объяснениях этого же
// дерева, и счёт по сырой строке завысил бы знаменатель переписи — то есть
// сделал бы покрытие хуже, чем оно есть, на величину собственной прозы.
func declaredRPCs(dir string) (map[string][]string, int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, 0, err
	}
	out := map[string][]string{}
	files := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".proto") {
			continue
		}
		// #nosec G304 -- e пришло из os.ReadDir(dir) строкой выше: e.Name() есть имя
		// записи ЭТОГО каталога и сепаратора не содержит by construction, поэтому
		// join за dir не выходит. Каталог контракта задаёт вызывающий.
		body, rerr := os.ReadFile(filepath.Join(dir, e.Name()))
		if rerr != nil {
			return nil, 0, rerr
		}
		files++
		svc := ""
		for _, line := range strings.Split(stripProtoComments(string(body)), "\n") {
			if m := reService.FindStringSubmatch(line); m != nil {
				svc = m[1]
				continue
			}
			if strings.HasPrefix(line, "}") {
				svc = ""
				continue
			}
			if svc == "" {
				continue
			}
			if m := reRPC.FindStringSubmatch(line); m != nil {
				out[svc] = append(out[svc], m[1])
			}
		}
	}
	if files == 0 {
		return nil, 0, fmt.Errorf("в %s нет файлов контракта", dir)
	}
	return out, files, nil
}

// stripProtoComments снимает // и /* */ вне строковых литералов.
func stripProtoComments(src string) string {
	var b strings.Builder
	b.Grow(len(src))
	inLine, inBlock, inStr := false, false, false
	for i := 0; i < len(src); i++ {
		ch := src[i]
		switch {
		case inLine:
			if ch == '\n' {
				inLine = false
				b.WriteByte(ch)
			}
		case inBlock:
			if ch == '*' && i+1 < len(src) && src[i+1] == '/' {
				inBlock = false
				i++
			} else if ch == '\n' {
				b.WriteByte(ch)
			}
		case inStr:
			b.WriteByte(ch)
			if ch == '\\' && i+1 < len(src) {
				i++
				b.WriteByte(src[i])
			} else if ch == '"' {
				inStr = false
			}
		default:
			switch {
			case ch == '"':
				inStr = true
				b.WriteByte(ch)
			case ch == '/' && i+1 < len(src) && src[i+1] == '/':
				inLine = true
				i++
			case ch == '/' && i+1 < len(src) && src[i+1] == '*':
				inBlock = true
				i++
			default:
				b.WriteByte(ch)
			}
		}
	}
	return b.String()
}

// --- точка регистрации ----------------------------------------------------

// publicServiceFields читает тело registerPublicServices и возвращает
// служба → имя поля сборки, на котором она зарегистрирована.
//
// Судится ИСХОД: то, что зарегистрировано на публичном слушателе, публично —
// независимо от того, как служба названа.
func publicServiceFields(cmdDir string) (map[string]string, error) {
	fset := token.NewFileSet()
	files, err := parseDirFiles(fset, cmdDir)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	found := false
	for _, f := range files {
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Name.Name != "registerPublicServices" || fn.Body == nil {
				continue
			}
			found = true
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, isCall := n.(*ast.CallExpr)
				if !isCall {
					return true
				}
				sel, isSel := call.Fun.(*ast.SelectorExpr)
				if !isSel {
					return true
				}
				svc, okName := serviceFromRegister(sel.Sel.Name)
				if !okName || len(call.Args) < 2 {
					return true
				}
				if field, okField := servicesField(call.Args[1]); okField {
					out[svc] = field
				}
				return true
			})
		}
	}
	if !found {
		return nil, fmt.Errorf("в %s не найдена registerPublicServices", cmdDir)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("registerPublicServices не регистрирует ни одной службы")
	}
	return out, nil
}

// serviceFromRegister превращает RegisterXServiceServer → XService.
func serviceFromRegister(name string) (string, bool) {
	if !strings.HasPrefix(name, "Register") || !strings.HasSuffix(name, "ServiceServer") {
		return "", false
	}
	mid := strings.TrimSuffix(strings.TrimPrefix(name, "Register"), "ServiceServer")
	if mid == "" {
		return "", false
	}
	return mid + "Service", true
}

// servicesField достаёт имя поля из выражения вида svcs.projectHandler.
func servicesField(arg ast.Expr) (string, bool) {
	sel, ok := arg.(*ast.SelectorExpr)
	if !ok {
		return "", false
	}
	if ident, isIdent := sel.X.(*ast.Ident); !isIdent || ident.Name != "svcs" {
		return "", false
	}
	return sel.Sel.Name, true
}

// handlerPackages читает объявление структуры services и возвращает
// поле → путь импорта пакета, чей тип в этом поле лежит.
func handlerPackages(cmdDir string) (map[string]string, error) {
	fset := token.NewFileSet()
	files, err := parseDirFiles(fset, cmdDir)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, f := range files {
		aliases := importAliases(f)
		for _, decl := range f.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.TYPE {
				continue
			}
			for _, spec := range gen.Specs {
				ts, isTS := spec.(*ast.TypeSpec)
				if !isTS || ts.Name.Name != "services" {
					continue
				}
				st, isStruct := ts.Type.(*ast.StructType)
				if !isStruct {
					continue
				}
				for _, field := range st.Fields.List {
					alias, okAlias := selectorPackage(field.Type)
					if !okAlias {
						continue
					}
					path, okPath := aliases[alias]
					if !okPath {
						continue
					}
					for _, nm := range field.Names {
						out[nm.Name] = path
					}
				}
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("в %s не найдено объявление services с полями-обработчиками", cmdDir)
	}
	return out, nil
}

func importAliases(f *ast.File) map[string]string {
	out := map[string]string{}
	for _, imp := range f.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			continue
		}
		alias := path[strings.LastIndex(path, "/")+1:]
		if imp.Name != nil {
			alias = imp.Name.Name
		}
		out[alias] = path
	}
	return out
}

// selectorPackage достаёт алиас пакета из типа вида *projectapp.Handler.
func selectorPackage(t ast.Expr) (string, bool) {
	if star, ok := t.(*ast.StarExpr); ok {
		t = star.X
	}
	sel, ok := t.(*ast.SelectorExpr)
	if !ok {
		return "", false
	}
	ident, ok := sel.X.(*ast.Ident)
	if !ok {
		return "", false
	}
	return ident.Name, true
}

// parseDirFiles — не-тестовые файлы Go каталога, разобранные.
//
// Замена `parser.ParseDir`, снятой с поддержки. Она группирует файлы по ПАКЕТАМ,
// а группировка здесь не читается ни одним вызывающим: все три обходят
// `pkg.Files` плоско. Заодно уходит недетерминизм — порядок обхода карты пакетов
// в Go случаен, а `os.ReadDir` отдаёт имена отсортированными, и вход проверки
// становится воспроизводимым.
//
// Фильтр тестовых файлов — тот же, что был у снятого вызова: разбор судит
// прод-код, и проба, лежащая рядом, его утверждением не является.
func parseDirFiles(fset *token.FileSet, dir string) ([]*ast.File, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	out := make([]*ast.File, 0, len(entries))
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, perr := parser.ParseFile(fset, filepath.Join(dir, name), nil, parser.SkipObjectResolution)
		if perr != nil {
			return nil, perr
		}
		out = append(out, f)
	}
	return out, nil
}
