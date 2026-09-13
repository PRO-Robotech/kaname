// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// quota_authority_retired.go — АВТОРИТЕТ ВЕЛИЧИН УШЁЛ ИЗ СЛУЖБЫ ДОСТУПА ЦЕЛИКОМ.
//
// Задача продукта `PRO-Robotech/kacho#2117`, приёмка `KAN-QUOTA-1`, стадия S4,
// сценарии `KAN-Q4-08`, `KAN-Q4-10`, `KAN-Q4-14`; условие готовности `DoD S4`
// пп. 1, 13.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ — ОТСУТСТВИЕ, А НЕ ПРИСУТСТВИЕ, И ПОТОМУ ГЕЙТ НУЖЕН ОСОБЕННО
//
// Проверка, ищущая ОТСУТСТВИЕ формы, на исчезнувшем предмете замолкает: её
// образец не совпадёт больше никогда, обход и перепись целы, вердикт зелёный.
// Отличить это от исправной работы можно только переписью ОБЪЁМА: «находок
// ноль» и «прочитано ноль» обязаны быть разными вердиктами, и оба напечатаны.
//
// Предмет разбора — ВОЗВРАТ: авторитет величин, заведённый заново в службе, чей
// продукт отвечает «кому что разрешено», а не «сколько чего можно завести».
//
// ─────────────────────────────────────────────────────────────────────────────
// РАЗБОР СУДИТ УЗЕЛ-ИДЕНТИФИКАТОР, А НЕ ТЕКСТ — И ЭТО НЕСУЩЕЕ
//
// Гейт по подстроке краснел бы на СОБСТВЕННОМ объяснении: перечень снятых имён
// стоит в этом же файле, а надгробие снятого метода — в `authzguard`. Проверка,
// судящая ТЕКСТ, не отличает исполняемую часть от комментария, который эту же
// часть объясняет, — и снимают её первой, как непонятную.
//
// Поэтому ось прод-кода разбирает файл `go/parser`-ом и судит ТОЛЬКО узлы
// `*ast.Ident`. Комментарий, строковый литерал и запись о снятом предмете под
// неё не подпадают by construction — и это намеренно: снятое называется в
// отрицательной форме, надгробием, а не стирается молча. Читатель, пришедший за
// методом, которого больше нет, обязан узнать, что его СНЯЛИ, а не решить, что
// он ищет не там.
//
// Ось контракта разбирает СТРОКУ ОБЪЯВЛЕНИЯ (`service` / `message` / `enum` /
// `rpc` в начале строки).
//
// Отступ в образцах записан `[ \t]`, а НЕ `[[:space:]]`, и это не придирка:
// второй класс включает перевод строки, поэтому совпадение начиналось на строку
// РАНЬШЕ объявления и находка называла чужую координату. Поймала это инъекция, а
// не чтение: сам факт находки был верен, неверно было место — то есть гейт
// послал бы читателя искать не туда. `.proto` не разбирается тем же парсером, но объявление
// от комментария отличимо: комментарий начинается с `//`, а объявление — с
// ключевого слова. Граница названа честно: объявление, записанное внутри
// многострочного комментария `/* */`, разбору невидимо.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ПРЕДИКАТ ПО СЛОВУ `limit` ОТВЕРГНУТ — ЭТО ИЗМЕРЕНО, А НЕ ВЫБРАНО
//
// Прежняя редакция условия снятия #2117 считала слово `limit` в контракте и была
// НЕДОСТИЖИМА by construction (`kacho#2457`): под неё попадали имя поля размера
// страницы (`int32 limit = 2`), предел веерного ответа и проза об учёте у
// владельцев. Чтобы предикат дал ноль, пришлось бы снять имя поля страницы —
// ломающее изменение, к величинам отношения не имеющее.
//
// Здесь предмет назван ИМЕНЕМ АВТОРИТЕТА, а не словом: закрытый перечень снятых
// символов и объявления, чьё имя несёт `Limit`. Поле `limit` объявлением не
// является и разбору невидимо.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЗАКОННЫЙ ОСТАТОК НАЗВАН ПОИМЁННО — ИНАЧЕ ГЕЙТ ПОТРЕБОВАЛ БЫ РАСШИРЕНИЯ ПОВЕРХНОСТИ
//
// Из службы уходит АВТОРИТЕТ величин. НЕ уходят три вещи, и каждая обязана
// молчать под всеми осями:
//
//	`LimitKind` и словарь посадки  три собственных потолка службы берут величину
//	                              из посадки (`П25`, `KAN-Q3-01`); снять их
//	                              значило бы оставить самостоятельную установку
//	                              без ограничения на число аккаунтов и
//	                              удостоверений — расширение поверхности, не
//	                              названное ни в одном артефакте;
//	`IdentityQuotaService`,       арендаторское чтение СВОЕГО потолка; переехало
//	`Quota`                       в контракт службы решением `Д9` именно затем,
//	                              чтобы пережить уход модуля;
//	предел СКОРОСТИ приёма        защита от злоупотребления, а не потолок
//	                              количества; слово «квота» в её отказе —
//	                              совпадение написания.
//
// Ни одно из трёх в перечень снятых имён не входит, и каждое стоит законным
// близнецом в инъекции (`quota_authority_retired_injection_test.go`): без второй
// половины «находок нет» было бы неотличимо от «разбор не смотрит».
package check

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"regexp"
	"sort"
	"strings"
)

// retiredAuthoritySymbols — ЗАКРЫТЫЙ перечень имён, которыми служба называла
// авторитет величин.
//
// Перечень, а не образец по слову: `LimitKind` остаётся жить, `LimitScope` —
// нет, и различить их может только имя целиком. Сопоставление идёт по РАВЕНСТВУ
// имени узла, а не по вхождению подстроки, поэтому `CountableKind` не ловит
// `CountableKindOfPosture`, буде такой заведут, — и это верно: гейт судит то,
// что снято, а не то, что похоже.
var retiredAuthoritySymbols = []string{
	// контракт авторитета
	"InternalLimitService",
	"LimitService",
	"EffectiveLimit",
	"LimitChange",
	"CreateLimitMetadata",
	"UpdateLimitMetadata",
	"DeleteLimitMetadata",
	"ResolveLimitsRequest",
	"ResolveLimitsResponse",
	"ListChangedLimitsRequest",
	"ListChangedLimitsResponse",
	// домен авторитета
	"LimitID",
	"LimitScope",
	"LimitCarrier",
	"LimitFilter",
	"ResolveEffective",
	// закрытый каталог видов (`Д8`, `DoD S4` п. 13)
	"CountableKind",
	"countableKinds",
	"CountableEntries",
	"CountableKinds",
	"CountableKindsOfService",
	"CarrierOfKind",
	"IsCountableKind",
	"AuthorityStatedKinds",
	// хранилище авторитета
	"LimitRepo",
	"NewLimitRepo",
}

// keptAuthorityNeighbours — имена, которые на вид похожи на снятые и ОСТАЮТСЯ.
//
// Перечень существует не для разбора (он сопоставляет по равенству и этих имён
// не содержит), а для ПЕРЕПИСИ: сколько раз законный сосед прочитан. Число
// печатается рядом с находками, чтобы «ноль находок» было отличимо от «ось
// смотрит не туда»: если соседи прочитаны ноль раз, разбор не дошёл до файлов,
// где живёт остаток, и его ноль ничего не значит.
var keptAuthorityNeighbours = []string{
	"LimitKind",
	"PostureStatedKinds",
	"IsPostureStatedKind",
	"IdentityQuotaService",
	"OwnCeilingKnobs",
	"OwnCeilingRepo",
}

// countableCatalogueDecl — объявление закрытого каталога видов.
//
// Отдельной осью, а не только именем в перечне выше: условие готовности `DoD S4`
// п. 13 называет ИМЕННО объявление — «файл может уехать, а объявление остаться».
// Образец экранирован, поэтому собственного текста не ловит by construction.
var countableCatalogueDecl = regexp.MustCompile(`(?m)^var countableKinds = \[\]CountableKind\{`)

// authorityContractDecl — объявление контракта, чьё имя несёт `Limit`.
//
// `Quota` под образец НЕ входит намеренно: `IdentityQuotaService`, `Quota` и
// `ListIdentityQuotas*` остаются жить, и предикат, ловящий их, отвергал бы
// верную работу.
var authorityContractDecl = regexp.MustCompile(`(?m)^[ \t]*(service|message|enum|rpc)[ \t]+([A-Za-z][A-Za-z0-9_]*)`)

// quotaReaderRelationDecl — объявление отношения «читатель пределов».
//
// Отношение заведено РАДИ двух глаголов авторитета (`Resolve`,
// `ListChangedSince`). Со снятием глаголов оно не становится безобидным: право,
// которое выдаётся и ничего не даёт, есть поверхность без предмета — его выдают,
// перечисляют в ведомостях и отзывают, и ни одно из трёх действий ни на что не
// влияет.
var quotaReaderRelationDecl = regexp.MustCompile(`(?m)^[ \t]*define[ \t]+quota_reader[ \t]*:`)

// AuthorityResidueLedger — ОТНОШЕНИЯ МОДЕЛИ ПРАВ, снятие которых этой стадии не
// принадлежит. Ключ — имя отношения, значение — причина И предикат снятия.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ВЕДОМОСТЬ, А НЕ СНЯТИЕ ОСИ
//
// Ось модели прав завести и тут же обезвредить значило бы подогнать предикат под
// результат. Ведомость делает обратное: предмет назван, причина записана, а
// запись ИСТЕКАЕТ САМА — отношение ушло из модели, и запись становится находкой
// в тот же прогон. Ось при этом продолжает ловить ВСЯКОЕ другое отношение
// авторитета, буде такое заведут.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ЭТО НЕ ОТСРОЧКА, А ДРУГОЙ ПРЕДМЕТ — ИЗМЕРЕНО, А НЕ ОБЪЯВЛЕНО
//
// Снятие `quota_reader` есть ОТЗЫВ ВЫДАННОГО ПРАВА, а не снятие кода, и его цена
// лежит в трёх местах, ни одно из которых этой полосе не принадлежит:
//
//  1. право ВЫДАНО ПРИМЕНЁННОЙ миграцией `0001_initial.sql` — четыре строки в
//     четырёх таблицах (выдача, её кортеж, событие очереди, факт отношения) плюс
//     группа-получатель `module-quota-readers`. Применённую не правят: отзыв
//     идёт НОВОЙ миграцией, и у неё свой предмет — снятие системной выдачи;
//  2. каталог прав ТРЕБУЕТ это отношение двумя записями, а его единственный
//     писатель — копия КРАЯ в репозитории платформы: своя копия обязана
//     совпадать с ней побайтово, и правка здесь развела бы две копии;
//  3. снятие права доводится до ДЕЙСТВУЮЩЕЙ модели, а не до её объявления:
//     нужны чеканка нового идентификатора модели и перекат служб на него, то
//     есть поднятый стенд. Изменение дерева этого не производит.
//
// Отношение при этом БЕЗВРЕДНО в промежутке: глаголов, которые его требовали, в
// службе больше нет, и выдать его — значит выдать доступ к методам, которых не
// существует.
//
// Предмет заведён задачей `kaname#59` с признаком, числами и предикатом снятия.
// Второй остаток стадии — хранилище авторитета (таблица, три функции и два
// триггера на чужих таблицах) — задача `kaname#58`: разбор этой оси его НЕ
// покрывает, потому что судит имена в коде и объявления контракта, а не схему.

var AuthorityResidueLedger = map[string]string{
	"quota_reader": "право читать действующие пределы; глаголы, его требовавшие, сняты " +
		"стадией S4, но само право ВЫДАНО применённой миграцией 0001_initial.sql " +
		"(4 строки + группа-получатель) и ТРЕБУЕТСЯ двумя записями каталога прав, " +
		"чья копия принадлежит краю платформы. Отзыв — новая миграция плюс перекат " +
		"служб на новый идентификатор модели; предмет заведён задачей kaname#59. " +
		"ПРЕДИКАТ СНЯТИЯ: объявления нет ни в одной копии модели — запись становится " +
		"находкой в тот же прогон",
}

// AuthorityResidueCensus — объём осмотренного.
//
// Печатается ВСЕГДА и целиком: у проверки на отсутствие это единственное, чем
// «находок ноль» отличается от «прочитано ноль».
type AuthorityResidueCensus struct {
	// GoFiles — прод-файлов Go разобрано.
	GoFiles int
	// GoIdents — узлов-идентификаторов осмотрено.
	GoIdents int
	// Contracts — файлов контракта прочитано.
	Contracts int
	// ContractDecls — объявлений контракта осмотрено.
	ContractDecls int
	// Models — объявлений модели прав прочитано.
	Models int
	// Kept — прочтений законного соседа. Ноль здесь означает, что разбор не
	// дошёл до остатка, и его вердикт недействителен.
	Kept int
	// Excused — прочтений отношения, снятие которого объявлено чужим предметом.
	// Печатается рядом с находками: послабление, о котором не сказано числом,
	// неотличимо от его отсутствия.
	Excused int
	// Unparsed — файлов Go, которые парсер не принял. Третья категория: это не
	// «находок нет», а «о файле не известно ничего».
	Unparsed []string
}

func (c AuthorityResidueCensus) String() string {
	return fmt.Sprintf(
		"перепись: прод-файлов Go разобрано %d (узлов-имён %d), контрактов прочитано %d "+
			"(объявлений %d), объявлений модели прав %d; законный остаток прочитан %d раз; "+
			"по ведомости прощено %d; не разобрано %d",
		c.GoFiles, c.GoIdents, c.Contracts, c.ContractDecls, c.Models, c.Kept,
		c.Excused, len(c.Unparsed))
}

// AuthorityResidueFinding — одна находка: где, по какой оси и что именно.
type AuthorityResidueFinding struct {
	Where string
	Axis  string
	What  string
}

func (f AuthorityResidueFinding) String() string {
	return fmt.Sprintf("%s [%s] %s", f.Where, f.Axis, f.What)
}

// Названия осей. Вынесены константами, потому что их называет и инъекция: ось,
// переименованная в одном месте из двух, дала бы пробу, утверждающую о другой.
const (
	AxisContract  = "контракт"
	AxisGoCode    = "прод-код"
	AxisCatalogue = "каталог видов"
	AxisModel     = "модель прав"
)

// JudgeAuthorityResidue судит корпус: ключ — путь в дереве, значение — текст.
//
// excused — ведомость отношений модели, чьё снятие объявлено чужим предметом
// (`AuthorityResidueLedger`). Передаётся ПАРАМЕТРОМ, а не берётся из пакета:
// инъекция подаёт сюда синтетику, и судья, ходящий за ведомостью сам, на ней бы
// не работал. Сверка идёт в ОБЕ стороны — отношение вне ведомости есть находка,
// запись ведомости без предмета есть находка тоже.
//
// Вид оси выбирается по имени файла: `.go` (не `_test.go`) — прод-код, `.proto` —
// контракт, `.fga` — модель прав. Файл, не попавший ни под одну, не читается
// вовсе и в перепись не идёт: молчание о нём честнее, чем ноль.
//
// Возвращает перепись и находки; находок ноль при непустой переписи — годно.
func JudgeAuthorityResidue(corpus, excused map[string]string) (AuthorityResidueCensus, []AuthorityResidueFinding) {
	var (
		census   AuthorityResidueCensus
		findings []AuthorityResidueFinding
	)

	retired := make(map[string]bool, len(retiredAuthoritySymbols))
	for _, s := range retiredAuthoritySymbols {
		retired[s] = true
	}
	kept := make(map[string]bool, len(keptAuthorityNeighbours))
	for _, s := range keptAuthorityNeighbours {
		kept[s] = true
	}

	seenExcused := map[string]bool{}

	paths := make([]string, 0, len(corpus))
	for p := range corpus {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	for _, path := range paths {
		body := corpus[path]
		switch {
		case strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go"):
			census.GoFiles++
			idents, kcount, ok := authorityIdents(path, body)
			if !ok {
				census.Unparsed = append(census.Unparsed, path)
				continue
			}
			census.GoIdents += idents.total
			census.Kept += kcount
			for _, hit := range idents.hits {
				findings = append(findings, AuthorityResidueFinding{
					Where: fmt.Sprintf("%s:%d", path, hit.line),
					Axis:  AxisGoCode,
					What:  "имя снятого авторитета величин: " + hit.name,
				})
			}
			for _, loc := range countableCatalogueDecl.FindAllStringIndex(body, -1) {
				findings = append(findings, AuthorityResidueFinding{
					Where: fmt.Sprintf("%s:%d", path, 1+strings.Count(body[:loc[0]], "\n")),
					Axis:  AxisCatalogue,
					What:  "объявление закрытого каталога видов",
				})
			}

		case strings.HasSuffix(path, ".proto"):
			census.Contracts++
			for _, m := range authorityContractDecl.FindAllStringSubmatchIndex(body, -1) {
				census.ContractDecls++
				name := body[m[4]:m[5]]
				if !strings.Contains(name, "Limit") {
					if kept[name] {
						census.Kept++
					}
					continue
				}
				findings = append(findings, AuthorityResidueFinding{
					Where: fmt.Sprintf("%s:%d", path, 1+strings.Count(body[:m[0]], "\n")),
					Axis:  AxisContract,
					What:  fmt.Sprintf("объявление %s %s", body[m[2]:m[3]], name),
				})
			}

		case strings.HasSuffix(path, ".fga"):
			census.Models++
			for _, loc := range quotaReaderRelationDecl.FindAllStringIndex(body, -1) {
				if _, ok := excused["quota_reader"]; ok {
					census.Excused++
					seenExcused["quota_reader"] = true
					continue
				}
				findings = append(findings, AuthorityResidueFinding{
					Where: fmt.Sprintf("%s:%d", path, 1+strings.Count(body[:loc[0]], "\n")),
					Axis:  AxisModel,
					What:  "объявление отношения quota_reader — права читать пределы, которых нет",
				})
			}
		}
	}

	// ВТОРАЯ СТОРОНА СВЕРКИ: запись, которой нечего прощать. Судится ТОЛЬКО когда
	// модель прочитана: на корпусе без моделей всякая запись выглядела бы
	// истёкшей, и находка была бы вердиктом об обходе, а не о дереве.
	if census.Models > 0 {
		stale := make([]string, 0, len(excused))
		for rel := range excused {
			if !seenExcused[rel] {
				stale = append(stale, rel)
			}
		}
		sort.Strings(stale)
		for _, rel := range stale {
			findings = append(findings, AuthorityResidueFinding{
				Where: "AuthorityResidueLedger",
				Axis:  AxisModel,
				What: fmt.Sprintf("запись ведомости о %q прощать больше нечего: отношение "+
					"ушло из модели. Послабление, пережившее предмет, прикроет следующую находку — "+
					"снимите запись тем же изменением", rel),
			})
		}
	}

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Where != findings[j].Where {
			return findings[i].Where < findings[j].Where
		}
		return findings[i].What < findings[j].What
	})
	return census, findings
}

// identHit — попадание по оси прод-кода.
type identHit struct {
	name string
	line int
}

// identScan — итог обхода одного файла.
type identScan struct {
	total int
	hits  []identHit
}

// authorityIdents разбирает файл и судит УЗЛЫ-ИМЕНА.
//
// Третий возвращаемый — разобрался ли файл. Неразобранный НЕ засчитывается ни в
// находки, ни в чистоту: о нём не известно ничего, и это третья категория, а не
// вердикт.
func authorityIdents(path, body string) (identScan, int, bool) {
	var (
		scan identScan
		kept int
	)
	retired := make(map[string]bool, len(retiredAuthoritySymbols))
	for _, s := range retiredAuthoritySymbols {
		retired[s] = true
	}
	keptSet := make(map[string]bool, len(keptAuthorityNeighbours))
	for _, s := range keptAuthorityNeighbours {
		keptSet[s] = true
	}

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, body, parser.SkipObjectResolution)
	if err != nil {
		return identScan{}, 0, false
	}
	ast.Inspect(file, func(n ast.Node) bool {
		id, ok := n.(*ast.Ident)
		if !ok {
			return true
		}
		scan.total++
		switch {
		case retired[id.Name]:
			scan.hits = append(scan.hits, identHit{name: id.Name, line: fset.Position(id.Pos()).Line})
		case keptSet[id.Name]:
			kept++
		}
		return true
	})
	return scan, kept, true
}
