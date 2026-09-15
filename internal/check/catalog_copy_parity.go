// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// catalog_copy_parity.go — сверка двух копий каталога прав: своей и копии края.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ЗДЕСЬ ИЗМЕНИЛОСЬ И ПОЧЕМУ (kaname#79)
//
// Прежняя сверка была `cmp` двух файлов с ОДНОНАПРАВЛЕННОЙ посылкой: «источник
// истины один — копия края», и единственный совет находки — позвать
// `sync-permission-catalog`, то есть ПЕРЕПИСАТЬ свою копию копией края.
//
// Посылка держалась, пока оба дерева линковали ОДИН фундамент. Она перестала
// держаться, когда фундамент переименовал свой контракт: полное имя метода у
// контракта, живущего в библиотеке, задаёт ВЕРСИЯ БИБЛИОТЕКИ, которую линкует
// дерево, а версии у деревьев разные. Тогда расхождение означает не «наша копия
// отстала», а «отстала копия края», и прежний совет в этом направлении ВРЕДЕН:
//
//	перепись 2026-09-14 (`corelib@v1.7.0` переименовал форму подписки;
//	платформа на своём стволе пинила `corelib@v1.5.0`):
//	  записей у каждой стороны   338
//	  расходится                   1  — только сегмент пакета в `fqn`
//	  остальные поля записи       совпадают дословно
//
// Этот случай ЗАКРЫТ 2026-09-15: платформа подняла пин, копии снова совпадают
// побайтово, и запись ведомости, объяснявшая расхождение, снята — разбор у
// самой ведомости ниже. Довод о направлении оставлен, потому что он о КЛАССЕ:
// следующее переименование в фундаменте даст ту же картину.
//
// ЧЕМ ВРЕДЕН СОВЕТ — сказано ровно настолько, насколько измерено.
//
// Наша копия индексируется ПО `fqn` (`internal/apps/kaname/seed/permissions.go`,
// `byFQN`), и по нему же её спрашивают о ПОЛНОМ ИМЕНИ МЕТОДА, с которым вызов
// пришёл на СВОЙ слушатель (`internal/authzguard/acr_floor.go`,
// `requiredACRMin` → `strings.TrimPrefix(fullMethod, "/")`;
// `public_caller_policy.go`). Служба линкует `corelib@v1.7.0`, поэтому вызов
// приходит как `/corelib.subscription.…/Subscribe`. Записав сюда имя отставшего
// края, мы положили бы в посев имя метода, которого этот двоичный файл НЕ
// СЛУЖИТ, — мёртвая запись, а у служимого глагола записи бы не стало.
//
// ГРАНИЦА ЭТОГО ДОВОДА НАЗВАНА, ЧТОБЫ ЕГО НЕ ПЕРЕСКАЗАЛИ ШИРЕ. У пола ACR
// промах поиска даёт исход «требования нет» (правило 3 в `allow`), но ДО него
// стоит правило 1: глагол обязан быть во фронтируемом краем наборе
// (`authzguard.GatewayFrontedInternalRPCs`). Перепись 2026-09-14: глагола
// подписки в этом наборе НЕТ, значит сегодня промах на нём ИНЕРТЕН. Довод
// латентный, а не наступивший, и записан он так намеренно: наступит он тогда,
// когда глагол во фронтируемый набор внесут, — и заметить это будет нечем.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО СВЕРКА УТВЕРЖДАЕТ ТЕПЕРЬ
//
// Норма прежняя и НЕ ослаблена: копии — ОДИН порождённый артефакт. Изменилось
// то, что у равенства появился закрытый список переименований фундамента, и
// каждое из них обязано держать себя САМО в обе стороны. Остаток после их
// применения — находка с прежним текстом.
//
// Сравнение остаётся ПОБАЙТОВЫМ, а не «по смыслу»: файл режется на блоки
// записей по своей же форме, сборка блоков обязана дословно воспроизвести
// исходный файл (иначе форма файла сменилась — тоже находка), переименование
// применяется к блоку края, блоки пересортировываются по `fqn` (переименование
// двигает запись в перечне) и сравниваются дословно.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧЕГО ЭТА СВЕРКА НЕ ЗАКРЫВАЕТ — сказано прямо
//
//  1. Она НЕ знает пина фундамента у края: в конвейере копия края приезжает
//     ВЫБОРКОЙ одного каталога, `go.mod` платформы в ней нет. Поэтому
//     направление расхождения не ВЫЧИСЛЯЕТСЯ, а ОБЪЯВЛЯЕТСЯ ведомостью ниже, и
//     держится ведомость самоистечением, а не доверием.
//  2. Она НЕ судит, верно ли переименование по существу. Она судит, что оно
//     объявлено, что обе его стороны в деревьях ЕСТЬ и что кроме него не
//     разошлось ничего.
//  3. Провязка сверки к конвейеру — предмет `catalog_check_wiring.go`, не этот.
package check

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// CatalogFoundationRename — объявленное расхождение копий, произведённое
// переименованием контракта, чей владелец — ФУНДАМЕНТ, а не одно из двух
// деревьев. Пока деревья пинят разные версии фундамента, обе копии верны
// каждая для своей, и совпасть они не могут by construction.
type CatalogFoundationRename struct {
	// EdgeFQN — полное имя метода в копии края.
	EdgeFQN string
	// OwnFQN — полное имя того же метода в нашей копии.
	OwnFQN string
	// Why — почему расхождение не дефект.
	Why string
	// Removal — ПРЕДИКАТ СНЯТИЯ записи, внешний по отношению к этому дереву.
	Removal string
	// Refs — где предмет ведётся.
	Refs string
}

// catalogFoundationRenames — ЗАКРЫТЫЙ перечень объявленных расхождений.
//
// Запись здесь — послабление, и оно связано теми же тремя условиями, что всякое
// другое: величина названа замером (сколько записей из скольких расходится),
// предмет заведён (`Refs`), снятие наступает от ВНЕШНЕГО факта, а не от чьей-то
// памяти. Самоистечение держит `CompareCatalogCopies`: запись, чьей стороне в
// дереве больше нечего исключать, — находка.
//
// ПУСТОЙ ПЕРЕЧЕНЬ — ЦЕЛЬ, А НЕ ПОЛОМКА. На нём сверка требует побайтового
// совпадения копий и печатает «переименований объявлено 0»; способность падать
// у неё держат пробы на синтетике, а не наличие записи здесь.
//
// ─────────────────────────────────────────────────────────────────────────────
// СНЯТА ЕДИНСТВЕННАЯ ЗАПИСЬ — САМОИСТЕЧЕНИЕ СРАБОТАЛО ТАК, КАК ОБЪЯВЛЕНО
//
// Запись объясняла расхождение формы подписки: у края глагол стоял под именем
// пакета платформы, у нас — под именем пакета фундамента (`corelib@v1.7.0`
// переименовал контракт; kaname#79 · PRO-Robotech/kacho#2601 ·
// PRO-Robotech/corelib#7). Её предикат снятия звучал: «копия края называет
// глагол именем фундамента — платформа подняла пин до v1.7.0 и перегенерировала
// каталог».
//
// Предикат наступил на стволе платформы `edc98869b7` (2026-09-15): её `go.mod`
// пинит `corelib v1.7.0`, копия края называет глагол именем фундамента, прежнего
// имени в ней нет. Сверка против этого ствола дала (`make check-permission-catalog
// EDGE_TREE=<выборка ствола>`):
//
//	перепись: записей у края 338 · записей у нас 338 · переименований объявлено 1 · применено 0 · побайтово до ведомости true
//	НАХОДКА: ведомость объявленных переименований пережила свой предмет.
//
// То есть копии совпали побайтово, а красное пришло от самой записи — вид
// `CatalogFindingLedger`, не `CatalogFindingCopies`. Других записей в перечне не
// было, поэтому он пуст.
var catalogFoundationRenames = []CatalogFoundationRename{}

// CatalogFoundationRenames — объявленный перечень (копия, чтобы вызывающий не
// правил ведомость через возвращённый срез).
func CatalogFoundationRenames() []CatalogFoundationRename {
	out := make([]CatalogFoundationRename, len(catalogFoundationRenames))
	copy(out, catalogFoundationRenames)
	return out
}

// Виды находок. Разделены потому, что у них РАЗНЫЙ адресат: ведомость правят
// здесь, а расхождение копий ведёт либо к синхронизации, либо к платформе.
// Общий заголовок «копии разошлись» на находке ведомости лгал бы: при
// наступившем предикате снятия копии как раз СОВПАДАЮТ.
const (
	// CatalogFindingLedger — находка в ведомости послаблений.
	CatalogFindingLedger = "ведомость"
	// CatalogFindingCopies — находка в самих копиях.
	CatalogFindingCopies = "копии"
)

// CatalogParityFinding — одна находка: вид и текст.
type CatalogParityFinding struct {
	Kind string
	Text string
}

// CatalogParityCensus — объём осмотренного. «Ноль находок» обязано быть отличимо
// от «ноль прочитанного», а «ноль расхождений» — от «распознаватель ослеп».
type CatalogParityCensus struct {
	// EdgeEntries, OwnEntries — записей у каждой стороны.
	EdgeEntries int
	OwnEntries  int
	// RenamesDeclared — записей в ведомости.
	RenamesDeclared int
	// RenamesApplied — сколько из них ДЕЙСТВИТЕЛЬНО применились к копии края.
	RenamesApplied int
	// BytesEqual — совпали ли копии побайтово ДО применения ведомости.
	BytesEqual bool
}

// String — перепись одной строкой, пригодной для журнала конвейера.
func (c CatalogParityCensus) String() string {
	return fmt.Sprintf(
		"перепись: записей у края %d · записей у нас %d · переименований объявлено %d · применено %d · побайтово до ведомости %v",
		c.EdgeEntries, c.OwnEntries, c.RenamesDeclared, c.RenamesApplied, c.BytesEqual)
}

// CompareCatalogCopies — сверка против ДЕЙСТВУЮЩЕЙ ведомости дерева. Возвращает
// перечень находок (пустой = зелёное) и перепись. Ошибка — это ТРЕТИЙ ИСХОД:
// разобрать не удалось, вердикта о совпадении копий НЕТ (не путать с находкой).
func CompareCatalogCopies(edgeRaw, ownRaw string) ([]CatalogParityFinding, CatalogParityCensus, error) {
	return compareCatalogCopiesWith(catalogFoundationRenames, edgeRaw, ownRaw)
}

// compareCatalogCopiesWith — та же сверка с ЯВНОЙ ведомостью.
//
// Отдельная форма нужна ПРОБАМ: инъекция обязана вносить дефект в ведомость и
// в копии, а не подменять пакетную переменную из-под соседних проб. Прод-вход
// остаётся один и ведомость берёт только свою — подменить её вызовом нельзя.
func compareCatalogCopiesWith(
	renames []CatalogFoundationRename, edgeRaw, ownRaw string,
) ([]CatalogParityFinding, CatalogParityCensus, error) {
	census := CatalogParityCensus{
		RenamesDeclared: len(renames),
		BytesEqual:      edgeRaw == ownRaw,
	}

	edgeBlocks, err := splitCatalogBlocks(edgeRaw)
	if err != nil {
		return nil, census, fmt.Errorf("копия края: %w", err)
	}
	ownBlocks, err := splitCatalogBlocks(ownRaw)
	if err != nil {
		return nil, census, fmt.Errorf("своя копия: %w", err)
	}
	census.EdgeEntries = len(edgeBlocks)
	census.OwnEntries = len(ownBlocks)

	var findings []CatalogParityFinding

	// ── ВЕДОМОСТЬ ДЕРЖИТ СЕБЯ В ОБЕ СТОРОНЫ ──────────────────────────────────
	//
	// Сторона края отсутствует → исключать больше нечего: край догнал (либо
	// глагол снят), запись обязана уйти вместе со своим предметом.
	// Сторона своя отсутствует → ведомость утверждает о НАШЕМ дереве неправду.
	edgeByFQN := blocksByFQN(edgeBlocks)
	ownByFQN := blocksByFQN(ownBlocks)
	renamed := make(map[string]string, len(renames))
	for _, r := range renames {
		if _, ok := edgeByFQN[r.EdgeFQN]; !ok {
			findings = append(findings, CatalogParityFinding{CatalogFindingLedger, fmt.Sprintf(
				"нечего исключать: у края больше нет глагола %q — снимите запись, предикат снятия наступил. %s",
				r.EdgeFQN, r.Refs)})
			continue
		}
		if _, ok := ownByFQN[r.OwnFQN]; !ok {
			findings = append(findings, CatalogParityFinding{CatalogFindingLedger, fmt.Sprintf(
				"запись называет наш глагол %q, которого в нашей копии НЕТ — она утверждает о дереве неправду. %s",
				r.OwnFQN, r.Refs)})
			continue
		}
		renamed[r.EdgeFQN] = r.OwnFQN
		census.RenamesApplied++
	}

	// ── ПРИМЕНЕНИЕ ВЕДОМОСТИ К КОПИИ КРАЯ ────────────────────────────────────
	//
	// Переименование двигает запись в перечне: он отсортирован по `fqn`. Значит
	// после подстановки блоки пересортировываются, и только тогда сравниваются.
	projected := make([]catalogBlock, 0, len(edgeBlocks))
	for _, b := range edgeBlocks {
		if own, ok := renamed[b.fqn]; ok {
			body := strings.Replace(b.body, catalogFQNField(b.fqn), catalogFQNField(own), 1)
			if body == b.body {
				return nil, census, fmt.Errorf(
					"поле `fqn` записи %q не найдено дословно — форма записи не та, что разбирает эта сверка", b.fqn)
			}
			b = catalogBlock{fqn: own, body: body}
		}
		projected = append(projected, b)
	}
	sort.Slice(projected, func(i, j int) bool { return projected[i].fqn < projected[j].fqn })

	if assembleCatalog(projected) == ownRaw {
		return findings, census, nil
	}

	// ── ОСТАТОК — НАХОДКА, И ОН НАЗЫВАЕТСЯ ПОИМЁННО ──────────────────────────
	findings = append(findings, catalogResidualFindings(projected, ownBlocks)...)
	if len(findings) == 0 {
		// Состав и содержимое записей сошлись, а файл — нет: разошлась ФОРМА
		// файла (порядок, отступ, перевод строки). Молчать об этом нельзя:
		// побайтовость и есть предмет сверки.
		findings = append(findings, CatalogParityFinding{CatalogFindingCopies,
			"состав и содержимое записей сходятся, а файлы — нет: " +
				"разошлась ФОРМА файла (порядок записей, отступ либо перевод строки)"})
	}
	return findings, census, nil
}

// catalogFQNField — поле `fqn` записи в том виде, в каком его пишет генератор.
func catalogFQNField(fqn string) string {
	return `"fqn": ` + mustJSONString(fqn)
}

func mustJSONString(s string) string {
	b, err := json.Marshal(s)
	if err != nil { // недостижимо для строки
		panic(err)
	}
	return string(b)
}

// catalogResidualFindings — что именно осталось разошедшимся после ведомости.
func catalogResidualFindings(projected, own []catalogBlock) []CatalogParityFinding {
	projByFQN := blocksByFQN(projected)
	ownByFQN := blocksByFQN(own)

	var findings []CatalogParityFinding
	for _, b := range projected {
		o, ok := ownByFQN[b.fqn]
		if !ok {
			findings = append(findings, CatalogParityFinding{CatalogFindingCopies,
				fmt.Sprintf("есть у края, нет у нас: %s", b.fqn)})
			continue
		}
		if o.body != b.body {
			findings = append(findings, CatalogParityFinding{CatalogFindingCopies,
				fmt.Sprintf("запись расходится содержимым: %s", b.fqn)})
		}
	}
	for _, b := range own {
		if _, ok := projByFQN[b.fqn]; !ok {
			findings = append(findings, CatalogParityFinding{CatalogFindingCopies,
				fmt.Sprintf("есть у нас, нет у края: %s", b.fqn)})
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Text < findings[j].Text })
	return findings
}

// catalogBlock — одна запись каталога ДОСЛОВНЫМИ байтами плюс её `fqn`.
type catalogBlock struct {
	fqn  string
	body string
}

func blocksByFQN(blocks []catalogBlock) map[string]catalogBlock {
	m := make(map[string]catalogBlock, len(blocks))
	for _, b := range blocks {
		m[b.fqn] = b
	}
	return m
}

const (
	catalogPrefix    = "[\n"
	catalogSuffix    = "\n]\n"
	catalogSeparator = ",\n"
)

// splitCatalogBlocks — режет файл на записи ДОСЛОВНО и проверяет СВОЮ ЖЕ
// предпосылку: сборка блоков обязана воспроизвести исходный текст побайтово.
// Не воспроизвела — форма файла не та, что разбирает эта сверка, и это ТРЕТИЙ
// ИСХОД, а не находка: о совпадении копий мы не узнали ничего.
func splitCatalogBlocks(raw string) ([]catalogBlock, error) {
	if !strings.HasPrefix(raw, catalogPrefix) || !strings.HasSuffix(raw, catalogSuffix) {
		return nil, fmt.Errorf("форма файла не та: ожидались %q в начале и %q в конце",
			catalogPrefix, catalogSuffix)
	}
	body := raw[len(catalogPrefix) : len(raw)-len(catalogSuffix)]
	if strings.TrimSpace(body) == "" {
		return nil, fmt.Errorf("перечень пуст — сверять нечего")
	}

	parts := strings.Split(body, "\n  },\n")
	blocks := make([]catalogBlock, 0, len(parts))
	for i, p := range parts {
		if i < len(parts)-1 {
			p += "\n  }"
		}
		fqn, err := catalogBlockFQN(p)
		if err != nil {
			return nil, err
		}
		blocks = append(blocks, catalogBlock{fqn: fqn, body: p})
	}
	if got := assembleCatalog(blocks); got != raw {
		return nil, fmt.Errorf("разбор не воспроизводит файл побайтово (%d байт против %d) — форма файла сменилась",
			len(got), len(raw))
	}
	return blocks, nil
}

// assembleCatalog — сборка обратно. Обратна `splitCatalogBlocks` by construction.
func assembleCatalog(blocks []catalogBlock) string {
	bodies := make([]string, 0, len(blocks))
	for _, b := range blocks {
		bodies = append(bodies, b.body)
	}
	return catalogPrefix + strings.Join(bodies, catalogSeparator) + catalogSuffix
}

// catalogBlockFQN — `fqn` записи, прочитанный РАЗБОРОМ, а не поиском подстроки:
// имя метода встречается и в значении `permission`, и сверка по образцу взяла
// бы не то поле.
func catalogBlockFQN(block string) (string, error) {
	var entry struct {
		FQN string `json:"fqn"`
	}
	if err := json.Unmarshal([]byte(block), &entry); err != nil {
		return "", fmt.Errorf("запись не разбирается как JSON: %w", err)
	}
	if entry.FQN == "" {
		return "", fmt.Errorf("у записи пустое поле `fqn` — сверять её не по чему")
	}
	return entry.FQN, nil
}
