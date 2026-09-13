// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// contract_names_live_machinery.go — МАШИНЕРИЯ, НАЗВАННАЯ КОММЕНТАРИЕМ
// КОНТРАКТА, ОБЯЗАНА СУЩЕСТВОВАТЬ В ДЕРЕВЕ.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Комментарий публичного контракта читает ИНТЕГРАТОР — у него нет ни нашей
// истории, ни возможности перемерить. Обещание механизма, снятого миграцией,
// для него неотличимо от действующего: класс «принято-и-проигнорировано» со
// стороны контракта (`api-conventions.md` §«Неисполнимая возможность»).
//
// Наблюдалось (kacho#2486): `rpc ForceLogout` обещал строку в очереди
// федеративного уведомления и рассылку по каналу, обновляющую кэш отзыва на
// крае. Очередь снята миграцией, канал снят вместе со своим триггером, а рядом
// стояла ссылка на файл контракта, которого в модуле нет. Три утверждения
// пережили свой предмет и продолжали читаться как действующие.
//
// ─────────────────────────────────────────────────────────────────────────────
// СУЖЕНИЕ ИДЁТ ПО МАРКЕРУ, КОТОРЫЙ СТАВИТ САМ КОММЕНТАРИЙ
//
// Голый предикат «слово в обратных кавычках обязано резолвиться» негоден, и это
// ИЗМЕРЕНО, а не предположено: на дереве службы он даёт 239 токенов, из которых
// 159 не резолвятся ни в таблицу, ни в канал, ни в колонку — 66 % ложных
// находок. Предикат с такой долей не читают, а гейт, который не читают, не
// держит ничего.
//
// Поэтому заявлением считается не токен, а токен ВМЕСТЕ С МАРКЕРОМ, который
// комментарий ставит сам:
//
//	`<имя>_outbox`        суффикс очереди — заявлена ТАБЛИЦА
//	`<имя>` table         слово сразу после — заявлена ТАБЛИЦА
//	`<имя>` channel       слово сразу после — заявлен КАНАЛ
//	NOTIFY … on `<имя>`   оборот перед    — заявлен КАНАЛ
//
// Замер того же дерева этим предикатом: заявлений 9, из них резолвятся 6
// (`audit_outbox`, `fga_outbox`, `session_revocations`), не резолвятся 3 — ровно
// те три, ради которых гейт заведён. Ложных находок ноль.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО СЧИТАЕТСЯ ИСТИНОЙ
//
// Схему называет ПРИМЕНЁННОЕ дерево миграций, а не намерение: таблицы —
// `CREATE TABLE`, каналы — `pg_notify`. Обе половины читаются из одного
// источника, поэтому снятие механизма миграцией немедленно делает заявление о
// нём находкой, и держать запись ради зелёного негде.
//
// ─────────────────────────────────────────────────────────────────────────────
// ВТОРАЯ ОСЬ: ССЫЛКА НА СОСЕДНИЙ КОНТРАКТ
//
// Комментарий, называющий `<имя>.proto` БЕЗ каталога, называет контракт ЭТОГО
// модуля — так в дереве и пишут (`internal_iam_service.proto`, `user.proto`).
// Такое имя обязано резолвиться.
//
// Ссылка С КАТАЛОГОМ (`kacho/cloud/validation.proto`) под ось НЕ подпадает, и
// это решение, а не пропуск: у платформы свой репозиторий, её файла в этом
// модуле нет by construction, и утверждение о чужом дереве предикатом ЭТОГО
// дерева не судится. Замер: таких ссылок 2, обе законны; включив их, гейт начал
// бы с двух ложных находок и потребовал бы ведомости прощений — то есть
// исключения, выданного вперёд.
package check

import (
	"regexp"
	"sort"
	"strings"
)

// MachineryKind — что именно заявил комментарий.
type MachineryKind string

const (
	// MachineryTable — заявлена таблица схемы.
	MachineryTable MachineryKind = "таблица"
	// MachineryChannel — заявлен канал уведомления.
	MachineryChannel MachineryKind = "канал"
	// MachineryContract — заявлен соседний файл контракта.
	MachineryContract MachineryKind = "контракт"
)

// MachineryClaim — одно заявление комментария о машинерии дерева.
type MachineryClaim struct {
	// File — путь контракта относительно корня набора.
	File string
	// Line — строка, на которой стоит имя.
	Line int
	// Name — заявленное имя.
	Name string
	// Kind — чем комментарий его назвал.
	Kind MachineryKind
}

// MachineryFacts — вход предиката. Собран так, чтобы предикат прогонялся
// инъекцией, не трогая дерево.
type MachineryFacts struct {
	// Sources — путь контракта → его исходный текст.
	Sources map[string]string
	// Tables — таблицы ПРИМЕНЁННОЙ схемы.
	Tables map[string]struct{}
	// Channels — каналы уведомления, которые эта схема производит.
	Channels map[string]struct{}
	// Contracts — базовые имена контрактов, существующих в модуле.
	Contracts map[string]struct{}
}

// MachineryCensus — объём осмотренного. Печатается всегда: «ноль находок»
// обязано быть отличимо от «ноль прочитанного».
type MachineryCensus struct {
	// Files — прочитано файлов контрактов.
	Files int
	// CommentBlocks — прочитано блоков комментария.
	CommentBlocks int
	// Claims — распознано заявлений всего.
	Claims int
	// ByKind — распознано заявлений по видам.
	ByKind map[MachineryKind]int
	// Resolved — из них резолвится (законные близнецы).
	Resolved int
}

// commentLine — строка комментария контракта.
var commentLine = regexp.MustCompile(`^\s*//`)

// backtickToken — имя в обратных кавычках: змеиная запись, латиница.
var backtickToken = regexp.MustCompile("`([a-z][a-z0-9_]*)`")

// tableMarker — слово `table` сразу за именем.
var tableMarker = regexp.MustCompile(`^\W{0,3}table\b`)

// channelMarker — слово `channel` сразу за именем.
var channelMarker = regexp.MustCompile(`^\W{0,3}channel\b`)

// notifyBefore — оборот `NOTIFY … on` (или `LISTEN … on`) прямо перед именем.
// Он и есть маркер: имя, стоящее за предлогом такого оборота, — канал.
var notifyBefore = regexp.MustCompile(`(NOTIFY|LISTEN)[^` + "`" + `]{0,40}\bon\s*$`)

// siblingContract — имя соседнего контракта: БЕЗ каталога (см. шапку).
var siblingContract = regexp.MustCompile(`(?:^|[^\w/.])([a-z0-9_]+\.proto)\b`)

// markerWindow — сколько символов после имени читает маркер. Величина выбрана
// замером, а не на глаз: на 14 предикат даёт ноль ложных находок, на 60 —
// три (`kaname`, `token_jti` дважды), потому что слово-маркер успевает прийти
// из соседнего предложения.
const markerWindow = 14

// AuditMachineryClaims — заявления комментариев контрактов, которым в дереве
// нечего назвать. Пусто = норма.
//
// Возвращает находки и перепись раздельно: перепись — самостоятельное
// утверждение, и пустой обход обязан быть отличим от чистого дерева.
func AuditMachineryClaims(f MachineryFacts) ([]MachineryClaim, MachineryCensus) {
	census := MachineryCensus{ByKind: map[MachineryKind]int{}}
	var found []MachineryClaim

	for _, path := range sortedStringKeys(f.Sources) {
		census.Files++
		for _, block := range commentBlocksOf(f.Sources[path]) {
			census.CommentBlocks++
			for _, claim := range claimsInBlock(path, block) {
				census.Claims++
				census.ByKind[claim.Kind]++
				if machineryResolves(f, claim) {
					census.Resolved++
					continue
				}
				found = append(found, claim)
			}
		}
	}
	sort.Slice(found, func(i, j int) bool {
		if found[i].File != found[j].File {
			return found[i].File < found[j].File
		}
		return found[i].Line < found[j].Line
	})
	return found, census
}

// machineryResolves — есть ли у заявления предмет в дереве.
func machineryResolves(f MachineryFacts, c MachineryClaim) bool {
	switch c.Kind {
	case MachineryTable:
		_, ok := f.Tables[c.Name]
		return ok
	case MachineryChannel:
		_, ok := f.Channels[c.Name]
		return ok
	case MachineryContract:
		_, ok := f.Contracts[c.Name]
		return ok
	}
	return false
}

// commentBlock — подряд идущие строки комментария, сведённые в один текст.
//
// Сведение обязательно: имя переносится на следующую строку вместе с обёрткой
// (`… subscription on` / `` `session_revoked` ``), и построчный разбор потерял бы
// ровно тот случай, ради которого маркер и заведён.
type commentBlock struct {
	// Text — текст блока одной строкой.
	Text string
	// LineAt — номер исходной строки по смещению в Text.
	LineAt []int
}

// commentBlocksOf — блоки комментария исходника.
func commentBlocksOf(src string) []commentBlock {
	lines := strings.Split(src, "\n")
	var blocks []commentBlock
	for i := 0; i < len(lines); {
		if !commentLine.MatchString(lines[i]) {
			i++
			continue
		}
		var b commentBlock
		for ; i < len(lines) && commentLine.MatchString(lines[i]); i++ {
			text := strings.TrimSpace(strings.TrimLeft(strings.TrimSpace(lines[i]), "/")) + " "
			for range text {
				b.LineAt = append(b.LineAt, i+1)
			}
			b.Text += text
		}
		blocks = append(blocks, b)
	}
	return blocks
}

// claimsInBlock — заявления одного блока комментария.
func claimsInBlock(path string, b commentBlock) []MachineryClaim {
	var out []MachineryClaim
	for _, m := range backtickToken.FindAllStringSubmatchIndex(b.Text, -1) {
		name := b.Text[m[2]:m[3]]
		after := b.Text[m[1]:min(len(b.Text), m[1]+markerWindow)]
		before := b.Text[max(0, m[0]-45):m[0]]

		// ПОРЯДОК ВЕТВЕЙ НЕСУЩИЙ, и он установлен инъекцией, а не выбран.
		//
		// Суффикс `_outbox` — догадка о виде; слово `table`/`channel` и оборот
		// `NOTIFY … on` — то, что комментарий сказал ПРЯМО. Сказанное прямо
		// сильнее догадки, потому что каналы этого дерева названы по очереди,
		// которую объявляют (`kaname_invite_mail_outbox`): поставь суффикс
		// первым — и КАЖДЫЙ живой канал был бы объявлен несуществующей
		// таблицей, то есть гейт краснел бы на исправном дереве.
		kind := MachineryKind("")
		switch {
		case tableMarker.MatchString(after):
			kind = MachineryTable
		case channelMarker.MatchString(after):
			kind = MachineryChannel
		case notifyBefore.MatchString(before):
			kind = MachineryChannel
		case strings.HasSuffix(name, "_outbox"):
			kind = MachineryTable
		default:
			continue
		}
		out = append(out, MachineryClaim{File: path, Line: lineAt(b, m[0]), Name: name, Kind: kind})
	}
	for _, m := range siblingContract.FindAllStringSubmatchIndex(b.Text, -1) {
		out = append(out, MachineryClaim{
			File: path, Line: lineAt(b, m[2]),
			Name: b.Text[m[2]:m[3]], Kind: MachineryContract,
		})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Line < out[j].Line })
	return out
}

// lineAt — исходная строка по смещению в сведённом тексте блока.
func lineAt(b commentBlock, off int) int {
	if off < 0 || off >= len(b.LineAt) {
		return 0
	}
	return b.LineAt[off]
}

// sortedStringKeys — ключи в устойчивом порядке: вердикт не зависит от обхода
// карты, иначе перечень находок менялся бы от прогона к прогону.
func sortedStringKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
