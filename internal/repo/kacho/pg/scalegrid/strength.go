// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package scalegrid

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/PRO-Robotech/kacho/pkg/gitenv"
)

// СЕТКА ПРЕДЕЛА ПРОЧНОСТИ — ПЯТЬ НОВЫХ ОСЕЙ И ИСХОД ВЕРДИКТА НА КАЖДОЙ ТОЧКЕ
//
// Сетка четырёх осей (grid.go) отвечает на вопрос «растёт ли стоимость от
// размера облака» и отвечает на него ОДНИМ исходом: все её 24 точки дали
// `allow`. Отказной путь не измерен там ни разу, а ломается система именно на
// нём — ранний выход работает ТОЛЬКО на «да» (предел одной строки стоит внутри
// ветви выдач), поэтому отказ обязан дочитать то, что разрешение бросает первой
// же строкой.
//
// Отсюда устройство этой сетки, и оно отличается от соседней по существу:
// ТОЧКА — НЕ ОДИН ВОПРОС, А ТРИ. Каждая точка снимается тремя вопросами на
// ОДНОМ И ТОМ ЖЕ посеве:
//
//	allow      — право есть, ветвь выдач отвечает первой строкой;
//	deny_label — право «почти есть»: субъект несёт выдачи в области, их роли
//	             несут спрошенный глагол, и отвергает ПОСЛЕДНЕЕ звено —
//	             предикат ветви правила. Это ДОРОГОЙ отказ;
//	deny_verb  — спрошенного глагола не несёт ни одна роль базы, соединение
//	             схлопывается на `role_verb`. Это ДЕШЁВЫЙ отказ, и он стоит
//	             рядом КОНТРОЛЕМ: без него отчёт скажет «отказ дёшев», и это
//	             будет правдой про фикстуру, а не про продукт.
//
// Пара «allow / deny_label» на одном посеве даёт ДЕЛЬТУ — то есть цену
// недочитанного, — а не приписывает всю стоимость отказу.
//
// Сетка живёт КОНСТАНТОЙ здесь и ниоткуда не переопределяется: тот же довод,
// что у соседней (отчёт, снятый на сокращённой сетке, неотличим от полного).

const (
	// AxisV — ИСХОД ВЕРДИКТА против размера облака.
	//
	// Варьирует N, как ось N соседней сетки, но каждая точка спрашивается тремя
	// исходами. Отвечает ровно на то, чего соседняя сетка не спрашивала: держится
	// ли плоскость по размеру облака НА ОТКАЗЕ.
	AxisV Axis = "V"
	// AxisM — МЕМБЕРСТВ спрашивающего.
	//
	// Множество входит в ОБЕ ветви запроса разом: `speaker_pair` даёт M+2 строки
	// (сам, группы, подстановка), текстовый `speaker` — 2·M+2 (голая форма группы
	// и форма с хвостом членства). Предела на число членств в дереве НЕТ:
	// `group_members` мощности не ограничивает, а объявленное умолчание
	// `iam.group = 64` (миграция 0094) — предел числа ГРУПП В АККАУНТЕ, и он не
	// энфорсится.
	AxisM Axis = "M"
	// AxisL — СТРОК `access_binding_subjects`, совпавших с парой (говорящий, область).
	//
	// L НЕ равно «числу ролей»: уникальность действующей выдачи ключуется легаси-
	// субъектом строки `access_bindings`, а на `access_binding_subjects` уникальности
	// по (субъект, область) нет. Значит L набирается ОДНОЙ ролью: k привязок вида
	// subjects=[болван_i, U] дают k строк (U, область).
	AxisL Axis = "L"
	// AxisS — МОЩНОСТЬ ЦЕПИ ОБЛАСТЕЙ (строк CTE `scope`).
	//
	// Точки: 1 (вырожденная) · 7 (сегодняшняя наблюдаемая) · 11 (согласованное
	// замыкание глубины 4) · 341 (схемный потолок: у каждого узла свои четыре
	// ребра, 1+4+16+64+256). Последняя ПОМЕЧЕНА посевной: производители дерева
	// шлют одно-два звена, формы цепи не проверяет никто.
	AxisS Axis = "S"
	// AxisK — ПРАВИЛ РОЛИ, накрывших объект.
	//
	// Соединение `role_rule_selectors` даёт K строк на каждую пару
	// (говорящий, область) с выдачей; предикат ветви правила их отбирает. На
	// разрешении предел одной строки замыкает; на отказе все K читаются и
	// ОТБРАСЫВАЮТСЯ — поэтому на этой оси несущей становится «тронуто».
	AxisK Axis = "K"
	// AxisPg — СТРАНИЦА ПЕРЕЧИСЛЕНИЯ × доля доступных.
	//
	// `List` — не один заход: цикл повторяет заход, пока страница не наполнится
	// ЛИБО кандидаты типа не кончатся. При доле доступных 0 % страница не
	// наполняется никогда, и один вызов просматривает ВЕСЬ тип.
	AxisPg Axis = "Pg"
)

// AskMode — какой вопрос задаётся в точке.
type AskMode string

const (
	// AskAllow — право есть.
	AskAllow AskMode = "allow"
	// AskDenyLabel — ДОРОГОЙ отказ: отвергает предикат ветви правила.
	AskDenyLabel AskMode = "deny(правило)"
	// AskDenyVerb — ДЕШЁВЫЙ отказ: глагола не несёт ни одна роль.
	AskDenyVerb AskMode = "deny(глагол)"
)

// AskModes — все три вопроса, в порядке печати. Порядок фиксирован: колонки
// отчёта читаются слева направо, и перестановка сделала бы две редакции отчёта
// несравнимыми.
func AskModes() []AskMode { return []AskMode{AskAllow, AskDenyLabel, AskDenyVerb} }

// StrengthPoint — точка сетки предела прочности.
//
// Все шесть величин стоят в КАЖДОЙ точке, включая неподвижные: иначе «при
// фиксированных M, L, S» остаётся обещанием.
type StrengthPoint struct {
	Axis Axis
	// N — объектов зеркала.
	N int
	// M — членств спрашивающего в группах.
	M int
	// L — строк (говорящий, область) в `access_binding_subjects`.
	L int
	// S — ожидаемая мощность CTE `scope` в строках.
	S int
	// K — правил роли, накрывших объект.
	K int
	// Pg — размер страницы перечисления. Ноль — точка не про перечисление.
	Pg int
	// AllowedShare — доля доступных кандидатов в процентах (ось Pg).
	AllowedShare int
	// Seeded — состояние ПОСЕВНОЕ: продукт его сегодня не производит.
	// Печатается в отчёт пометкой; замер от этого не становится негодным, но
	// читатель обязан знать, что описано не то, что производит дерево.
	Seeded bool
}

// Value — величина той оси, которую точка варьирует.
func (p StrengthPoint) Value() int {
	switch p.Axis {
	case AxisV:
		return p.N
	case AxisM:
		return p.M
	case AxisL:
		return p.L
	case AxisS:
		return p.S
	case AxisK:
		return p.K
	case AxisPg:
		return p.Pg
	}
	return 0
}

// String — точка одной строкой.
func (p StrengthPoint) String() string {
	s := fmt.Sprintf("%s=%d (N=%d M=%d L=%d S=%d K=%d", p.Axis, p.Value(), p.N, p.M, p.L, p.S, p.K)
	if p.Axis == AxisPg {
		s += fmt.Sprintf(" Pg=%d доступно=%d%%", p.Pg, p.AllowedShare)
	}
	if p.Seeded {
		s += ", ПОСЕВНОЕ"
	}
	return s + ")"
}

// ── ОСИ ──────────────────────────────────────────────────────────────────────

// strengthV — исход вердикта против размера облака.
//
// Верхняя точка 10⁵, а не 10⁶: ось отвечает на вопрос о ФОРМЕ («меняет ли отказ
// плоскость по N»), и на неё довольно трёх порядков. Миллион стоит две с
// половиной минуты посева на точку и здесь ничего не добавил бы — соседняя
// сетка его уже прошла на разрешении.
var strengthV = []StrengthPoint{
	{Axis: AxisV, N: 100, M: 0, L: 1, S: 7, K: 1},
	{Axis: AxisV, N: 1000, M: 0, L: 1, S: 7, K: 1},
	{Axis: AxisV, N: 10000, M: 0, L: 1, S: 7, K: 1},
	{Axis: AxisV, N: 100000, M: 0, L: 1, S: 7, K: 1},
}

// strengthM — членств спрашивающего.
//
// M = 0 ОБЯЗАТЕЛЬНА как нижняя: без неё «членства входят в стоимость»
// неотличимо от «ветви членств не существует». Верхние точки 256 и 1024 — СВЕРХ
// объявленного умолчания (`iam.group = 64`), и это помечается: продукт объявил
// такое состояние невозможным и НЕ ПРОВЕРЯЕТ его.
var strengthM = []StrengthPoint{
	{Axis: AxisM, N: 1000, M: 0, L: 1, S: 7, K: 1},
	{Axis: AxisM, N: 1000, M: 1, L: 1, S: 7, K: 1},
	{Axis: AxisM, N: 1000, M: 8, L: 1, S: 7, K: 1},
	{Axis: AxisM, N: 1000, M: 64, L: 1, S: 7, K: 1},
	{Axis: AxisM, N: 1000, M: 256, L: 1, S: 7, K: 1, Seeded: true},
	{Axis: AxisM, N: 1000, M: 1024, L: 1, S: 7, K: 1, Seeded: true},
}

// strengthL — строк (говорящий, область).
var strengthL = []StrengthPoint{
	{Axis: AxisL, N: 1000, M: 0, L: 1, S: 7, K: 1},
	{Axis: AxisL, N: 1000, M: 0, L: 8, S: 7, K: 1},
	{Axis: AxisL, N: 1000, M: 0, L: 64, S: 7, K: 1},
	{Axis: AxisL, N: 1000, M: 0, L: 512, S: 7, K: 1, Seeded: true},
}

// strengthS — мощность цепи областей.
//
// Выдача на этой оси стоит НА САМОМ ОБЪЕКТЕ (глубина 0), а не на проекте: иначе
// точка S = 1 не существует как состояние — у объекта без рёбер проекта в
// области нет, и оба вопроса схлопнулись бы в дешёвый отказ. Плата за это
// названа: точки этой оси не сравнимы построчно с точками прочих осей, где
// выдача стоит на проекте. Внутри оси сравнимость сохраняется полностью.
var strengthS = []StrengthPoint{
	{Axis: AxisS, N: 1000, M: 0, L: 1, S: 1, K: 1},
	{Axis: AxisS, N: 1000, M: 0, L: 1, S: 7, K: 1},
	{Axis: AxisS, N: 1000, M: 0, L: 1, S: 11, K: 1},
	{Axis: AxisS, N: 1000, M: 0, L: 1, S: 341, K: 1, Seeded: true},
}

// strengthK — правил роли, накрывших объект.
var strengthK = []StrengthPoint{
	{Axis: AxisK, N: 1000, M: 0, L: 1, S: 7, K: 1},
	{Axis: AxisK, N: 1000, M: 0, L: 1, S: 7, K: 8},
	{Axis: AxisK, N: 1000, M: 0, L: 1, S: 7, K: 32},
	{Axis: AxisK, N: 1000, M: 0, L: 1, S: 7, K: 64},
}

// strengthPg — страница перечисления × доля доступных.
//
// Доля 0 % — ХУДШАЯ: страница не наполняется никогда, и вызов просматривает весь
// тип. Точка Pg = 5000 законна для замера и НЕЗАКОННА для края: у `List` верхнего
// предела нет вовсе, а контрактный потолок 1000 живёт в другом месте — поэтому
// она помечается «сверх контракта».
// Порядок точек — ДОЛЯ СНАРУЖИ, страница внутри, и это не оформление: смена доли
// перекрашивает метки всех 10⁵ объектов, а смена страницы не стоит ничего.
// Порядок «страница снаружи» дал бы двенадцать перекрасок вместо трёх, то есть
// заплатил бы минутами за расположение колонок в таблице.
var strengthPg = []StrengthPoint{
	{Axis: AxisPg, N: 100000, M: 0, L: 1, S: 7, K: 1, Pg: 50, AllowedShare: 100},
	{Axis: AxisPg, N: 100000, M: 0, L: 1, S: 7, K: 1, Pg: 500, AllowedShare: 100},
	{Axis: AxisPg, N: 100000, M: 0, L: 1, S: 7, K: 1, Pg: 1000, AllowedShare: 100},
	{Axis: AxisPg, N: 100000, M: 0, L: 1, S: 7, K: 1, Pg: 5000, AllowedShare: 100, Seeded: true},
	{Axis: AxisPg, N: 100000, M: 0, L: 1, S: 7, K: 1, Pg: 50, AllowedShare: 50},
	{Axis: AxisPg, N: 100000, M: 0, L: 1, S: 7, K: 1, Pg: 500, AllowedShare: 50},
	{Axis: AxisPg, N: 100000, M: 0, L: 1, S: 7, K: 1, Pg: 1000, AllowedShare: 50},
	{Axis: AxisPg, N: 100000, M: 0, L: 1, S: 7, K: 1, Pg: 5000, AllowedShare: 50, Seeded: true},
	{Axis: AxisPg, N: 100000, M: 0, L: 1, S: 7, K: 1, Pg: 50, AllowedShare: 0},
	{Axis: AxisPg, N: 100000, M: 0, L: 1, S: 7, K: 1, Pg: 500, AllowedShare: 0},
	{Axis: AxisPg, N: 100000, M: 0, L: 1, S: 7, K: 1, Pg: 1000, AllowedShare: 0},
	{Axis: AxisPg, N: 100000, M: 0, L: 1, S: 7, K: 1, Pg: 5000, AllowedShare: 0, Seeded: true},
}

// Strength — полная сетка предела прочности, В ПОРЯДКЕ ПРОГОНА: от дешёвого к
// дорогому.
//
// Порядок — не оформление: если дорогая ступень сорвётся, дешёвые уже сняты и
// предъявлены. Обратный порядок отдал бы за срыв ВЕСЬ прогон.
func Strength() [][]StrengthPoint {
	return [][]StrengthPoint{strengthV, strengthM, strengthL, strengthS, strengthK, strengthPg}
}

// StrengthReportPath — куда ложится отчёт сетки предела прочности.
const StrengthReportPath = "services/iam/internal/repo/kacho/pg/scalegrid/REPORT-R7-2-strength.txt"

// StrengthDigest — отпечаток сетки по СОДЕРЖИМОМУ точек.
func StrengthDigest(grid [][]StrengthPoint) string {
	h := sha256.New()
	for _, axis := range grid {
		for _, p := range axis {
			h.Write([]byte(fmt.Sprintf("%s|%d|%d|%d|%d|%d|%d|%d|%t\n",
				p.Axis, p.N, p.M, p.L, p.S, p.K, p.Pg, p.AllowedShare, p.Seeded)))
		}
	}
	for _, m := range AskModes() {
		h.Write([]byte(string(m) + "\n"))
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// StrengthDescribe — сетка словами, для шапки отчёта.
func StrengthDescribe(grid [][]StrengthPoint) string {
	var b strings.Builder
	for _, axis := range grid {
		if len(axis) == 0 {
			continue
		}
		fmt.Fprintf(&b, "  ось %s: ", axis[0].Axis)
		for i, p := range axis {
			if i > 0 {
				b.WriteString(", ")
			}
			fmt.Fprintf(&b, "%d", p.Value())
			if p.Axis == AxisPg {
				fmt.Fprintf(&b, "/%d%%", p.AllowedShare)
			}
			if p.Seeded {
				b.WriteString("*")
			}
		}
		fixed := []string{}
		for _, o := range []struct {
			a Axis
			v int
		}{{AxisV, axis[0].N}, {AxisM, axis[0].M}, {AxisL, axis[0].L},
			{AxisS, axis[0].S}, {AxisK, axis[0].K}} {
			if o.a != axis[0].Axis {
				name := string(o.a)
				if o.a == AxisV {
					name = "N"
				}
				fixed = append(fixed, fmt.Sprintf("%s=%d", name, o.v))
			}
		}
		fmt.Fprintf(&b, "  — неподвижны: %s\n", strings.Join(fixed, " "))
	}
	fmt.Fprintf(&b, "  вопросов на точку: %d (%s)\n", len(AskModes()), joinModes(AskModes()))
	fmt.Fprintf(&b, "  «*» — ПОСЕВНОЕ состояние: продукт его сегодня не производит либо объявил невозможным\n")
	fmt.Fprintf(&b, "  отпечаток сетки: %s\n", StrengthDigest(grid))
	return b.String()
}

func joinModes(ms []AskMode) string {
	out := make([]string, 0, len(ms))
	for _, m := range ms {
		out = append(out, string(m))
	}
	return strings.Join(out, " · ")
}

// AbsPathOf — абсолютный путь артефакта, разрешённый ОТ КОРНЯ ДЕРЕВА.
//
// Тот же довод, что у ReportAbsPath: `go test` исполняется в каталоге пакета,
// поэтому относительный путь лёг бы внутрь `relverdict/`, а гейт свежести искал
// бы артефакт у корня и НЕ НАШЁЛ БЫ — то есть печатал бы «отчёта нет» при
// существующем отчёте. Корень спрашивается у git, а не собирается из `..`:
// число шагов вверх зависит от того, кто зовёт.
//
// Отдельной функцией, а не вторым `ReportAbsPath`: артефактов у прибора стало
// два, и копия разрешителя разошлась бы с оригиналом молча.
func AbsPathOf(rel string) (string, error) {
	out, err := gitenv.Command("", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return "", fmt.Errorf("scalegrid: корень дерева не установлен, писать %s некуда: %w", rel, err)
	}
	return strings.TrimSpace(string(out)) + "/" + rel, nil
}

// ── ОТПЕЧАТОК ПРЕДМЕТА ЗАМЕРА ЗАПИСИ И УДАЛЕНИЯ ──────────────────────────────
//
// Предмет у него ДРУГОЙ, и сторожить его отпечатком читающего прибора нельзя:
// такой гейт краснел бы на правке запроса вердикта, которой отчёт о записи не
// касается, и МОЛЧАЛ бы на правке материализатора — то есть ровно на том, что
// он обязан ловить. Второй отпечаток заводится не «для симметрии», а потому что
// у второго отчёта другой предмет.

// WriteDeleteReportPath — куда ложится отчёт записи и удаления.
const WriteDeleteReportPath = "services/iam/internal/repo/kacho/pg/scalegrid/REPORT-R7-2-write-delete.txt"

// reconcileDir — каталог материализатора: он и есть предмет замера записи.
const reconcileDir = "services/iam/internal/apps/kacho/api/access_binding/reconcile"

// WriteDeleteFingerprintPredicate — предикат второго отпечатка, словами.
const WriteDeleteFingerprintPredicate = `все не-тестовые .go каталога ` + reconcileDir +
	`; все .sql каталога ` + migrateDir + `, называющие хотя бы одну таблицу, которую пишет ` +
	`материализатор (имена таблиц ВЫВЕДЕНЫ из его кода по приставке "` + fingerprintTableMark +
	`", а не выписаны)` +
	`; у .go под отпечаток идёт ЗНАЧАЩЕЕ содержимое — поток лексем БЕЗ комментариев ` +
	`(директивы //go: сохранены), поэтому смена заголовка лицензии или прозы замер НЕ ` +
	`обесценивает; .sql берётся ПОБАЙТОВО — в его комментариях живут директивы мигратора ` +
	`(-- +goose), а отделить их текстом нельзя: две дефиса встречаются и внутри литерала`

// ComputeWriteDeleteFingerprint — отпечаток предмета замера записи и удаления.
//
// Устроен ТЕМИ ЖЕ двумя хэшами, что и первый (состав ловит появление и
// исчезновение файла, содержимое — правку существующего), и теми же вспомогатель-
// ными функциями: вторая реализация обхода разошлась бы с первой молча.
func ComputeWriteDeleteFingerprint(root string) (Fingerprint, error) {
	var fp Fingerprint
	fp.Predicate = WriteDeleteFingerprintPredicate

	code, err := nonTestGoFiles(root, reconcileDir)
	if err != nil {
		return fp, err
	}
	tables := map[string]bool{}
	for _, rel := range code {
		body, rerr := os.ReadFile(filepath.Join(root, rel)) // #nosec G304 -- rel получен обходом СОБСТВЕННОГО дерева репозитория под корнем root, не из запроса и не от пользователя
		if rerr != nil {
			return fp, fmt.Errorf("scalegrid: чтение %s: %w", rel, rerr)
		}
		for _, name := range tableNamesIn(string(body)) {
			tables[name] = true
		}
	}
	for name := range tables {
		fp.Tables = append(fp.Tables, name)
	}
	sort.Strings(fp.Tables)

	migrations, err := migrationsNaming(root, fp.Tables)
	if err != nil {
		return fp, err
	}
	files := append(append([]string{}, code...), migrations...)
	sort.Strings(files)
	fp.Files = files

	ch := sha256.New()
	for _, rel := range files {
		ch.Write([]byte(rel + "\n"))
	}
	fp.Composition = hex.EncodeToString(ch.Sum(nil))[:16]

	// Тот же `contentHash`, что у первого отпечатка: значащее содержимое
	// определяется ОДИН раз. Второй экземпляр этой арифметики разошёлся бы с
	// первым молча — оба давали бы «совпало» на неподвижном дереве, и заметить
	// расхождение было бы нечем.
	fp.Content, err = contentHash(root, files)
	if err != nil {
		return fp, err
	}
	return fp, nil
}
