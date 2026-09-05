// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package scalegrid

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// СЕТКА ЗАДАНА ЗДЕСЬ, В КОДЕ, И НИОТКУДА НЕ ПЕРЕОПРЕДЕЛЯЕТСЯ
//
// Ни аргументом командной строки, ни переменной окружения. Причина не
// стилистическая: отчёт, снятый на СОКРАЩЁННОЙ сетке, неотличим от полного и
// читается как полный. Прецедент в этом же дереве уже есть — переопределение
// объёма замера переменной окружения у соседнего прибора
// (`services/iam/tools/authzformbench`, `AUTHZFORMBENCH_NS`), — и повторять его здесь
// запрещено сценарием R7-1-03.
//
// Читателей у сетки ТРОЕ, и все трое берут её ОТСЮДА: прибор (что мерить),
// шапка отчёта (на чём снято), гейт свежести (совпадает ли объявленное с
// измеренным). Второго объявления сетки не заводится: два места об одном
// предмете расходятся молча.

// Axis — ось сетки. Оси варьируются ПО ОДНОЙ, остальные держатся неподвижными:
// точка, где двигались две оси сразу, не говорит ни об одной из них.
type Axis string

const (
	// AxisN — объектов зеркала в облаке. «Сколько всего ресурсов».
	AxisN Axis = "N"
	// AxisB — выдач, НЕ называющих спрашиваемого субъекта. «Сколько всего
	// связей в облаке»: работа, которую вердикт обязан не делать.
	AxisB Axis = "B"
	// AxisR — выдач, называющих спрашиваемого. Остаточная переменная: она
	// расти вправе, но ограниченно (предел вводится стадией S3).
	AxisR Axis = "R"
	// AxisF — прямых фактов на цепи областей, называющих спрашиваемого.
	// Третье слагаемое остаточной переменной (§1.4а приёмки).
	AxisF Axis = "F"
)

// Recruit — СПОСОБ набора точки.
//
// Отдельная колонка отчёта, а не подробность: одно и то же число выдач,
// набранное прямыми выдачами и через группы, проходит по РАЗНЫМ ветвям
// `speaker`, и «не растёт» для одной ветви ничего не говорит о другой.
type Recruit string

const (
	// RecruitDirect — субъект назван выдачей лично.
	RecruitDirect Recruit = "прямыми выдачами"
	// RecruitViaGroup — субъект набран членством в группе.
	RecruitViaGroup Recruit = "через группы"
	// RecruitFactSelf — факт назван на субъекта лично.
	RecruitFactSelf Recruit = "фактом лично"
	// RecruitFactGroup — факт назван на группу, в которой субъект состоит.
	RecruitFactGroup Recruit = "фактом через группу"
	// RecruitFactWildcard — факт назван подстановкой `user:*`.
	RecruitFactWildcard Recruit = "фактом подстановкой user:*"
)

// Point — одна точка сетки: четыре величины и способ набора.
//
// Все четыре стоят в КАЖДОЙ точке, включая те оси, которые в ней не двигаются.
// Иначе «при фиксированных B, R, F» остаётся обещанием: перепись переписывает
// то, что посажено, а точка обязана назвать, что она посадить СОБИРАЛАСЬ.
type Point struct {
	Axis    Axis
	N       int
	B       int
	R       int
	F       int
	Recruit Recruit
}

// Value — величина той оси, которую эта точка варьирует.
func (p Point) Value() int {
	switch p.Axis {
	case AxisN:
		return p.N
	case AxisB:
		return p.B
	case AxisR:
		return p.R
	case AxisF:
		return p.F
	}
	return 0
}

// String — точка одной строкой, для шапки отчёта и сообщений об отказе.
func (p Point) String() string {
	return fmt.Sprintf("%s=%d (N=%d B=%d R=%d F=%d, %s)",
		p.Axis, p.Value(), p.N, p.B, p.R, p.F, p.Recruit)
}

// ── ПОЛНАЯ СЕТКА ─────────────────────────────────────────────────────────────
//
// Потолок — 10⁶ (решение при R7-1-01): критерий владельца назван миллионом, и
// сетка, кончающаяся на 10⁵, отвечает не на тот вопрос. Гоняется РУЧНЫМ
// прогоном; в конвейере идёт малая (см. Small).

// fullN — ось N: объектов зеркала. Прочие оси держатся на месте.
var fullN = []Point{
	{Axis: AxisN, N: 100, B: 1000, R: 9, F: 1, Recruit: RecruitDirect},
	{Axis: AxisN, N: 1000, B: 1000, R: 9, F: 1, Recruit: RecruitDirect},
	{Axis: AxisN, N: 10000, B: 1000, R: 9, F: 1, Recruit: RecruitDirect},
	{Axis: AxisN, N: 100000, B: 1000, R: 9, F: 1, Recruit: RecruitDirect},
	{Axis: AxisN, N: 1000000, B: 1000, R: 9, F: 1, Recruit: RecruitDirect},
}

// fullB — ось B: чужие выдачи. Это и есть «миллион связей в облаке».
var fullB = []Point{
	{Axis: AxisB, N: 1000, B: 100, R: 9, F: 1, Recruit: RecruitDirect},
	{Axis: AxisB, N: 1000, B: 1000, R: 9, F: 1, Recruit: RecruitDirect},
	{Axis: AxisB, N: 1000, B: 1000000, R: 9, F: 1, Recruit: RecruitDirect},
}

// fullR — ось R: выдачи, называющие спрашиваемого.
//
// Каждая точка выше 9 набирается ДВАЖДЫ — прямыми выдачами и через группы
// (R7-1-26): ветви `speaker` разные, и молчание одной о другой не говорит.
// Верхняя точка — ОБЪЯВЛЕННОЕ число 1000, а не ссылка на предел S3: во время
// S1 предела ещё не существует, и сетка, ссылающаяся на него, не исполнима.
var fullR = []Point{
	{Axis: AxisR, N: 1000, B: 1000, R: 1, F: 1, Recruit: RecruitDirect},
	{Axis: AxisR, N: 1000, B: 1000, R: 9, F: 1, Recruit: RecruitDirect},
	{Axis: AxisR, N: 1000, B: 1000, R: 100, F: 1, Recruit: RecruitDirect},
	{Axis: AxisR, N: 1000, B: 1000, R: 100, F: 1, Recruit: RecruitViaGroup},
	{Axis: AxisR, N: 1000, B: 1000, R: 227, F: 1, Recruit: RecruitDirect},
	{Axis: AxisR, N: 1000, B: 1000, R: 227, F: 1, Recruit: RecruitViaGroup},
	{Axis: AxisR, N: 1000, B: 1000, R: 1000, F: 1, Recruit: RecruitDirect},
	{Axis: AxisR, N: 1000, B: 1000, R: 1000, F: 1, Recruit: RecruitViaGroup},
}

// fullF — ось F: прямые факты на цепи областей.
//
// Точка F = 0 ОБЯЗАТЕЛЬНА как нижняя: без неё «полоса фактов входит в
// стоимость» неотличимо от «полосы фактов не существует». Точки выше 1
// набираются ТРЕМЯ способами написания субъекта — лично, через группу,
// подстановкой: это три разные ветви `speaker`, и они соединяются с фактом
// по-разному.
var fullF = []Point{
	{Axis: AxisF, N: 1000, B: 1000, R: 9, F: 0, Recruit: RecruitFactSelf},
	{Axis: AxisF, N: 1000, B: 1000, R: 9, F: 1, Recruit: RecruitFactSelf},
	{Axis: AxisF, N: 1000, B: 1000, R: 9, F: 10, Recruit: RecruitFactSelf},
	{Axis: AxisF, N: 1000, B: 1000, R: 9, F: 10, Recruit: RecruitFactGroup},
	{Axis: AxisF, N: 1000, B: 1000, R: 9, F: 10, Recruit: RecruitFactWildcard},
	{Axis: AxisF, N: 1000, B: 1000, R: 9, F: 100, Recruit: RecruitFactSelf},
	{Axis: AxisF, N: 1000, B: 1000, R: 9, F: 100, Recruit: RecruitFactGroup},
	{Axis: AxisF, N: 1000, B: 1000, R: 9, F: 100, Recruit: RecruitFactWildcard},
}

// Full — полная сетка четырёх осей, в порядке прогона.
func Full() [][]Point { return [][]Point{fullN, fullB, fullR, fullF} }

// ── МАЛАЯ СЕТКА ──────────────────────────────────────────────────────────────
//
// Идёт в конвейере на каждом прогоне (R7-1-06). Её предмет — не форма кривой, а
// ДЕГРАДАЦИЯ: отношение верхней точки к нижней не должно перевалить объявленный
// потолок. Ось R стоит рядом ПОЛОЖИТЕЛЬНЫМ КОНТРОЛЕМ — она обязана расти, иначе
// «не растёт» по N и B было бы тождественно верно для прибора, дающего ноль.

var smallN = []Point{
	{Axis: AxisN, N: 100, B: 100, R: 9, F: 1, Recruit: RecruitDirect},
	{Axis: AxisN, N: 1000, B: 100, R: 9, F: 1, Recruit: RecruitDirect},
}

var smallB = []Point{
	{Axis: AxisB, N: 100, B: 100, R: 9, F: 1, Recruit: RecruitDirect},
	{Axis: AxisB, N: 100, B: 1000, R: 9, F: 1, Recruit: RecruitDirect},
}

var smallR = []Point{
	{Axis: AxisR, N: 100, B: 100, R: 1, F: 1, Recruit: RecruitDirect},
	{Axis: AxisR, N: 100, B: 100, R: 9, F: 1, Recruit: RecruitDirect},
}

// smallF — ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ малой сетки.
//
// Контролем была ось R, и она им БЫТЬ ПЕРЕСТАЛА: после R7-1-13 разрешённый
// вердикт отвечает первой же строкой ветви выдач, поэтому число выдач,
// называющих спрашиваемого, его стоимости больше не меняет — ось R на
// разрешающем вопросе стала плоской ПО ПОСТРОЕНИЮ. Контроль, привязанный к
// снятому предмету, краснел бы на верной правке; оставить его значило бы
// требовать назад ту самую стоимость, ради снятия которой правка делалась.
//
// Ось F этим свойством не обладает и обладать не может: условные факты
// безусловного основания не дают, отбор различных над ними читает их все, и
// стоимость обязана расти. То есть контроль остаётся контролем — он просто
// переехал на ту ось, где рост есть по существу, а не по недоделке.
var smallF = []Point{
	{Axis: AxisF, N: 100, B: 100, R: 9, F: 1, Recruit: RecruitFactSelf},
	{Axis: AxisF, N: 100, B: 100, R: 9, F: 100, Recruit: RecruitFactSelf},
}

// Small — малая сетка для конвейера: четыре оси, по две точки.
func Small() [][]Point { return [][]Point{smallN, smallB, smallR, smallF} }

// ReportPath — куда ложится отчёт полной сетки.
//
// Константа, а не аргумент: гейт свежести читает отчёт ПО ЭТОМУ пути, и путь,
// задаваемый снаружи, позволил бы положить отчёт мимо гейта — то есть иметь
// замер, о котором гейт ничего не знает и потому молчит.
const ReportPath = "services/iam/internal/repo/kacho/pg/scalegrid/REPORT-R7-1-S1-scale-grid.txt"

// Digest — отпечаток сетки: то, что попадает в шапку отчёта и сверяется при
// чтении.
//
// Считается по СОДЕРЖИМОМУ точек, а не по их числу: сетка из пяти точек,
// у которой верхняя опущена с 10⁶ до 10⁵, даёт то же число точек и другой
// отпечаток. Ровно это и надо поймать.
func Digest(grid [][]Point) string {
	h := sha256.New()
	for _, axis := range grid {
		for _, p := range axis {
			h.Write([]byte(fmt.Sprintf("%s|%d|%d|%d|%d|%s\n",
				p.Axis, p.N, p.B, p.R, p.F, p.Recruit)))
		}
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// Describe — сетка словами, для шапки отчёта.
func Describe(grid [][]Point) string {
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
			if p.Recruit != RecruitDirect {
				fmt.Fprintf(&b, " (%s)", p.Recruit)
			}
		}
		// Печатаются ТОЛЬКО неподвижные оси. Ставить сюда и варьируемую значило
		// бы назвать её «фиксированной» её же нижним значением — то есть
		// напечатать про точку неправду в шапке отчёта.
		fixed := []string{}
		for _, o := range []struct {
			a Axis
			v int
		}{{AxisN, axis[0].N}, {AxisB, axis[0].B}, {AxisR, axis[0].R}, {AxisF, axis[0].F}} {
			if o.a != axis[0].Axis {
				fixed = append(fixed, fmt.Sprintf("%s=%d", o.a, o.v))
			}
		}
		fmt.Fprintf(&b, "  — неподвижны: %s\n", strings.Join(fixed, " "))
	}
	fmt.Fprintf(&b, "  отпечаток сетки: %s\n", Digest(grid))
	return b.String()
}
