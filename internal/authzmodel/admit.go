// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzmodel

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/PRO-Robotech/kaname/internal/authzplan"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// admit.go — ДОПУСК собранной модели прав: чистая функция, отвечающая на один
// вопрос — вправе ли текст, собранный из доставленных манифестов, стать моделью
// процесса.
//
// Вход — ТЕКСТ и перечень термов, объявленных ключом публичного чтения
// (`publicReadToChildren`) в доставленных манифестах ([KeyTerm], kaname#866,
// приёмка public-read-container-of-a-module-type-is-admitted.md, Р4). Допуск
// по-прежнему не знает, КТО написал текст, но знает, какие типы объявлены
// ключом: три следствия ключа, написанные рукой, побайтово равны написанным
// ключом, и по одному тексту их не различить. Перечень выводится из СОДЕРЖАНИЯ
// доставленных манифестов (поле ключа), а не из их происхождения. Пустой перечень
// — строгий режим: класс в блоке нового типа есть находка всюду.
//
// Решение — docs/engineering/architecture/composed-model-is-admitted-by-content.md.
// Приёмка — docs/engineering/acceptance/composed-model-admits-only-what-it-owns.md,
// предмет A (сценарии ADM-A-01…ADM-A-27). Здесь они НЕ пересказываются: два места
// об одном предмете расходятся молча.
//
// # НОРМА, из которой выведено всё остальное
//
// Композиция допускается, только если она МОНОТОННА и ПОДВЕШЕНА: вправе добавить
// поддерево типов, которых образ не несёт, и не вправе изменить ни одного
// объявления, которое образ уже несёт.
//
// # Вход — ТЕКСТ, а не разобранная модель
//
// Три причины, и первая несущая:
//
//  1. Д7(а) судит БАЙТЫ — у разобранной модели байтов нет, и функция, принимающая
//     только `*authzplan.Model`, эту клаузу выразить не может вовсе;
//  2. вход `internal/manifest` дал бы цикл импорта: тот пакет уже
//     импортирует этот (`relationgrant.go`, вызов `Shared()`);
//  3. допуск судит МОДЕЛЬ, а не заявку: манифест до модели проходит рендер, и
//     судить заявку значило бы судить не тот артефакт.
//
// # Канон берётся у ОБРАЗА, а не у вызывающего
//
// Это требование к сигнатуре, а не удобство: канон-параметр делает допуск
// САМОУДОВЛЕТВОРИМЫМ — вызывающий, подавший вместо канона собранный текст,
// обнуляет Д7(а) (префикс тривиально равен), Д1 (вхождение одно) и Д4 (членство
// тривиально выполнено). Поэтому [Admit] принимает ОДИН аргумент, а
// параметризованная форма [admit] не экспортирована и зовётся только пробами
// пакета — им нужен синтетический канон, которого в продукте нет.
//
// # Второго разборщика грамматики модели здесь НЕТ
//
// Текст разбирает тот же `authzplan.ParseModel`, что и всё остальное дерево.
// Второй разборщик разошёлся бы с первым МОЛЧА — на той самой форме, которой не
// знает; тот же довод стоит в шапке `modelrender/render.go`.
//
// # Чего в этом файле НЕТ и почему — три ветви, снятые по одной причине
//
// Правило, чьё нарушение отвергнуто соседом РАНЬШЕ, чем дойдёт до нас, есть
// ветвь без предмета: она молчала бы вечно.
//
//	«вывод не выходит за пределы блока и его указателей» — исполняет
//	`Model.validate()` внутри ParseModel: `or nosuchrelation`,
//	`or admin from nosuchpointer` и `or nosuchrel from project` до допуска не
//	доезжают, значения `*authzplan.Model` по ним не возникает;
//
//	«тип субъекта объявлен» — тот же `Model.validate()`: `[user, nosuchtype]`
//	отвергается разбором;
//
//	«новое имя не совпадает с именем канона» — исполняет сама Д1: при
//	терминальной Д7(а) текст канона присутствует целиком, поэтому совпадение с
//	каноническим именем даёт ДВА вхождения, и срабатывает счёт вхождений.
//
// Утверждения о первых двух живут пробой над РАЗБОРЩИКОМ, а не над допуском.

// Rule — правило допуска. Значения — часть контракта: их читает оператор, и по
// ним же трассируются сценарии приёмки.
type Rule string

const (
	// RuleD7Prefix — текст собранной модели начинается текстом канона ПОБАЙТОВО.
	// Терминальна: не совпал префикс — о разобранном говорить нельзя, модель
	// может быть чужой целиком.
	RuleD7Prefix Rule = "Д7(а)"
	// RuleD7Suffix — всякая строка за границей префикса — одна из пяти форм:
	// пустая · комментарий · relations · define · type <идентификатор>.
	RuleD7Suffix Rule = "Д7(б)"
	// RuleD1 — имя типа встречается в перечне типов ровно один раз, имя отношения
	// — ровно один раз в перечне объявлений своего типа.
	RuleD1 Rule = "Д1"
	// RuleD3 — ни одна пара (тип, отношение), достижимая из объявлений нового
	// типа, не разрешается подстановкой, кроме термов, объявленных ключом
	// публичного чтения, — и тех только в своём объявлении ([KeyTerm]).
	RuleD3 Rule = "Д3"
	// RuleD4Userset — всякий усерсет нового типа есть отношение, которое
	// тип-носитель действительно объявляет.
	RuleD4Userset Rule = "Д4(а)"
	// RuleD4Condition — всякое условие нового типа — имя из условий канона.
	RuleD4Condition Rule = "Д4(б)"
	// RuleD5 — план каждого объявления нового типа выразим.
	RuleD5 Rule = "Д5′"
	// RuleD8 — у типа не больше одного указателя на каждый тип-предок.
	RuleD8 Rule = "Д8"
)

// ФОРМА ИМЕНИ ТИПА ОБЪЯВЛЕНА НЕ ЗДЕСЬ (задача kacho#2015).
//
// Она часть формы строки `type`, а не отдельная клауза: предикат один, и двух
// объявлений одного предмета не заводится. Здесь стояло СВОЁ объявление образца
// — до тех пор, пока читатель у него был один. Читателей стало три: этот допуск,
// загрузчик манифеста (`internal/manifest`, после размыкания таблицы типов) и
// колонка `catalog_resource.object_type` ограничением базы. Поэтому образец
// переехал в `internal/domain`, к своему близнецу — форме имени модуля, — и
// зовётся отсюда.
//
// Импорт `domain` сюда безопасен by construction: `domain` — чистый Go и на
// `authzmodel` не ссылается (цикла нет), а поведение допуска не меняется —
// образец тот же побайтово.

// Finding — одна находка допуска.
//
// Она называет КООРДИНАТУ, а не «модель не собралась»: цена эксплуатации —
// объявленная ось решения, и отказ обязан говорить оператору, что править.
type Finding struct {
	// Rule — правило, которое нарушено.
	Rule Rule
	// Type — тип, о котором находка. Пусто у Д7: там ещё не разобрано ничего.
	Type string
	// Relation — отношение, о котором находка. Пусто, когда находка о типе целиком.
	Relation string
	// Term — терм либо запись субъекта, сделавшая находку. Пусто, когда предмет
	// находки не терм.
	Term string
	// Text — текст для оператора. Всякий перечень в нём ПРИВЕДЁН К ПОРЯДКУ:
	// неотсортированный делает текст функцией случая, а пробу — флейкующей by
	// construction.
	Text string
}

func (f Finding) String() string {
	return string(f.Rule) + ": " + f.Text
}

// AdmissionReport — отчёт допуска.
//
// Исходов ТРИ: допущено всё · находка · СУДИТЬ НЕЧЕГО. Третий в успех НЕ
// засчитывается и из вердикта НЕ вычитается.
type AdmissionReport struct {
	// Judged — суждение СОСТОЯЛОСЬ: канон разобран, собранный текст разобран, и
	// правила исполнены (либо остановлены Д7, что тоже есть вердикт).
	//
	// Поле существует ради УМОЛЧАНИЯ ТИПА, а не ради диагностики. [Admit] на
	// входе, который не разобрался, возвращает ошибку И отчёт; отчёт этот —
	// нулевой, а у нулевого значения `len(Findings) == 0` и
	// `NothingToJudge == false`. Без этого признака нулевой отчёт отвечал бы
	// «допущено» и печатал «находок 0», то есть читался бы как ЧИСТЫЙ — ровно на
	// том входе, ради которого клауза fail-closed заведена (kacho#2000).
	//
	// Контракт «вызывающий обязан проверить err раньше Admitted()» исполним, но
	// исполним только тем, кто о нём помнит: естественная форма
	// `rep, err := Admit(x); if !rep.Admitted() { … }` даёт fail-open. Величина,
	// которую построение подставляет молча, предметом стража быть не может
	// (§«Пустой список — это „не сужаем"»), поэтому строгость здесь
	// держится УМОЛЧАНИЕМ, а не дисциплиной вызывающего: число вызывающих будет
	// расти, а нулевое значение останется одно.
	Judged bool
	// TypesSeen — сколько блоков типа осмотрено (перечень, а не множество имён).
	// Ноль означает, что до разбора дело не дошло, и [AdmissionReport.Census] это
	// говорит: «ноль находок» обязано быть отличимо от «ноль прочитанного».
	TypesSeen int
	// TypesNew — сколько РАЗЛИЧНЫХ имён собранной модели канон не несёт.
	TypesNew int
	// Findings — находки в порядке правил и координат, детерминированном.
	Findings []Finding
	// NothingToJudge — третий исход. Предикат ОДИН: TypesNew == 0. Прежние два
	// признака («суффикс пуст» и «текст равен канону») расходились на тексте
	// «канон + перевод строки»; выбран тот, что совпадает с предметом правила:
	// судить нечего ровно тогда, когда судить некого.
	NothingToJudge bool
	// TerminatedAtD7 — правила после Д7 не исполнялись. Без этого признака
	// «находок 1» читалось бы как «остальное чисто».
	TerminatedAtD7 bool
	// ComputedOnlyWildcards — величина СОБСТВЕННОЙ ПРЕМИССЫ допуска: сколько пар
	// достигают подстановки ТОЛЬКО шагом `Term.Computed` внутри канонического
	// типа. Ребро `Computed` внутри НОВОГО типа проходится всегда (редакция
	// kaname#866: законные термы ключа — точки с классом в новом типе, и
	// объявление, выведенное из них, судится само), а внутри канонического —
	// переключается; эта величина и есть разница двух счётов. Печатается ВСЕГДА:
	// иначе премисса осталась бы утверждением без производителя — той же формой
	// без содержания, только этажом выше клаузы.
	ComputedOnlyWildcards int
}

// Admitted — допущена ли композиция.
//
// Утверждение ПОЛОЖИТЕЛЬНОЕ: допущено ровно то, что было СУЖДЕНО и не дало
// находок. Ни третий исход, ни несостоявшееся суждение успехом НЕ являются, и
// отличать их друг от друга здесь не требуется — оба означают «не допущено».
func (r AdmissionReport) Admitted() bool {
	return r.Judged && len(r.Findings) == 0 && !r.NothingToJudge
}

// Census — перепись. Печатается ВСЕГДА, в том числе при находке и при третьем
// исходе.
func (r AdmissionReport) Census() string {
	s := fmt.Sprintf("типов осмотрено %d, новых %d, находок %d",
		r.TypesSeen, r.TypesNew, len(r.Findings))
	// Несостоявшееся суждение называется ПЕРВЫМ и отдельным словом: при нём
	// остальные величины переписи ничего не измеряют, а «находок 0» читается
	// оператором как «чисто». Это тот же предмет, что «ноль находок обязано быть
	// отличимо от ноль прочитанного», применённый к самому отчёту.
	if !r.Judged {
		return s + "; суждение не состоялось, и в успех это НЕ засчитывается"
	}
	if r.TerminatedAtD7 {
		return s + "; правила после Д7 не исполнялись"
	}
	s += fmt.Sprintf("; подстановок, достижимых только через Term.Computed: %d", r.ComputedOnlyWildcards)
	// Третий исход объявляется словом только тогда, когда он и есть исход.
	// Предикат его остаётся ОДИН и живёт полем [AdmissionReport.NothingToJudge];
	// но фраза «судить нечего», напечатанная рядом с находкой, читается
	// оператором как «всё в порядке», тогда как исход там — ОТКАЗ. Само число
	// новых типов при этом никуда не девается: оно уже названо выше.
	if r.NothingToJudge && len(r.Findings) == 0 {
		s += "; судить нечего, и в успех это НЕ засчитывается"
	}
	return s
}

// Admit судит собранную модель против канона ОБРАЗА.
//
// Ошибка возвращается там, где судить не о чем: канон образа не разобрался либо
// разбор собранного текста не состоялся. Отказ разбора — НЕ третий исход и не
// «ноль находок»: пустой перечень находок читался бы как «чисто».
//
// Вызывающий обязан вести себя fail-closed: композиция, не прошедшая допуск, не
// «пропускается с предупреждением».
//
// Канон разбирается ЗДЕСЬ, а не берётся у [Shared]: допуск — чистая функция, и
// ответ её не вправе зависеть от того, наполнил ли кто-то запомненные планы
// раньше. Цена — один разбор канона на вызов; допуск зовётся на пути ПУСКА, а не
// на пути запроса.
//
// keyTerms — термы, которые ключ публичного чтения вписал в блоки НОВЫХ типов
// этого текста (их производит тот же вызов композиции, что собрал текст). Пусто —
// строгий режим. Запись, которой текст не несёт, — отказ ([ErrKeyTermNotInText]):
// перечень, описывающий другой текст, исключал бы то, чего ключ здесь не писал.
func Admit(composed string, keyTerms ...KeyTerm) (AdmissionReport, error) {
	return admit(DSL, composed, keyTerms...)
}

// KeyTerm — один терм, который ключ публичного чтения вписал в объявление
// НОВОГО типа (kaname#866, Р1). Термов три вида, и только эти:
//
//   - контейнер, `public_reader`: голая запись класса (Pointer пуст);
//   - контейнер, отношение действия чтения: голая запись класса (Pointer пуст);
//   - ребёнок, отношение действия чтения: `public_reader from <Pointer>`.
//
// Исключение снимает с суждения Д3 ровно этот терм и ровно в этом объявлении:
// прочие записи того же объявления судятся как без перечня.
type KeyTerm struct {
	// Type — новый тип, в блоке которого стоит терм.
	Type string
	// Relation — объявление, в котором стоит терм.
	Relation string
	// Pointer — пусто у голой записи класса; иначе указатель терма
	// `public_reader from <Pointer>`.
	Pointer string
}

func (k KeyTerm) String() string {
	if k.Pointer == "" {
		return k.Type + "." + k.Relation + " [" + string(domain.SubjectTypeSystemClass) + "]"
	}
	return k.Type + "." + k.Relation + " [" + domain.PublicReaderRelation + " from " + k.Pointer + "]"
}

// ErrKeyTermNotInText — перечень термов ключа называет терм, которого собранный
// текст не несёт, либо тип, которого нет среди новых типов текста. Суждение не
// состоялось: перечень описывает не этот текст.
var ErrKeyTermNotInText = errors.New("authzmodel: допуск: перечень термов ключа не описывает собранный текст")

// admit — параметризованная форма. НЕ экспортирована: см. шапку файла про
// самоудовлетворимость.
//
// Признак [AdmissionReport.Judged] ставится ЗДЕСЬ и ровно в одном месте — на
// пути, где вердикт действительно вынесен. Форма выбрана СТРУКТУРНОЙ, а не
// «поставить признак у каждого return»: путь ошибки, добавленный в [judge]
// завтра, получит строгое умолчание сам, ничего для этого не делая. Перечень
// мест, которые автор обязан не забыть, разошёлся бы с кодом на первом же
// новом отказе — и разошёлся бы молча, в сторону «допущено».
func admit(canon, composed string, keyTerms ...KeyTerm) (AdmissionReport, error) {
	rep, err := judge(canon, composed, keyTerms)
	if err != nil {
		// Отчёт по пути ошибки отдаётся КАК ЕСТЬ, без признака суждения: он
		// несёт то, что успели осмотреть, и не выдаёт этого за вердикт.
		return rep, err
	}
	rep.Judged = true
	return rep, nil
}

// judge — сами правила. Всякий её `nil`-возврат есть ВЕРДИКТ (в том числе
// остановка на Д7); всякая ошибка — «судить не о чем».
func judge(canon, composed string, keyTerms []KeyTerm) (AdmissionReport, error) {
	var rep AdmissionReport

	// Канон разбирается ПЕРВЫМ: из него выводятся закрытые наборы (имена типов,
	// имена условий). Выписанный список разошёлся бы с каноном молча, а
	// неразбираемый канон означает, что сверять не с чем, — это отказ, а не
	// чистый отчёт.
	canonModel, err := authzplan.ParseModel(canon)
	if err != nil {
		return rep, fmt.Errorf("authzmodel: допуск: разбор канона образа не состоялся: %w", err)
	}

	// ── Д7(а) ────────────────────────────────────────────────────────────────
	if !strings.HasPrefix(composed, canon) {
		off := firstDivergence(canon, composed)
		rep.TerminatedAtD7 = true
		rep.Findings = append(rep.Findings, Finding{
			Rule: RuleD7Prefix,
			Text: fmt.Sprintf("текст канона в собранной модели не найден дословно: "+
				"первое расхождение на байте %d (строка %d)", off, 1+strings.Count(composed[:off], "\n")),
		})
		return rep, nil
	}

	// ── Д7(б) ────────────────────────────────────────────────────────────────
	if fs := suffixFormFindings(canon, composed); len(fs) > 0 {
		rep.TerminatedAtD7 = true
		rep.Findings = fs
		return rep, nil
	}

	// ── разбор собранного ────────────────────────────────────────────────────
	m, err := authzplan.ParseModel(composed)
	if err != nil {
		return rep, fmt.Errorf("authzmodel: допуск: разбор не состоялся: %w", err)
	}

	canonTypes := map[string]bool{}
	for _, t := range canonModel.Types {
		canonTypes[t.Name] = true
	}
	canonConditions := map[string]bool{}
	for _, c := range canonModel.Conditions {
		canonConditions[c] = true
	}

	rep.TypesSeen = len(m.Types)
	newNames := map[string]bool{}
	var newOrder []string
	for _, t := range m.Types {
		if canonTypes[t.Name] || newNames[t.Name] {
			continue
		}
		newNames[t.Name] = true
		newOrder = append(newOrder, t.Name)
	}
	rep.TypesNew = len(newOrder)
	rep.NothingToJudge = rep.TypesNew == 0

	dupTypeName, d1 := occurrenceFindings(m)
	rep.Findings = append(rep.Findings, d1...)

	lawful, err := lawfulKeyTerms(m, newNames, keyTerms)
	if err != nil {
		return rep, err
	}
	d3, premise := reachableWildcardFindings(m, newNames, lawful)
	rep.Findings = append(rep.Findings, d3...)
	rep.ComputedOnlyWildcards = premise

	rep.Findings = append(rep.Findings, subjectFindings(m, newNames, canonConditions)...)
	rep.Findings = append(rep.Findings, inexpressiblePlanFindings(m, newOrder)...)

	// ── Д8 ───────────────────────────────────────────────────────────────────
	//
	// ФАКТ отказа берётся у существующего метода, ТЕКСТ производится здесь: его
	// текст перечисляет указатели обходом КАРТЫ, а порядок обхода карты в Go
	// рандомизирован — 400 прогонов на одном входе дают два разных текста.
	// Проба, закрепляющая такой текст, флейкует by construction.
	//
	// Метод НЕ зовётся на задвоенном имени типа, и предмет этой клаузы — АТРИБУЦИЯ,
	// а не защита от паники. Паники больше нет: с kacho#1987 метод на таком имени
	// отвечает ОТКАЗОМ, потому что его утверждение там не определено — какой блок
	// действует, решал бы порядок сборки. Но отказ, вынесенный по этой причине,
	// правилу Д8 не принадлежит: Д8 говорит «два указателя в один тип-предок», и
	// приписать ему чужой отказ значило бы назвать сработавшим правило, предмета
	// которого на этом входе нет. Такой вход уже отвергнут Д1 выше, поэтому
	// fail-closed не страдает.
	//
	// Проба TestAdmitSurvivesSplitPointerNamesAcrossDuplicateBlocks держит обе
	// половины: метод отвечает отказом без паники, а находок Д8 при этом ноль.
	if !dupTypeName && m.AssertOnePointerPerParentType() != nil {
		rep.Findings = append(rep.Findings, pointerAmbiguityFindings(m)...)
	}

	return rep, nil
}

// firstDivergence — смещение первого расхождения байтов. Усечение собранного
// текста считается расхождением на его конце: канона там просто нет.
func firstDivergence(canon, composed string) int {
	n := min(len(canon), len(composed))
	for i := range n {
		if canon[i] != composed[i] {
			return i
		}
	}
	return n
}

// suffixFormFindings — Д7(б).
//
// Строка судится по ПЕРВОМУ СЛОВУ, а форма имени типа входит в форму строки
// `type`: предикат один. Пустая строка в перечне форм ОБЯЗАТЕЛЬНА — блоки
// композиции разделены пустой строкой, и белый список без неё покраснел бы на
// первой же законной композиции.
//
// Форма `define` проверяется по первому слову и не глубже: `define v_get:` и
// `define v_get: [user] and super_admin` — законные СТРОКИ, которые отвергает
// РАЗБОР. Сузив здесь, допуск отобрал бы у отказа разбора его собственный вход.
func suffixFormFindings(canon, composed string) []Finding {
	suffix := composed[len(canon):]
	base := strings.Count(canon, "\n") + 1

	var out []Finding
	for i, raw := range strings.Split(suffix, "\n") {
		line := strings.TrimSpace(raw)
		num := base + i
		switch {
		case line == "", strings.HasPrefix(line, "#"), line == "relations", strings.HasPrefix(line, "define "):
			continue
		case strings.HasPrefix(line, "type "):
			name := strings.TrimSpace(strings.TrimPrefix(line, "type "))
			if domain.IsWellFormedObjectTypeName(name) {
				continue
			}
			out = append(out, Finding{
				Rule: RuleD7Suffix,
				Type: name,
				Text: fmt.Sprintf("строка %d: имя типа %q не отвечает форме %s: %q",
					num, name, domain.ObjectTypeNameGrammar(), line),
			})
		default:
			out = append(out, Finding{
				Rule: RuleD7Suffix,
				Text: fmt.Sprintf("строка %d: строка вне пяти форм суффикса "+
					"(пустая · комментарий · relations · define · type): %q", num, line),
			})
		}
	}
	return out
}

// occurrenceFindings — Д1, счёт вхождений по ПЕРЕЧНЮ, не членство в множестве.
//
// Формулировка через множество здесь молчит: у задвоенного типа различных имён
// столько же, сколько было. Первым возвращается признак задвоенного ИМЕНИ ТИПА —
// он нужен Д8 (см. её место вызова).
func occurrenceFindings(m *authzplan.Model) (bool, []Finding) {
	var out []Finding

	byType := map[string]int{}
	var typeOrder []string
	for _, t := range m.Types {
		if byType[t.Name] == 0 {
			typeOrder = append(typeOrder, t.Name)
		}
		byType[t.Name]++
	}
	dup := false
	for _, name := range typeOrder {
		if byType[name] < 2 {
			continue
		}
		dup = true
		out = append(out, Finding{
			Rule: RuleD1,
			Type: name,
			Text: fmt.Sprintf("имя типа %q встречается в модели %d раза — какой блок действует, "+
				"решал бы порядок сборки, а не решение", name, byType[name]),
		})
	}

	seenPair := map[string]bool{}
	for _, t := range m.Types {
		byRel := map[string]int{}
		var relOrder []string
		for _, r := range t.Relations {
			if byRel[r.Name] == 0 {
				relOrder = append(relOrder, r.Name)
			}
			byRel[r.Name]++
		}
		for _, name := range relOrder {
			key := t.Name + "." + name
			if byRel[name] < 2 || seenPair[key] {
				continue
			}
			seenPair[key] = true
			out = append(out, Finding{
				Rule:     RuleD1,
				Type:     t.Name,
				Relation: name,
				Text: fmt.Sprintf("отношение %q объявлено у типа %q %d раза — действует последнее, "+
					"и решает это порядок манифеста", name, t.Name, byRel[name]),
			})
		}
	}
	return dup, out
}

// declarationsNamed — ВСЕ объявления типа с этим именем.
//
// Перечень, а не `Rel()`: доступ по имени отдаёт ПОСЛЕДНЕЕ объявление, и
// подстановка, спрятанная за ним, была бы невидима. Задвоенное имя ловит и Д1, но
// двух молчаний не складывают.
func declarationsNamed(t *authzplan.ModelType, name string) []*authzplan.Relation {
	var out []*authzplan.Relation
	for _, r := range t.Relations {
		if r.Name == name {
			out = append(out, r)
		}
	}
	return out
}

// isWildcardLike — запись субъекта делает пару разрешаемой подстановкой.
// Признак — ПОЛЕ разбора (`DirectSubject.Wildcard`), а не написание `:*` в
// тексте: написание живёт в `Term.Raw`, и сверка по нему разошлась бы с разбором
// на первой же правке грамматики.
//
// Системный класс — та же подстановка по смыслу: отношение, принимающее класс
// прямо (`system_class`, `system_class:<имя>`), выполнимо «каждым вошедшим» или
// «каждым без входа». Словарь классов объявлен ядром, и модуль его не вносит
// (SC-37) — по тому же доводу, по которому не вносит `user:*`. Узнаётся по типу
// записи разбора, а не по написанию; правило «слово — класс» объявлено одно на
// дерево ([domain.IsClassSubjectWord]), его же читает загрузчик манифеста.
func isWildcardLike(d authzplan.DirectSubject) bool {
	return d.Wildcard || domain.IsClassSubjectWord(d.Type)
}

// bareClassRecord — голая запись класса, как её пишет ключ публичного чтения.
// Только она исключается термом ключа (CE-06): `system_class:<класс>` и `user:*`
// ключ не пишет никогда, и у них исключения нет ни в какой позиции.
var bareClassRecord = authzplan.DirectSubject{Type: string(domain.SubjectTypeSystemClass)}.String()

// wildcardRecords — записи субъектов пары, делающие её разрешаемой подстановкой
// (признак — [isWildcardLike]).
func wildcardRecords(m *authzplan.Model, typeName, relation string) []string {
	t := m.Type(typeName)
	if t == nil {
		return nil
	}
	var out []string
	for _, r := range declarationsNamed(t, relation) {
		for _, term := range r.Terms {
			for _, d := range term.Direct {
				if isWildcardLike(d) {
					out = append(out, d.String())
				}
			}
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// pair — узел замыкания Д3.
type pair struct{ typeName, relation string }

func (p pair) String() string { return p.typeName + "." + p.relation }

// keyTermSet — термы ключа, ставшие законными: исключение по [KeyTerm].
type keyTermSet struct {
	// class — объявления, где голая запись класса законна.
	class map[pair]bool
	// via — объявления и указатели, где терм `public_reader from <указатель>`
	// законен.
	via map[pair]map[string]bool
}

// lawfulKeyTerms — перечень ключа, сверенный с ТЕКСТОМ.
//
// Отказ ([ErrKeyTermNotInText]) — на всякой записи, которой текст не несёт: тип
// не из новых, объявления нет, голой записи класса либо терма с этим указателем
// в объявлении нет. Перечень, разошедшийся с текстом, описывает другую сборку, и
// исключать по нему — значит исключать вслепую. Называются ВСЕ такие записи.
//
// Терм ребёнка становится законным, только когда его указатель ведёт в НОВЫЙ тип,
// объявленный контейнером этим же перечнем (CE-07): резать ребро «ребёнок →
// контейнер» безопасно лишь потому, что `public_reader` такого контейнера сам
// стоит в посеве и судится как своё семя. Указатель в канонический тип либо в
// новый тип без `public_reader` в перечне — терм в тексте есть, но законным он не
// становится, и путь через него остаётся находкой.
func lawfulKeyTerms(m *authzplan.Model, newNames map[string]bool, keyTerms []KeyTerm) (keyTermSet, error) {
	set := keyTermSet{class: map[pair]bool{}, via: map[pair]map[string]bool{}}
	var absent []string
	type viaTerm struct {
		at  pair
		ptr string
	}
	var pending []viaTerm
	for _, kt := range keyTerms {
		t := m.Type(kt.Type)
		if !newNames[kt.Type] || t == nil {
			absent = append(absent, kt.String()+": тип не из новых типов текста")
			continue
		}
		at := pair{kt.Type, kt.Relation}
		found := false
		for _, r := range declarationsNamed(t, kt.Relation) {
			for _, term := range r.Terms {
				switch {
				case kt.Pointer == "" && term.Kind == authzplan.TermDirect:
					for _, d := range term.Direct {
						if d.String() == bareClassRecord {
							found = true
						}
					}
				case kt.Pointer != "" && term.Kind == authzplan.TermTTU &&
					term.TTUPointer == kt.Pointer && term.TTURelation == domain.PublicReaderRelation:
					found = true
				}
			}
		}
		if !found {
			absent = append(absent, kt.String()+": объявление такого терма не несёт")
			continue
		}
		if kt.Pointer == "" {
			set.class[at] = true
			continue
		}
		pending = append(pending, viaTerm{at: at, ptr: kt.Pointer})
	}
	if len(absent) > 0 {
		return keyTermSet{}, fmt.Errorf("%w: %s", ErrKeyTermNotInText, strings.Join(absent, "; "))
	}
	for _, v := range pending {
		// Судятся ВСЕ объявления указателя: задвоенное имя ловит и Д1, но двух
		// молчаний не складывают.
		var targets []string
		for _, decl := range declarationsNamed(m.Type(v.at.typeName), v.ptr) {
			targets = append(targets, m.PointerTargets(decl)...)
		}
		lawful := len(targets) > 0
		for _, target := range targets {
			if !newNames[target] || !set.class[pair{target, domain.PublicReaderRelation}] {
				lawful = false
			}
		}
		if !lawful {
			continue
		}
		if set.via[v.at] == nil {
			set.via[v.at] = map[string]bool{}
		}
		set.via[v.at][v.ptr] = true
	}
	return set, nil
}

// reachableWildcardFindings — Д3 и величина собственной премиссы допуска.
//
// # Правило ПОСЕВА
//
// Замыкание сеется КАЖДЫМ объявлением нового типа — не только его действиями. Это
// несущее: при узком посеве (одни действия) подстановка, достижимая через
// отношение, которым не пользуется ни одно действие, не находится вовсе. Цена
// широкого посева названа честно: мёртвое отношение, достигающее подстановки,
// будет отвергнуто, хотя ни одного вердикта не меняет.
//
// # Обход — от КАЖДОГО семени отдельно, находка — на семени
//
// Редакция kaname#866 (приёмка public-read-container-of-a-module-type-is-admitted.md,
// Р1/Р3). У каждого семени свой обход в ширину и своё множество посещённых, и
// находка ставится на ОБЪЯВЛЕНИЕ-СЕМЯ, из которого класс либо подстановка
// достижимы: одна на семя, а не одна на достигнутую пару с записью. Иначе
// исключение законных термов, наложенное на пару, снимало бы вместе с ними
// единственный сигнал об объявлении, которое до этих термов достаёт
// (`v_update` от `v_get`, авторское отношение от `public_reader`).
//
// Исключение термов ключа ([KeyTerm], перечень Р4 — типы, объявленные ключом)
// действует ТОЛЬКО на узле, равном семени: голая запись класса и терм
// `public_reader from <указатель>` законны в своём объявлении и больше нигде.
// Путь через законную точку ДРУГОГО объявления законным не становится.
//
// Поля находки: `Type`/`Relation` — семя; `Term` — отсортированные уникальные
// записи подстановки, достигнутые от семени; `Text` — путь до ПЕРВОГО попадания
// обхода в ширину и записи там. Порядок находок — по семени: тип, затем
// отношение в порядке объявления. Обход идёт по срезам, а не по картам, поэтому
// текст и порядок от прогона к прогону одни.
//
// # Рёбра
//
// Их три: `Term.TTU`, `DirectSubject.Userset` и `Term.Computed`. Ребро
// `Computed` проходится внутри нового типа (законная точка с классом в новом
// типе есть, и объявление, выведенное из неё — `or v_get`, — обязано стать
// находкой само) и внутри канонического (объявления канона в семя не кладутся).
// Величина премиссы — разница счётов с ребром `Computed` внутри канона и без
// него; внутри нового типа ребро включено в обоих плечах.
//
// # Судятся только НОВЫЕ типы
//
// Блоки канона судит Д7 — байтами, и ничем иным. Допуск, судящий Д3 по всей
// модели, покраснел бы на самом каноне: тот несёт подстановку в двух местах.
func reachableWildcardFindings(m *authzplan.Model, newNames map[string]bool, lawful keyTermSet) ([]Finding, int) {
	var seeds []pair
	seeded := map[pair]bool{}
	for _, t := range m.Types {
		if !newNames[t.Name] {
			continue
		}
		for _, r := range t.Relations {
			s := pair{t.Name, r.Name}
			if seeded[s] {
				continue
			}
			seeded[s] = true
			seeds = append(seeds, s)
		}
	}
	if len(seeds) == 0 {
		return nil, 0
	}

	full := map[pair]bool{}
	canonEdgeless := map[pair]bool{}
	var out []Finding
	for _, seed := range seeds {
		order, from := reach(m, newNames, seed, lawful, true)
		without, _ := reach(m, newNames, seed, lawful, false)
		for _, p := range order {
			full[p] = true
		}
		for _, p := range without {
			canonEdgeless[p] = true
		}

		var records []string
		var first pair
		var firstRecords []string
		for _, p := range order {
			recs := wildcardRecords(m, p.typeName, p.relation)
			if p == seed && lawful.class[seed] {
				recs = slices.DeleteFunc(slices.Clone(recs), func(r string) bool { return r == bareClassRecord })
			}
			if len(recs) == 0 {
				continue
			}
			if firstRecords == nil {
				first, firstRecords = p, recs
			}
			records = append(records, recs...)
		}
		if firstRecords == nil {
			continue
		}
		slices.Sort(records)
		records = slices.Compact(records)

		at := strings.Join(firstRecords, ", ")
		text := fmt.Sprintf("%s: подстановочная запись субъекта %s", first, at)
		if path := pathTo(from, first.String()); len(path) > 1 {
			names := make([]string, 0, len(path))
			for _, q := range path {
				names = append(names, q.String())
			}
			text = fmt.Sprintf("подстановка достижима: %s; запись %s", strings.Join(names, " → "), at)
		}
		out = append(out, Finding{
			Rule:     RuleD3,
			Type:     seed.typeName,
			Relation: seed.relation,
			Term:     strings.Join(records, ", "),
			Text:     text,
		})
	}

	// Премисса — как прежде: пары с записью подстановки, достижимые ТОЛЬКО
	// шагом `Computed` внутри канонического типа (по объединению обходов всех
	// семян; записи — без исключения термов, оно о семени, а не о паре).
	premise := 0
	for p := range full {
		if canonEdgeless[p] || len(wildcardRecords(m, p.typeName, p.relation)) == 0 {
			continue
		}
		premise++
	}
	return out, premise
}

// reach — обход в ширину от ОДНОГО семени. Возвращает достигнутое в порядке
// обхода (начиная с семени) и карту предшественников, по которой
// восстанавливается путь для отказа.
//
// На узле, равном семени, ребро законного терма `public_reader from <указатель>`
// не проходится ([lawfulKeyTerms]); на всяком другом узле — проходится.
func reach(m *authzplan.Model, newNames map[string]bool, seed pair, lawful keyTermSet, computedInsideCanon bool) ([]pair, map[string]string) {
	seen := map[pair]bool{seed: true}
	from := map[string]string{seed.String(): ""}
	order := []pair{seed}
	for i := 0; i < len(order); i++ {
		cur := order[i]
		t := m.Type(cur.typeName)
		if t == nil {
			continue
		}
		var next []pair
		for _, r := range declarationsNamed(t, cur.relation) {
			for _, term := range r.Terms {
				switch term.Kind {
				case authzplan.TermComputed:
					if newNames[cur.typeName] || computedInsideCanon {
						next = append(next, pair{cur.typeName, term.Computed})
					}
				case authzplan.TermTTU:
					if cur == seed && term.TTURelation == domain.PublicReaderRelation && lawful.via[seed][term.TTUPointer] {
						continue
					}
					for _, ptr := range declarationsNamed(t, term.TTUPointer) {
						for _, target := range m.PointerTargets(ptr) {
							next = append(next, pair{target, term.TTURelation})
						}
					}
				case authzplan.TermDirect:
					for _, d := range term.Direct {
						if d.Userset != "" {
							next = append(next, pair{d.Type, d.Userset})
						}
					}
				}
			}
		}
		for _, n := range next {
			if seen[n] {
				continue
			}
			seen[n] = true
			from[n.String()] = cur.String()
			order = append(order, n)
		}
	}
	return order, from
}

// pathTo восстанавливает путь от посева до пары.
func pathTo(from map[string]string, key string) []pair {
	var keys []string
	for cur := key; cur != ""; cur = from[cur] {
		keys = append(keys, cur)
		if _, ok := from[cur]; !ok {
			break
		}
	}
	out := make([]pair, 0, len(keys))
	for i := len(keys) - 1; i >= 0; i-- {
		k := keys[i]
		j := strings.LastIndex(k, ".")
		if j < 0 {
			continue
		}
		out = append(out, pair{k[:j], k[j+1:]})
	}
	return out
}

// subjectFindings — Д4(а) и Д4(б).
//
// Закрытые наборы ВЫВОДЯТСЯ: «отношение объявлено» — вопрос к типу-носителю
// собранной модели (новый тип вправе ссылаться на другой новый тип своей же
// поставки — платформа применяет ровно эту форму к своему модулю реестра), «имя
// условия знакомо» — вопрос к канону.
func subjectFindings(m *authzplan.Model, newNames map[string]bool, canonConditions map[string]bool) []Finding {
	var out []Finding
	for _, t := range m.Types {
		if !newNames[t.Name] {
			continue
		}
		for _, r := range t.Relations {
			for _, term := range r.Terms {
				for _, d := range term.Direct {
					if d.Userset != "" {
						carrier := m.Type(d.Type)
						if carrier == nil || len(declarationsNamed(carrier, d.Userset)) == 0 {
							out = append(out, Finding{
								Rule:     RuleD4Userset,
								Type:     t.Name,
								Relation: r.Name,
								Term:     d.String(),
								Text: fmt.Sprintf("%s.%s: тип %q не объявляет отношения %q, которого требует запись %q",
									t.Name, r.Name, d.Type, d.Userset, d.String()),
							})
						}
					}
					if d.Condition != "" && !canonConditions[d.Condition] {
						out = append(out, Finding{
							Rule:     RuleD4Condition,
							Type:     t.Name,
							Relation: r.Name,
							Term:     d.String(),
							Text: fmt.Sprintf("%s.%s: условие %q канон не объявляет; запись %q",
								t.Name, r.Name, d.Condition, d.String()),
						})
					}
				}
			}
		}
	}
	return out
}

// inexpressiblePlanFindings — Д5′.
//
// В слот встало именно это правило, а не «вывод не выходит за пределы блока»: у
// того производителя нет ни при каком входе, а у выразимости есть — вход,
// который разбор принимает, Д1–Д4 пропускают, а компиляция объявляет
// невыразимым. Без клаузы служба поднимается, а внутренняя ошибка достаётся
// арендатору на КОРРЕКТНОМ запросе.
func inexpressiblePlanFindings(m *authzplan.Model, newOrder []string) []Finding {
	var out []Finding
	for _, name := range newOrder {
		t := m.Type(name)
		if t == nil {
			continue
		}
		seen := map[string]bool{}
		for _, r := range t.Relations {
			if seen[r.Name] {
				continue
			}
			seen[r.Name] = true
			plan, err := m.Compile(name, r.Name)
			if err != nil {
				out = append(out, Finding{
					Rule: RuleD5, Type: name, Relation: r.Name,
					Text: fmt.Sprintf("%s.%s: план не построен: %v", name, r.Name, err),
				})
				continue
			}
			if plan.Expressible() {
				continue
			}
			// Unclassified компиляция уже приводит к порядку.
			out = append(out, Finding{
				Rule: RuleD5, Type: name, Relation: r.Name,
				Term: strings.Join(plan.Unclassified, "; "),
				Text: fmt.Sprintf("%s.%s: план невыразим, не отнесены термы: %s",
					name, r.Name, strings.Join(plan.Unclassified, "; ")),
			})
		}
	}
	return out
}

// pointerAmbiguityFindings — текст находки Д8, произведённый ЗДЕСЬ.
//
// Обход идёт по перечню типов и по ОТСОРТИРОВАННЫМ именам указателей, поэтому
// текст один при любом обходе карты. Метод-источник возвращает на ПЕРВОЙ такой
// паре, этот обход перечисляет ВСЕ, — поэтому перечень непуст всякий раз, когда
// метод отказал: предикат тот же и данные те же.
func pointerAmbiguityFindings(m *authzplan.Model) []Finding {
	var out []Finding
	reported := map[string]bool{}
	for _, t := range m.Types {
		names := make([]string, 0, len(m.Pointers[t.Name]))
		for rel := range m.Pointers[t.Name] {
			names = append(names, rel)
		}
		slices.Sort(names)

		byTarget := map[string][]string{}
		var targets []string
		for _, rel := range names {
			for _, ptr := range declarationsNamed(t, rel) {
				for _, target := range m.PointerTargets(ptr) {
					if _, ok := byTarget[target]; !ok {
						targets = append(targets, target)
					}
					byTarget[target] = append(byTarget[target], rel)
				}
			}
		}
		slices.Sort(targets)
		for _, target := range targets {
			ptrs := slices.Compact(slices.Clone(byTarget[target]))
			key := t.Name + "→" + target
			if len(ptrs) < 2 || reported[key] {
				continue
			}
			reported[key] = true
			out = append(out, Finding{
				Rule: RuleD8,
				Type: t.Name,
				Term: strings.Join(ptrs, ", "),
				Text: fmt.Sprintf("тип %q ведёт в %q более чем одним указателем: %s",
					t.Name, target, strings.Join(ptrs, ", ")),
			})
		}
	}
	return out
}
