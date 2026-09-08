// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzformbench

import (
	"fmt"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// Form — форма хранения права, которую прибор измеряет.
//
// Значение осталось ОДНО. Их было шесть: пять описывали, как разложить выдачу в
// кортежи внешнего движка отношений (плоско, через группу, через отношение роли,
// через контейнер и композицией), шестая — реляционная — вычисляла вердикт
// запросом к БД. Движок снят целиком (S6), и вместе с ним снялись пять форм: они
// были формами хранения В НЁМ и измеряться иначе не могли.
//
// Тип оставлен при одном значении намеренно, и это не «на будущее»: он читается —
// ячейка отчёта им подписана, и подпись «E-relational» отвечает на вопрос, к чему
// относятся числа. Отчёт, потерявший имя формы, стал бы таблицей чисел без
// предмета — а уже опубликованные отчёты (REPORT-*) подписаны именно так, и
// сопоставимость с ними держится этой подписью.
type Form string

// FormE — реляционная форма: вердикт вычисляется запросом к БД поверх зеркала
// объектов, внешнего движка отношений нет. Выдача — строка привязки, её субъекты
// и её правило-селектор: S + 2. Разворота в состав нет by construction.
const FormE Form = "E-relational"

// AllForms — перечень измеряемых форм в порядке отчёта.
var AllForms = []Form{FormE}

// BenchType — тип объекта, на котором снимается замер.
//
// Переехал сюда из снятого файла преобразований модели: там он называл тип, чьи
// глаголы переписывались под формы C и D, здесь — просто тип объектов фикстуры.
const BenchType = "vpc_network"

// Fixture ids. Fixed strings, not random: the comparison is between shapes, and a
// difference in ids would be a difference in the data (requirement 3).
const (
	// Якорь кластера берётся из ОБЪЯВЛЕНИЯ продукта, а не повторяется строкой:
	// фикстура моделирует настоящий мир, и переход написания обязан доехать и
	// до неё. Соседние идентификаторы синтетические и остаются как есть.
	clusterObj = "cluster:" + domain.ClusterSingletonID
	accountObj = "account:acc-bench"
	projectObj = "project:prj-bench"
	labelObj   = "label_set:lbl-bench"

	// ЧУЖОЙ арендатор — второй аккаунт того же кластера и его проект.
	//
	// Заведён не для полноты картины, а потому что без него один конъюнкт вердикта
	// формы E — область выдачи — ТОЖДЕСТВЕННО ИСТИНЕН: когда аккаунт и проект в
	// фикстуре по одному, «объект лежит в области привязки» верно про каждый объект,
	// о котором вопросник спрашивает. Инъекция «выкинуть проверку области целиком»
	// оставляла зелёными все шесть проб вердикта (найдено адверсарной проверкой
	// 2026-08-10). Различающая сила была у трёх конъюнктов из четырёх, а решение
	// принимается для МНОГОАРЕНДНОЙ системы — и именно на кросс-арендной границе
	// реляционная переписка правдоподобно расходится с движком: у формы A отказ на
	// чужом объекте СТРУКТУРЕН (кортежа нет — разрешать нечему), у формы E он
	// держится на рукописном условии транзитивной вложенности области.
	otherAccountObj = "account:acc-bench-other"
	otherProjectObj = "project:prj-bench-other"

	// Привязка формы E и её «встраиваемый» близнец — тот, что пишется в одной
	// транзакции с предметом выдачи.
	bindingObj       = "access_binding:ab-bench"
	inlineBindingObj = "access_binding:ab-inline"

	// Каскадный принципал — администратор аккаунта (уровень 3 супер-доступа).
	cascadeAdmin = "user:cascade-account-admin"
)

// Словарь намерения — отношения, которыми описывается мутация.
//
// Форма E переводит его в строки на своей стороне. Словарь пережил пять форм,
// которые писали его как есть (это была их wire-форма), и не переписан под
// единственную оставшуюся намеренно: производители намерения ниже остались
// нетронутыми, а значит числа сегодняшних прогонов сравнимы с уже
// опубликованными отчётами.
const (
	bindingRelPrefix       = "binding_role_"         // + роль; User — объект области
	bindingSubjectRel      = "binding_subject"       // субъект привязки
	bindingSelectorRel     = "binding_selector"      // правило-селектор привязки
	labelsRel              = "labels"                // объект входит в набор (общее с формой D)
	cascadeAccountAdminRel = "cascade_account_admin" // каскад, уровень 3
	cascadeClusterAdminRel = "cascade_cluster_admin" // каскад, уровни 1-2
)

// Scenario is the ONE dataset every shape is measured against.
type Scenario struct {
	N        int      // objects inside the selected set
	Spare    int      // objects OUTSIDE it, kept for the relabel operations
	Verbs    []string // M — the verbs the role grants
	Subjects []string // S — full principal strings, e.g. "user:u000"
	Role     string   // "viewer" | "editor" — selects the C/D grant relation
}

// DefaultVerbs is the verb set 22 of the model's 24 verb-bearing types declare.
func DefaultVerbs() []string { return []string{"v_get", "v_list", "v_update", "v_delete"} }

// NewScenario builds the dataset. Subjects are `user:` principals because that is
// what a tenant binding names; `service_account:` resolves through the same direct
// userset and would not change the shape of the graph.
func NewScenario(n, spare, subjects int, role string, verbs []string) Scenario {
	subs := make([]string, subjects)
	for i := range subs {
		subs[i] = fmt.Sprintf("user:u%04d", i)
	}
	return Scenario{N: n, Spare: spare, Verbs: verbs, Subjects: subs, Role: role}
}

// Object returns the id of the i-th object. Objects [0,N) are inside the selected
// set; [N, N+Spare) are outside it.
func (sc Scenario) Object(i int) string { return fmt.Sprintf("%s:obj-%06d", BenchType, i) }

// Objects returns the in-set objects.
func (sc Scenario) Objects() []string {
	out := make([]string, sc.N)
	for i := range out {
		out[i] = sc.Object(i)
	}
	return out
}

// ForeignObject — объект проекта ЧУЖОГО аккаунта, ПОМЕЧЕННЫЙ меткой набора.
//
// Метка обязательна и она здесь главное. Без неё отказ на этом объекте
// объясняется правилом-селектором, и конъюнкт области снова остаётся
// непроверенным — вопрос стал бы вторым экземпляром уже покрытого «объект вне
// набора». С меткой у формы E выполнены ВСЕ прочие конъюнкты (субъект назван в
// привязке, роль даёт глагол, метка объекта под селектор попадает), и отказать
// обязана ровно область.
//
// Идентификатор намеренно не из нумерации `Object(i)`: объект чужого арендатора
// не должен попадать ни в набор, ни в запасные — иначе он уехал бы в выдачу,
// страницу или переразметку и сдвинул бы базу сравнения пяти форм.
func (sc Scenario) ForeignObject() string { return BenchType + ":obj-foreign" }

// LabelledInMirror — объекты, чья строка зеркала несёт метку набора.
//
// Метку ставит ВЛАДЕЛЕЦ объекта, а не выдача: зеркало существует независимо от
// того, выдано ли кому-нибудь право. Поэтому чужой объект помечен так же, как
// свои, — и это не поблажка форме E, а единственный способ спросить её про
// область, не подсказав ответ другим конъюнктом.
func (sc Scenario) LabelledInMirror() map[string]bool {
	out := make(map[string]bool, sc.N+1)
	for _, o := range sc.Objects() {
		out[o] = true
	}
	out[sc.ForeignObject()] = true
	return out
}

// Structural returns the parent-pointer tuples. They are IDENTICAL in every shape
// and are therefore excluded from the grant accounting: attributing them to a shape
// would flatter whichever shape has fewest grant tuples.
//
// Второй аккаунт, его проект и один объект в нём — тоже структурное: они не входят
// ни в набор, ни в запасные, поэтому ни одна операция записи их не касается и
// величина выдачи каждой формы остаётся прежней. Проверено прогоном, а не
// рассуждением: строки выдачи всех шести форм до и после этой правки совпали, а
// структурная часть выросла ровно на три строки у каждой (см. `ExpectedStructuralRows`).
func (sc Scenario) Structural() []Tuple {
	out := make([]Tuple, 0, sc.N+sc.Spare+5)
	out = append(out,
		Tuple{User: clusterObj, Relation: "cluster", Object: accountObj},
		Tuple{User: accountObj, Relation: "account", Object: projectObj},
	)
	for i := 0; i < sc.N+sc.Spare; i++ {
		out = append(out, Tuple{User: projectObj, Relation: "project", Object: sc.Object(i)})
	}
	out = append(out,
		Tuple{User: clusterObj, Relation: "cluster", Object: otherAccountObj},
		Tuple{User: otherAccountObj, Relation: "account", Object: otherProjectObj},
		Tuple{User: otherProjectObj, Relation: "project", Object: sc.ForeignObject()},
	)
	return out
}

// Grant returns the tuples that materialize the binding over the in-set objects.
//
// Выдача формы E — строка привязки, её субъекты и её правило-селектор. Объекты
// набора здесь НЕ перечисляются: метка живёт в зеркале, зеркало наполняют
// владельцы объектов, и выдача узнаёт набор запросом. Отсюда и то, что «выдать» у
// неё стоит S + 2 независимо от N — постоянство и есть измеряемый результат, а не
// отказ прибора.
func Grant(f Form, sc Scenario) []Tuple {
	if f != FormE {
		return nil
	}
	return grantE(sc, bindingObj, projectObj)
}

// grantE собирает выдачу формы E: одна привязка + S субъектов + один селектор.
//
// Область привязки задаётся объектом (`project:` либо `account:`): вложенность
// области транзитивна, поэтому аккаунтная привязка накрывает объекты проектов
// этого аккаунта — и родительский указатель аккаунта в зеркале имеет читателя, а
// не лежит колонкой, которую никто не спрашивает.
func grantE(sc Scenario, binding, scope string) []Tuple {
	out := make([]Tuple, 0, len(sc.Subjects)+2)
	out = append(out, Tuple{User: scope, Relation: bindingRelPrefix + sc.Role, Object: binding})
	for _, s := range sc.Subjects {
		out = append(out, Tuple{User: s, Relation: bindingSubjectRel, Object: binding})
	}
	out = append(out, Tuple{User: labelObj, Relation: bindingSelectorRel, Object: binding})
	return out
}

// GrantScoped — та же выдача, но на названной области.
//
// Существует ради аккаунтной ветви предиката области, и «проверяется» здесь
// означает УТВЕРЖДЕНИЕ, а не исполнение. У ветви есть пара:
// TestAccountScopedGrantReachesObjectsOfItsProjects требует положительного
// (аккаунтная выдача накрывает объект проекта СВОЕГО аккаунта) и отрицательного
// (не накрывает помеченный объект проекта ЧУЖОГО аккаунта). Прежняя редакция
// этого комментария обещала проверку, которой не было: ветвь исполнялась, но ни
// одно утверждение от неё не зависело — снятие корреляции области не роняло ни
// одной пробы.
func GrantScoped(sc Scenario, scope string) []Tuple { return grantE(sc, bindingObj, scope) }

// InlineIntent — предмет выдачи и сама выдача для операций «в одной транзакции».
//
// Предмет — новый объект (строка зеркала), выдача — привязка на него. У движка
// отношений эта пара неприменима by construction, и ячейка сообщает именно это.
func InlineIntent(sc Scenario, obj string) (data, grant []Tuple) {
	return []Tuple{{User: projectObj, Relation: "project", Object: obj}},
		grantE(sc, inlineBindingObj, projectObj)
}

// InlineRevokeIntent — отзыв одного субъекта встраиваемой привязки, в той же
// транзакции, что и правка предмета выдачи.
func InlineRevokeIntent(sc Scenario, obj string) (data, revoke []Tuple) {
	return []Tuple{{User: projectObj, Relation: "project", Object: obj}},
		[]Tuple{{User: sc.Subjects[0], Relation: bindingSubjectRel, Object: inlineBindingObj}}
}

// CascadeSeed — принципал трёх верхних уровней доступа.
//
// Строка администратора аккаунта, которую запрос вердикта достаёт соединением
// ограниченной глубины по родительским указателям (leaf → project → account →
// cluster). Каскад меряется отдельной ячейкой, потому что это и есть путь,
// которым чинят аварию: он разрешается в момент запроса и не зависит от того,
// доехала ли до кого-нибудь материализация.
func CascadeSeed(_ Form, _ Scenario) []Tuple {
	return []Tuple{{User: cascadeAdmin, Relation: cascadeAccountAdminRel, Object: accountObj}}
}

// RelabelOne returns the tuples written when ONE object ENTERS the selected set —
// the "a label changed on one resource" operation.
//
// Это ось, на которой формы расходились сильнее всего и на которой плоский индекс
// платил хуже прочих: он переписывал всё произведение глаголов на субъекты для
// этого объекта. У формы E это правка метки ОДНОЙ строки зеркала, и величина от
// N не зависит.
func RelabelOne(f Form, sc Scenario, obj string) []Tuple {
	if f != FormE {
		return nil
	}
	return []Tuple{{User: labelObj, Relation: labelsRel, Object: obj}}
}

// RelabelMany is RelabelOne applied to K objects — the "mass re-tagging" operation.
func RelabelMany(f Form, sc Scenario, objs []string) []Tuple {
	var out []Tuple
	for _, o := range objs {
		out = append(out, RelabelOne(f, sc, o)...)
	}
	return out
}

// RevokeSubject returns the tuples DELETED when ONE subject loses the binding.
//
// Отзыв меряется отдельно от выдачи намеренно: путь материализации, умеющий
// только ДОБАВЛЯТЬ, зелен на каждом утверждении «было ли выдано» и неверен ровно
// на той операции, ради которой отзыв существует (см. .claude/rules/testing.md
// §«Параллельный newman», дискриминатор create-vs-update).
func RevokeSubject(f Form, sc Scenario, subject string) []Tuple {
	if f != FormE {
		return nil
	}
	return []Tuple{{User: subject, Relation: bindingSubjectRel, Object: bindingObj}}
}

// ExpectedGrantTuples — арифметика, объявленная ДО прогона, чтобы измеренное
// число строк сверялось с ней, а не принималось на веру.
func ExpectedGrantTuples(f Form, sc Scenario) int {
	if f != FormE {
		return -1
	}
	// s + 2: привязка, её субъекты, её правило-селектор. Строки зеркала сюда не
	// входят — они структурные.
	return len(sc.Subjects) + 2
}

// ExpectedStatements — объявленная ДО прогона арифметика колонки `StmtSQL` формы
// E, по операциям.
//
// Она нужна не для красоты отчёта: без неё измеряемое проверялось бы только по
// объёму, а объём у формы E постоянен — и форма, которая ВДОБАВОК к выдаче
// переразмечает весь набор, прошла бы все утверждения о строках, потому что
// правка метки строк не добавляет. Дефект найден инъекцией собственной пробы, а
// не рассуждением: инъекция «форма E разворачивает набор» пережила проверку
// объёма и упала только на этой величине.
//
// -1 — «не объявлена». Прежде так отвечали пять форм движка: стейтменты у них
// порождал он сам, и их число было свойством его реализации, а не нашим
// объявлением. Сегодня так отвечает только объём — у него нет колонки
// стейтментов, потому что это не операция замера времени.
func ExpectedStatements(f Form, op Op) int {
	if f != FormE {
		return -1
	}
	switch op {
	case OpGrant:
		return 5 // begin + привязка + субъекты + правило-селектор + commit
	case OpRevoke, OpRelabel1, OpRelabelK:
		return 3 // begin + один множественный стейтмент + commit
	case OpInlineGrant:
		return 6 // begin + предмет выдачи + три строки выдачи + commit
	case OpInlineRevoke:
		return 4 // begin + предмет выдачи + снятие субъекта + commit
	case OpCheck, OpPage50, OpPageFull, OpCascade:
		return 1 // вердикт — ОДИН запрос, и на одном объекте, и на целой странице
	case OpVolume:
		return -1 // у объёма нет колонки стейтментов: это не операция замера времени
	}
	return -1
}

// ExpectedStructuralRows — объявленная арифметика структурной части.
//
// Названа отдельно и до прогона, потому что у формы E ЭТО и есть величина,
// обязанная расти с N: цена самой выдачи у неё постоянна (s + 2), и постоянство —
// законный результат, а не отказ прибора. Форма, у которой ни одна величина не
// отвечает на удвоение входа, оставляет предпосылку «прибор различает»
// недоказанной, поэтому величина, которая обязана вырасти, названа заранее и
// сверяется с измеренной. С уходом второй стороны эта предпосылка стала ВАЖНЕЕ, а
// не менее важной: раньше различающую силу прибора можно было показать разницей
// между формами, теперь показать её нечем, кроме отклика одной формы на вход.
// Слагаемое 5 (а не 2) — чужой арендатор: второй аккаунт, его проект и один
// помеченный объект в нём. Оно названо ЗДЕСЬ, потому что эта арифметика —
// единственное место, где заявленный размер фикстуры сверяется с измеренным:
// пробы объёма упадут, если фикстура вырастет иначе, чем объявлено.
func ExpectedStructuralRows(f Form, sc Scenario) int {
	if f == FormE {
		// Строка зеркала на каждый объект — и внутри набора, и вне его, и чужого
		// арендатора; плюс два проекта, два аккаунта и роль-с-глаголами.
		return sc.N + sc.Spare + 5 + len(sc.Verbs)
	}
	return -1
}
