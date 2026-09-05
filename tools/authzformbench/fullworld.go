// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzformbench

import (
	"fmt"
	"sort"
	"strings"
)

// Мир, в котором задаётся вопросник по ПОЛНОЙ модели.
//
// # Почему раскладка осталась одна
//
// Раскладок было ДВЕ. Движок отношений получал мир РАЗВЁРНУТЫМ — структурные
// указатели, строки фактов и материализованный состав (привязка × объекты под её
// селектором × глаголы её роли × её субъекты), — а форма E тот же мир
// НЕразвёрнутым: зеркало, рёбра родительства, те же строки фактов и сама
// привязка со своим правилом-селектором.
//
// Разворот считался ЗДЕСЬ, на Go, по графу мира; содержание области у формы E
// считается в SQL рекурсивным обходом рёбер. Две независимые реализации одного
// понятия «объект лежит в области выдачи», и их согласие было содержательной
// частью доказательства — потому разворот и не спрашивал форму E: взять одну
// реализацию и подать обеим значило бы доказать, что программа равна самой себе.
//
// Движок снят (S6), и вместе с ним снята та часть раскладки, что переводила мир в
// его кортежи: без хранилища для результата она мерила бы counterfactual. Осталась
// раскладка формы E (`relRows`) и Go-подсчёт того, что привязка накрывает
// (`materialize`), — последний уже не пишется никуда, а служит доказательством,
// что фикстура не выродилась.
//
// # Что мир обязан содержать, чтобы вопрос не был вырожден
//
// Два арендатора (иначе конъюнкт области тождественно истинен — на этом первый
// заход XC-10 и был отвергнут), вложенная группа, владелец аккаунта отдельно от
// его администратора, администратор кластера, объект, к которому не ведёт ни
// одна привязка (тип, привязанный к кластеру), объект с публичным чтением через
// подстановочный субъект, и зеркальный субъект чужого арендатора — он обязан
// получать разрешение ТАМ, где свой получает отказ. Без зеркального субъекта
// «отказано на чужом» неотличимо от «отказано всем, потому что засев не доехал».

// Идентификаторы мира. Фиксированные строки: сравниваются формы, а разница в
// идентификаторах была бы разницей в данных.
const (
	fmClusterObj = "cluster:cluster_kacho_root"

	fmHomeAccount    = "account:acc-home"
	fmForeignAccount = "account:acc-foreign"
	fmHomeProject    = "project:prj-home"
	fmForeignProject = "project:prj-foreign"

	fmGroupOuter = "group:grp-outer"

	// Субъекты вопросника.
	fmSubjDirect        = "user:u-direct" // назван в привязке проекта
	fmSubjDirectSA      = "service_account:sa-direct"
	fmSubjInGroup       = "user:u-in-group"       // член внешней группы
	fmSubjAccountAdmin  = "user:u-account-admin"  // каскад, уровень 3
	fmSubjAccountOwner  = "user:u-account-owner"  // структурный источник на своём аккаунте
	fmSubjClusterAdmin  = "user:u-cluster-admin"  // каскад, уровни 1-2
	fmSubjObjectOwner   = "user:u-object-owner"   // владелец реестра и репозитория
	fmSubjStranger      = "user:u-stranger"       // ни в одной привязке и ни в одном факте
	fmSubjForeignDirect = "user:u-foreign-direct" // зеркальный: назван в привязке ЧУЖОГО проекта

	// Роли мира и их глаголы. Роль-читатель заведена отдельной привязкой на
	// область АККАУНТА, чтобы область проекта и область аккаунта различались
	// наблюдаемо, а не только в схеме.
	fmRoleEditor = "role.bench.editor"
	fmRoleLister = "role.bench.lister"

	// Метка набора здесь больше не объявляется: её ставил единственный читатель —
	// раскладка мира в строки формы под сверку с движком, снятая вместе с ним.
)

// fmTenant — принадлежность объекта арендатору. Объект, привязанный к кластеру,
// не принадлежит ни одному, и это не пробел фикстуры, а свойство типа.
type fmTenant string

const (
	tenantHome    fmTenant = "home"
	tenantForeign fmTenant = "foreign"
	tenantCluster fmTenant = "cluster"
	// tenantUnlabelled — не арендатор, а роль объекта в фикстуре: он лежит у
	// СВОЕГО арендатора, но вне набора, который сужает правило-селектор. Значение
	// используется только при построении мира; принадлежность такого объекта
	// вычисляется как у своего.
	tenantUnlabelled fmTenant = "unlabelled"
)

// fmObject — один объект мира.
type fmObject struct {
	Type     string
	ID       string
	Tenant   fmTenant
	Pointers map[string]string // отношение-указатель → "тип:идентификатор"
	Labelled bool
}

func (o fmObject) Ref() string { return o.Type + ":" + o.ID }

// fmFact — строка факта: то, что iam держит у себя колонкой или таблицей
// (владелец аккаунта, администратор кластера, членство, публичное чтение), а
// движок — кортежем.
type fmFact struct {
	Object   string // "тип:идентификатор"
	Relation string
	Subject  string
}

// fmBinding — выдача в НЕразвёрнутом виде.
type fmBinding struct {
	ID        string
	ScopeType string // account | project
	ScopeID   string // полный "тип:идентификатор"
	Role      string
	Subjects  []string
	// SelectorTypes — типы объектов, которые накрывает правило-селектор.
	// Заполняется ВСЕМИ типами с глаголами: сужение здесь оставило бы часть
	// модели без единого вопроса, и «совпало» читалось бы шире, чем спрошено.
	SelectorTypes []string
}

// fmWorld — мир целиком.
type fmWorld struct {
	Model     *Model
	Objects   []fmObject
	Facts     []fmFact
	Bindings  []fmBinding
	RoleVerbs map[string][]string
	Groups    map[string][]string // группа → члены (полные строки субъектов)

	byRef map[string]fmObject
}

// buildWorld собирает мир ИЗ модели: перечень типов, их указатели и их глаголы
// берутся разбором, а не выписываются. Добавят в модель тип — он появится в мире
// и в вопроснике сам.
func buildWorld(m *Model) (*fmWorld, error) {
	if err := m.AssertOnePointerPerParentType(); err != nil {
		return nil, err
	}
	w := &fmWorld{
		Model:     m,
		RoleVerbs: map[string][]string{},
		Groups: map[string][]string{
			// Вложенность групп СНЯТА вместе со свойством: модель сужена до
			// схемы (задача #734), и `group#member` субъектом членства больше
			// не принимается — хранилище отвергает такой кортеж проверкой
			// формы. Проба снимается вместе со своим предметом, а не
			// подгоняется: субъект `u-nested` был заведён под эту ветвь и
			// другой не имеет.
			fmGroupOuter: {fmSubjInGroup},
		},
		byRef: map[string]fmObject{},
	}

	add := func(o fmObject) {
		if o.Pointers == nil {
			o.Pointers = map[string]string{}
		}
		w.Objects = append(w.Objects, o)
		w.byRef[o.Ref()] = o
	}

	// Каркас: кластер, два аккаунта, два проекта.
	add(fmObject{Type: "cluster", ID: "cluster_kacho_root", Tenant: tenantCluster})
	add(fmObject{Type: "account", ID: "acc-home", Tenant: tenantHome, Labelled: true,
		Pointers: map[string]string{"cluster": fmClusterObj}})
	add(fmObject{Type: "account", ID: "acc-foreign", Tenant: tenantForeign, Labelled: true,
		Pointers: map[string]string{"cluster": fmClusterObj}})
	add(fmObject{Type: "project", ID: "prj-home", Tenant: tenantHome, Labelled: true,
		Pointers: map[string]string{"account": fmHomeAccount, "cluster": fmClusterObj}})
	add(fmObject{Type: "project", ID: "prj-foreign", Tenant: tenantForeign, Labelled: true,
		Pointers: map[string]string{"account": fmForeignAccount, "cluster": fmClusterObj}})
	add(fmObject{Type: "group", ID: "grp-outer", Tenant: tenantHome})

	// По объекту каждого арендатора на КАЖДЫЙ тип с глаголами. Порядок обхода —
	// порядок объявления в модели, поэтому тип-контейнер (реестр) заводится
	// раньше своего ребёнка (репозитория), и указатель ребёнка резолвится.
	var verbTypes []string
	for _, t := range m.Types {
		if len(t.Verbs()) == 0 {
			continue
		}
		verbTypes = append(verbTypes, t.Name)
		if t.Name == "account" || t.Name == "project" {
			continue // уже в каркасе
		}
		// Три объекта на тип, и третий — не пустое место: он лежит у СВОЕГО
		// арендатора и не несёт метки набора. Без него правило-селектор проверено
		// ровно на одном объекте всего мира, а конъюнкт, у которого один свидетель,
		// почти тождественно истинен — снятие его меняло бы вердикт в пяти вопросах
		// из тысяч, и «проба способна упасть» держалось бы на волоске.
		for _, tn := range []fmTenant{tenantHome, tenantForeign, tenantUnlabelled} {
			labelled, anchor := true, tn
			if tn == tenantUnlabelled {
				labelled, anchor = false, tenantHome
			}
			o := fmObject{Type: t.Name, ID: fmt.Sprintf("obj-%s-%s", t.Name, tn),
				Tenant: anchor, Labelled: labelled, Pointers: map[string]string{}}
			for ptr := range m.Pointers[t.Name] {
				targets := m.PointerTargets(t.Rel(ptr))
				if len(targets) != 1 {
					return nil, fmt.Errorf("указатель %s.%s ведёт в %d типов — мир не знает, куда его привязать",
						t.Name, ptr, len(targets))
				}
				ref, ok := w.anchorFor(targets[0], anchor)
				if !ok {
					return nil, fmt.Errorf("указатель %s.%s ведёт в тип %q, для которого в мире нет якоря",
						t.Name, ptr, targets[0])
				}
				o.Pointers[ptr] = ref
			}
			if len(o.Pointers) == 0 {
				return nil, fmt.Errorf("тип %q с глаголами не несёт ни одного указателя — "+
					"объект такого типа не привязан ни к чему, и вопрос про область к нему неприменим", t.Name)
			}
			o.Tenant = tenantOf(w, o)
			add(o)
		}
	}
	if len(verbTypes) == 0 {
		return nil, fmt.Errorf("в модели не нашлось ни одного типа с глаголами — вопросник был бы пуст")
	}

	// Объект каждому типу, который объявляет отношения, но глаголов не несёт
	// (сегодня это тип-полномочие прокси). Без него его отношение не было бы
	// спрошено НИ РАЗУ — а «эквивалентность на всей модели» с непрошенным
	// отношением означает «на всей, кроме той, о которой забыли».
	for _, t := range m.Types {
		if len(t.Relations) == 0 || len(byTypeCount(w, t.Name)) > 0 {
			continue
		}
		o := fmObject{Type: t.Name, ID: "obj-" + t.Name + "-home", Tenant: tenantHome,
			Labelled: true, Pointers: map[string]string{}}
		for ptr := range m.Pointers[t.Name] {
			targets := m.PointerTargets(t.Rel(ptr))
			if len(targets) != 1 {
				return nil, fmt.Errorf("указатель %s.%s ведёт в %d типов", t.Name, ptr, len(targets))
			}
			ref, ok := w.anchorFor(targets[0], tenantHome)
			if !ok {
				return nil, fmt.Errorf("указатель %s.%s ведёт в тип %q без якоря", t.Name, ptr, targets[0])
			}
			o.Pointers[ptr] = ref
		}
		add(o)
	}

	// Публичный репозиторий: тот же тип, третий объект, накладной кортеж
	// подстановочного чтения. Заводится ровно потому, что подстановочный субъект
	// объявлен в модели ОДНИМ отношением одного типа: без своего объекта эта
	// ветвь модели не была бы спрошена ни разу.
	if pub, ok := w.publicRepoObject(m); ok {
		add(pub)
		w.Facts = append(w.Facts, fmFact{Object: pub.Ref(), Relation: "v_get", Subject: "user:*"})
	}

	// Строки фактов. Каждая — то, что iam хранит у себя, а движок кортежем.
	w.Facts = append(w.Facts,
		fmFact{Object: fmHomeAccount, Relation: "owner", Subject: fmSubjAccountOwner},
		fmFact{Object: fmHomeAccount, Relation: "admin", Subject: fmSubjAccountAdmin},
		fmFact{Object: fmForeignAccount, Relation: "owner", Subject: "user:u-foreign-owner"},
		fmFact{Object: fmClusterObj, Relation: "system_admin", Subject: fmSubjClusterAdmin},
	)
	for _, o := range w.Objects {
		if o.Type == "account" || o.Type == "project" {
			continue // владелец аккаунта заведён отдельным субъектом выше
		}
		if m.Type(o.Type) != nil && m.Type(o.Type).Rel("owner") != nil && o.Tenant == tenantHome {
			w.Facts = append(w.Facts, fmFact{Object: o.Ref(), Relation: "owner", Subject: fmSubjObjectOwner})
		}
	}
	// Членство в группах — такая же строка факта, как владение: у iam это таблица
	// членов, у движка кортеж. Отдельной таблицы под членство здесь НЕТ намеренно —
	// два места об одном предмете разошлись бы, а замыкание субъекта по группам
	// читает ровно эти же строки.
	for _, g := range sortedKeys(w.Groups) {
		for _, mem := range w.Groups[g] {
			w.Facts = append(w.Facts, fmFact{Object: g, Relation: "member", Subject: mem})
		}
	}
	// Подстановочное чтение справочника: `cluster:<root>#viewer@user:*` — то, что
	// бутстрап кластера пишет намеренно (каждый аутентифицированный арендатор
	// обязан читать глобальный справочник). Без этой строки ветвь `user:*` у
	// `cluster.viewer` не была бы спрошена ни разу, а она — ровно тот случай, где
	// отношение выполнимо подстановкой и не сужает ничего.
	if cl := m.Type("cluster"); cl != nil && cl.Rel("viewer") != nil {
		w.Facts = append(w.Facts, fmFact{Object: fmClusterObj, Relation: "viewer", Subject: "user:*"})
	}

	// Положительная сторона КАЖДОГО отношения, решающего доступ.
	//
	// Отношение, у которого спрошены только отказы, — это половина предмета:
	// «формы совпали» на нём означает «обе одинаково молчат». Поэтому на каждое
	// не-глагольное отношение, принимающее прямого субъекта, кладётся один факт —
	// ВЫВЕДЕННО из модели, а не выписанным перечнем, чтобы новое отношение
	// получало свою положительную сторону само.
	//
	// Не кладётся туда, где факт уже есть (владелец аккаунта, администратор,
	// членство — они заведены выше со СВОИМИ субъектами, и перекрытие смазало бы
	// их роль), и туда, где ЕДИНСТВЕННЫЕ записи прямого списка условны: такой
	// кортеж без условия движок не принимает вовсе, а с условием требует
	// контекста запроса, которого у формы E нет. Это и есть исход (в), и он
	// доказан отдельной пробой, а не обойдён здесь молча.
	seeded := map[string]bool{}
	for _, f := range w.Facts {
		seeded[f.Object+"#"+f.Relation] = true
	}
	for _, t := range m.Types {
		for _, r := range t.Relations {
			if IsVerb(r.Name) || m.IsPointer(t.Name, r.Name) {
				continue
			}
			subj := unconditionedSubject(r)
			if subj == "" {
				continue
			}
			for _, o := range w.Objects {
				// Метка здесь ни при чём: она сужает правило-селектор ВЫДАЧИ, а
				// факт от неё не зависит. Требование метки оставило бы без
				// положительной стороны отношения объекта, который меткой не
				// помечается вовсе, — например кластера.
				if o.Type != t.Name || o.Tenant == tenantForeign {
					continue
				}
				if seeded[o.Ref()+"#"+r.Name] {
					continue
				}
				seeded[o.Ref()+"#"+r.Name] = true
				w.Facts = append(w.Facts, fmFact{Object: o.Ref(), Relation: r.Name, Subject: subj})
				break
			}
		}
	}

	w.RoleVerbs[fmRoleEditor] = []string{"v_get", "v_update"}
	w.RoleVerbs[fmRoleLister] = []string{"v_list"}

	w.Bindings = []fmBinding{
		{ID: "ab-home-project", ScopeType: "project", ScopeID: fmHomeProject, Role: fmRoleEditor,
			Subjects: []string{fmSubjDirect, fmSubjDirectSA}, SelectorTypes: verbTypes},
		{ID: "ab-home-account", ScopeType: "account", ScopeID: fmHomeAccount, Role: fmRoleLister,
			Subjects: []string{fmGroupOuter + "#member"}, SelectorTypes: verbTypes},
		{ID: "ab-foreign-project", ScopeType: "project", ScopeID: fmForeignProject, Role: fmRoleEditor,
			Subjects: []string{fmSubjForeignDirect}, SelectorTypes: verbTypes},
	}
	return w, nil
}

// byTypeCount — объекты названного типа, уже заведённые в мире.
func byTypeCount(w *fmWorld, typeName string) []fmObject {
	var out []fmObject
	for _, o := range w.Objects {
		if o.Type == typeName {
			out = append(out, o)
		}
	}
	return out
}

// unconditionedSubject — субъект вопросника, годный в прямую запись отношения,
// либо пустая строка, если годной записи нет.
//
// Условные записи ПРОПУСКАЮТСЯ намеренно: кортеж под них движок принимает только
// вместе с условием, а ответ на него зависит от контекста запроса. Отношение,
// у которого условны ВСЕ записи, положительной стороны в этом вопроснике не
// получает — и это его свойство, а не пробел фикстуры.
func unconditionedSubject(r *Relation) string {
	for _, term := range r.Terms {
		if term.Kind != TermDirect {
			continue
		}
		for _, d := range term.Direct {
			if d.Condition != "" || d.Wildcard || d.Userset != "" {
				continue
			}
			switch d.Type {
			case "user":
				return fmSubjObjectOwner
			case "service_account":
				return fmSubjDirectSA
			}
		}
	}
	return ""
}

// publicRepoObject — третий объект типа, чей глагол принимает подстановочный
// субъект. Тип НЕ выписан: он находится по модели, поэтому исчезнет из мира
// вместе с подстановкой, если её когда-нибудь снимут.
func (w *fmWorld) publicRepoObject(m *Model) (fmObject, bool) {
	for _, t := range m.Types {
		for _, r := range t.Relations {
			if !IsVerb(r.Name) {
				continue
			}
			for _, term := range r.Terms {
				if term.Kind != TermDirect {
					continue
				}
				for _, d := range term.Direct {
					if !d.Wildcard {
						continue
					}
					src, ok := w.byRef[t.Name+":"+fmt.Sprintf("obj-%s-%s", t.Name, tenantHome)]
					if !ok {
						return fmObject{}, false
					}
					pub := fmObject{Type: t.Name, ID: "obj-" + t.Name + "-public", Tenant: tenantHome,
						Labelled: false, Pointers: map[string]string{}}
					for k, v := range src.Pointers {
						pub.Pointers[k] = v
					}
					return pub, true
				}
			}
		}
	}
	return fmObject{}, false
}

// anchorFor — объект-якорь названного типа для названного арендатора.
func (w *fmWorld) anchorFor(typeName string, tn fmTenant) (string, bool) {
	switch typeName {
	case "cluster":
		return fmClusterObj, true
	case "account":
		if tn == tenantHome {
			return fmHomeAccount, true
		}
		return fmForeignAccount, true
	case "project":
		if tn == tenantHome {
			return fmHomeProject, true
		}
		return fmForeignProject, true
	}
	ref := typeName + ":" + fmt.Sprintf("obj-%s-%s", typeName, tn)
	if _, ok := w.byRef[ref]; ok {
		return ref, true
	}
	return "", false
}

// tenantOf — арендатор объекта, ВЫВЕДЕННЫЙ по цепи родительства: тип, чьи
// указатели ведут только в кластер, не принадлежит ни одному арендатору, и
// вопросы про область к нему обязаны отвечать отказом у обеих сторон.
func tenantOf(w *fmWorld, o fmObject) fmTenant {
	for _, ref := range o.Pointers {
		if ref == fmHomeAccount || ref == fmHomeProject {
			return tenantHome
		}
		if ref == fmForeignAccount || ref == fmForeignProject {
			return tenantForeign
		}
		if p, ok := w.byRef[ref]; ok && p.Type != "cluster" {
			return tenantOf(w, p)
		}
	}
	return tenantCluster
}

// ancestors возвращает объект и всех его предков по цепи указателей.
func (w *fmWorld) ancestors(ref string) map[string]bool {
	out := map[string]bool{}
	var walk func(string, int)
	walk = func(r string, depth int) {
		if depth > MaxPointerDepth+2 || out[r] {
			return
		}
		out[r] = true
		o, ok := w.byRef[r]
		if !ok {
			return
		}
		for _, p := range o.Pointers {
			walk(p, depth+1)
		}
	}
	walk(ref, 0)
	return out
}

// materialize — что привязка НАКРЫВАЕТ, посчитанное на Go по графу мира:
// привязка × объекты под её селектором × глаголы её роли × её субъекты.
//
// Функция заводилась как воспроизведение реконсайлера — тем, что писалось в
// движок отношений. Движка нет, и писать это некуда; но у неё остался предмет, и
// он не в приборе, а в ФИКСТУРЕ: `TestWorldIsBuiltFromTheModelAndIsNotDegenerate`
// требует, чтобы субъект своей привязки получил хотя бы один объект своего
// арендатора и НИ ОДНОГО — чужого. Без этой проверки мир мог бы выродиться молча,
// и вопросник спрашивал бы там, где не выдано ничего: отказ на всё совпал бы с
// любым ответом.
//
// Считается ЗДЕСЬ, на Go, по графу мира, тогда как содержание области у формы E
// считается в SQL рекурсивным обходом рёбер. Это по-прежнему две независимые
// реализации одного понятия «объект лежит в области выдачи», и вторая не
// спрашивается у первой.
//
// Глагол, которого тип НЕ объявляет, пропускается: у продукта такой пропуск
// делает набор глаголов роли атрибутом ТИПА, а не роли.
func (w *fmWorld) materialize() []Tuple {
	var out []Tuple
	for _, b := range w.Bindings {
		types := map[string]bool{}
		for _, t := range b.SelectorTypes {
			types[t] = true
		}
		for _, o := range w.Objects {
			if !types[o.Type] || !o.Labelled {
				continue
			}
			if !w.ancestors(o.Ref())[b.ScopeID] {
				continue
			}
			t := w.Model.Type(o.Type)
			for _, v := range w.RoleVerbs[b.Role] {
				if t == nil || t.Rel(v) == nil {
					continue
				}
				for _, s := range b.Subjects {
					out = append(out, Tuple{User: s, Relation: v, Object: o.Ref()})
				}
			}
		}
	}
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ── вопросник ─────────────────────────────────────────────────────────────────

// FullQuestion — один вопрос полного вопросника.
type FullQuestion struct {
	Type     string
	Relation string
	Subject  string
	Object   string
	IsVerb   bool
}

// Name — имя вопроса в форме, годной для строки падения: тип, глагол, субъект,
// объект. Расхождение обязано называться поимённо, а не числом.
func (q FullQuestion) Name() string {
	return fmt.Sprintf("%s.%s | субъект %s | объект %s", q.Type, q.Relation, q.Subject, q.Object)
}

// fullSubjects — субъекты вопросника. Перечень закрыт и назван: каждый заведён
// под конкретную ветвь модели, и вырожденный (никем не наделённый) обязателен —
// без него «разрешено» и «разрешено всем» неразличимы.
func fullSubjects() []string {
	return []string{
		fmSubjDirect, fmSubjDirectSA, fmSubjInGroup,
		fmSubjAccountAdmin, fmSubjAccountOwner, fmSubjClusterAdmin,
		fmSubjObjectOwner, fmSubjStranger, fmSubjForeignDirect,
	}
}

// Questions строит вопросник ИЗ модели: каждое отношение каждого типа, кроме
// структурных указателей, — на каждом объекте этого типа и на каждом субъекте.
//
// Указатели исключены и это названо числом в переписи: они не решают доступ, а
// вопрос «является ли пользователь проектом» отвечал бы отказом у обеих сторон
// тождественно и разбавлял бы вопросник вопросами, которые не могут разойтись.
func (w *fmWorld) Questions() []FullQuestion {
	var qs []FullQuestion
	byType := map[string][]fmObject{}
	for _, o := range w.Objects {
		byType[o.Type] = append(byType[o.Type], o)
	}
	subs := fullSubjects()
	for _, t := range w.Model.Types {
		objs := byType[t.Name]
		if len(objs) == 0 {
			continue
		}
		for _, r := range t.Relations {
			if w.Model.IsPointer(t.Name, r.Name) {
				continue
			}
			for _, o := range objs {
				for _, s := range subs {
					qs = append(qs, FullQuestion{Type: t.Name, Relation: r.Name,
						Subject: s, Object: o.Ref(), IsVerb: IsVerb(r.Name)})
				}
			}
		}
	}
	return qs
}

// ── сторона формы E: неразвёрнутый мир ────────────────────────────────────────

// relRows — строки, которыми мир ложится в схему формы E.
type relRows struct {
	Mirror    [][3]string // тип · идентификатор · метки (JSON)
	Edges     [][5]string // тип · идентификатор · указатель · тип предка · идентификатор предка
	Facts     [][4]string // тип · идентификатор · отношение · субъект
	Bindings  [][4]string // идентификатор · тип области · идентификатор области · роль
	BindSubj  [][2]string
	Selectors [][3]string // привязка · тип объекта · метки (JSON)
	RoleVerbs [][2]string
}

// Метода `(*fmWorld).relRows` здесь БОЛЬШЕ НЕТ. Он раскладывал полномодельный мир
// в строки формы, чтобы её вердикты можно было сверить с вердиктами внешнего движка
// на том же мире. Движок снят (kacho#747, S6), сверять не с чем, и вызывающих у
// метода не осталось ни одного. Тип `relRows` выше ЖИВ: его продолжает называть
// проба узкой и полномодельной формы, у которой обе стороны свои.

// subjectSeeds — что считается «этим субъектом» на входе вердикта: он сам и, для
// пользователя, подстановочная форма своего типа. Членство в группах добирается
// рекурсивно уже в запросе.
//
// Подстановка типизирована: `user:*` не накрывает служебную учётку. Ошибка здесь
// была бы не косметической — она отдала бы публичное чтение машинному
// принципалу, которому модель его не давала.
func subjectSeeds(subject string) []string {
	st, _, err := splitObject(subject)
	if err != nil {
		return []string{subject}
	}
	return []string{subject, st + ":*"}
}

// describeWorld — перепись мира для отчёта.
//
// Второй строкой здесь печаталось, во сколько кортежей мир разворачивается у
// движка отношений и какая их часть — материализованный состав. Обе величины
// сняты вместе с движком: без стороны, которая эти кортежи хранит, число
// измеряло бы counterfactual — «во столько развернулось бы, если бы было куда».
func (w *fmWorld) describeWorld() string {
	var b strings.Builder
	fmt.Fprintf(&b, "объектов %d · рёбер родительства %d · строк фактов %d · привязок %d · групп %d\n",
		len(w.Objects), countEdges(w), len(w.Facts), len(w.Bindings), len(w.Groups))
	return b.String()
}

func countEdges(w *fmWorld) int {
	n := 0
	for _, o := range w.Objects {
		n += len(o.Pointers)
	}
	return n
}
