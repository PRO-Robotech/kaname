// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package reconcile

// tuples_create_grant_scope_test.go — выдача, назвавшая ОДИН глагол, не вправе
// открывать RPC, спрашивающий про ДРУГОЙ.
//
// Предмет. Эмиттер на каждый материализованный объект пишет, помимо `v_*`,
// ярусный кортеж, и ярус выводится из КЛАССА глаголов правила: `create` — глагол
// записи, значит ярус `editor`. Модель при этом объявляет `editor ⇒ viewer`.
// Отсюда: правило, назвавшее ровно `create`, кладёт на объект `editor`, который
// резолвит и `editor`, и `viewer`. Пока RPC гейтится ЯРУСОМ, «право создать»
// автоматически означает «право прочитать, изменить и удалить» — доступ шире
// выданного, и шире он молча.
//
// Утверждение здесь СКВОЗНОЕ и не привязано к домену: population берётся из
// сгенерированного каталога прав (тот артефакт, который энфорсит край), тип —
// из канонической модели, а набор кортежей — у НАСТОЯЩЕГО эмиттера, а не у его
// пересказа. Поэтому проба покраснеет на любом домене, который заведёт ярусный
// гейт на собственном объекте, а не только на том, ради которого написана.
//
// ПАРНЫЙ ПОЛОЖИТЕЛЬНЫЙ в том же прогоне обязателен: «отношение не эмитировано»
// неотличимо от «эмиттер молчит вообще» и от «каталог назвал отношение, которого
// модель не знает». Поэтому рядом — правило с подстановкой `*`, которое обязано
// покрыть КАЖДЫЙ тот же RPC.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/services/iam/internal/authzmap"
	"github.com/PRO-Robotech/kacho/services/iam/internal/testsupport/catalogfixture"
)

// --- артефакты дерева, из которых выводится population ---------------------

const (
	// catalogRelPathGateway / catalogRelPathIAM — две вшитые копии каталога прав.
	// Они обязаны быть байт-идентичны, поэтому проба читает ОБЕ: чтение одной
	// оставило бы вторую дрейфовать при зелёной пробе.
	catalogRelPathGateway = "gateway/internal/middleware/embed/permission_catalog.json"
	catalogRelPathIAM     = "services/iam/internal/apps/kacho/seed/embedded/permission_catalog.json"

	// modelRelPath — канонический источник отношений и их выводимости.
	modelRelPath = "proto/kacho/cloud/iam/v1/fga_model.fga"
)

type catalogRow struct {
	FQN            string `json:"fqn"`
	Permission     string `json:"permission"`
	RequiredRel    string `json:"required_relation"`
	ScopeExtractor *struct {
		ObjectType       string `json:"object_type"`
		FromRequestField string `json:"from_request_field"`
	} `json:"scope_extractor"`
}

// repoRootFromTest поднимается от каталога пакета до корня модуля.
func repoRootFromTest(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	dir := wd
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("корень монорепо (go.mod) не найден от %s", wd)
		}
		dir = parent
	}
}

func readCatalog(t *testing.T, root, rel string) []catalogRow {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		t.Fatalf("копия каталога прав %s не прочитана: %v — у пробы нет источника истины", rel, err)
	}
	var rows []catalogRow
	if err := json.Unmarshal(raw, &rows); err != nil {
		t.Fatalf("разбор %s: %v", rel, err)
	}
	if len(rows) == 0 {
		t.Fatalf("%s разобран в ноль записей — проба ничего бы не утверждала", rel)
	}
	return rows
}

// --- выводимость отношений, прочитанная у МОДЕЛИ ---------------------------

var (
	reTypeDecl   = regexp.MustCompile(`(?m)^\s*type (\w+)\s*$`)
	reDefineDecl = regexp.MustCompile(`^\s*define (\w+)\s*:\s*(.*)$`)
	reBareOrTerm = regexp.MustCompile(`\bor\s+([a-z_][a-z0-9_]*)\s*(?:$|\n)`)
)

// implications читает канонический DSL и возвращает рёбра «отношение A влечёт
// отношение B» ДЛЯ ОДНОГО типа: строка `define viewer: [...] or editor` означает,
// что держатель `editor` резолвит `viewer`.
//
// Рёбра выводятся из текста модели, а не выписываются здесь: выписанная таблица
// сама стала бы поверхностью дрейфа и оставила бы новую выводимость незамеченной.
func implications(t *testing.T, dsl, fgaType string) map[string][]string {
	t.Helper()
	lines := strings.Split(dsl, "\n")
	start := -1
	for i, l := range lines {
		if m := reTypeDecl.FindStringSubmatch(l); m != nil {
			if m[1] == fgaType {
				start = i
				break
			}
		}
	}
	if start < 0 {
		t.Fatalf("модель %s не объявляет `type %s` — предпосылка пробы неверна", modelRelPath, fgaType)
	}
	out := map[string][]string{}
	for _, l := range lines[start+1:] {
		if reTypeDecl.MatchString(l) {
			break
		}
		m := reDefineDecl.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		relation, expr := m[1], m[2]
		for _, term := range reBareOrTerm.FindAllStringSubmatch(expr+"\n", -1) {
			// `X from Y` — вывод от ДРУГОГО объекта (иерархия), а не от отношения
			// на этом же объекте; такие термы сюда не попадают: regexp требует
			// конец строки сразу за именем.
			out[term[1]] = append(out[term[1]], relation)
		}
	}
	if len(out) == 0 {
		t.Fatalf("у типа %s не разобрано ни одного ребра выводимости — разборщик или модель сломаны", fgaType)
	}
	return out
}

// declaredRelations — имена отношений, которые модель объявляет У ЭТОГО типа.
//
// Нужно, чтобы отличить ДВА разных состояния, которые парный положительный
// контроль ниже прежде сваливал в одно: «каталог назвал отношение, которого
// модель на этом типе не знает» (опечатка либо снятое отношение — находка) и
// «отношение объявлено, но НЕВЫДАВАЕМО by construction» (вычисляемое, без
// прямого списка субъектов — намеренная посадка). Первое обязано ронять пробу,
// второе — нет.
func declaredRelations(t *testing.T, dsl, fgaType string) map[string]bool {
	t.Helper()
	lines := strings.Split(dsl, "\n")
	start := -1
	for i, l := range lines {
		if m := reTypeDecl.FindStringSubmatch(l); m != nil && m[1] == fgaType {
			start = i
			break
		}
	}
	if start < 0 {
		t.Fatalf("модель %s не объявляет `type %s` — предпосылка пробы неверна", modelRelPath, fgaType)
	}
	out := map[string]bool{}
	for _, l := range lines[start+1:] {
		if reTypeDecl.MatchString(l) {
			break
		}
		if m := reDefineDecl.FindStringSubmatch(l); m != nil {
			out[m[1]] = true
		}
	}
	if len(out) == 0 {
		t.Fatalf("у типа %s не разобрано ни одного объявления — разборщик или модель сломаны", fgaType)
	}
	return out
}

// ungrantableByDesign — RPC, чьё отношение НЕВЫДАВАЕМО НАМЕРЕННО: держать его
// можно только по своей природе, а не по выдаче.
//
// Перечень закрыт, и каждая запись несёт причину. Он ИСТЕКАЕТ САМ: если
// названное отношение перестанет быть вычисляемым (у него появится прямой список
// субъектов, то есть выдача начнёт его резолвить), запись станет находкой — см.
// утверждение в теле пробы. Без такого перечня парный положительный контроль
// требовал бы, чтобы КАЖДЫЙ гейт края был открываем выдачей, — а это ровно то
// допущение, которое неверно для права «действовать ОТ ИМЕНИ человека».
var ungrantableByDesign = map[string]string{
	"kacho.cloud.iam.v1.UserTokenService/Issue": "выпуск персонального токена — действие ОТ ИМЕНИ человека; " +
		"`iam_user.token_issuer` вычисляется из `subject`, поэтому обладать им можно только БУДУЧИ этим человеком (#1086)",
	"kacho.cloud.iam.v1.UserTokenService/Revoke": "отзыв персонального токена — та же полоса, что и выпуск (#1086)",

	// #1133 — ЧТЕНИЕ СВЕДЕНИЙ ОБ УДОСТОВЕРЕНИЯХ. Третья сторона той же директивы.
	// Запись появилась вместе с сужением: прежде `token_reader` выводился из
	// `v_list`, то есть выдачей резолвился, и в перечне ему места не было. Это и
	// есть форма, которую перечень обязан иметь — он идёт СЛЕДОМ за моделью, а не
	// впереди неё.
	"kacho.cloud.iam.v1.UserTokenService/List": "перечень персональных удостоверений — сведения о ЛИЧНОСТИ, " +
		"а не право на аккаунт; `iam_user.token_reader` выводится из `subject` и `super_admin from account`, " +
		"то есть держат его только сам человек и надзор облака, и выдачей внутри аккаунта он не резолвится (#1133)",

	// #1102 — РАСПОРЯЖЕНИЕ СТРОКОЙ ЛИЧНОСТИ. Полоса та же, что у пары выше, но
	// причина другая, и её стоит назвать своими словами: там отношение невыдаваемо,
	// потому что обладать им можно только БУДУЧИ человеком; здесь — потому что
	// строка `iam_user` глобальна (одна на все аккаунты человека), и распорядитель
	// ОДНОГО аккаунта, получив это право выдачей, распоряжался бы за границей
	// своего аккаунта.
	//
	// Обе записи держит один и тот же двусторонний контроль ниже: отношение обязано
	// быть ОБЪЯВЛЕНО моделью (иначе каталог называет несуществующее и край отказал
	// бы всем), и полная выдача `*` его резолвить НЕ должна (иначе запись пережила
	// свой предмет).
	"kacho.cloud.iam.v1.UserService/Update": "правка записи человека — `iam_user.record_writer` выводится " +
		"из `super_admin from account`, то есть только надзор облака; выдачей внутри аккаунта он не резолвится (#1102)",
	"kacho.cloud.iam.v1.UserService/Block": "запрет личности действует во ВСЕХ её аккаунтах, поэтому " +
		"`iam_user.identity_suspender` не выводится ни из одного источника уровня аккаунта (#1102)",
	"kacho.cloud.iam.v1.UserService/Unblock": "снятие запрета — та же полоса, что и запрет (#1102)",

	// #1131 — СНЯТИЕ СТРОКИ ЛИЧНОСТИ. Тот же довод, что у соседей по #1102, и с
	// более тяжёлым исходом: запрет обратим, удаление нет. Отличие от них одно и
	// его стоит назвать: здесь в круг держателей входит САМ ЧЕЛОВЕК (самоудаление
	// разрешено всегда), поэтому отношение выводится из `subject` ЛИБО из
	// `super_admin from account`, — но выдачей внутри аккаунта не резолвится
	// ни то, ни другое.
	"kacho.cloud.iam.v1.UserService/Delete": "снятие строки личности стирает человека во ВСЕХ его " +
		"аккаунтах, поэтому `iam_user.identity_remover` выводится только из `subject` (самоудаление) " +
		"и `super_admin from account` (надзор облака); выдачей внутри аккаунта он не резолвится. " +
		"Распорядителю аккаунта служит исключение из аккаунта — оно гейтится отношением АККАУНТА " +
		"`member_remover` и выдачей резолвится штатно (#1131 / #1127)",
}

// closure — что РЕАЛЬНО резолвится, если субъект держит перечисленные отношения.
func closure(seed []string, implies map[string][]string) map[string]bool {
	got := map[string]bool{}
	queue := append([]string(nil), seed...)
	for len(queue) > 0 {
		r := queue[0]
		queue = queue[1:]
		if got[r] {
			continue
		}
		got[r] = true
		queue = append(queue, implies[r]...)
	}
	return got
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// --- population: публичный RPC, адресующий СОБСТВЕННЫЙ объект ---------------

var reFQN = regexp.MustCompile(`^kacho\.(?:cloud\.)?[a-z]+\.v1\.(\w+)/(\w+)$`)

// objectSelfPublicRows — записи каталога, у которых scope_extractor указывает на
// САМ адресуемый ресурс (не на родительский project/account/cluster) и листенер
// публичный.
//
// Почему создание исключено: создавать ещё не существующий объект нельзя «на нём
// самом», поэтому create-child анкерится на РОДИТЕЛЕ и законно несёт ярус родителя.
// Родителем бывает и leaf-тип (балансировщик для своего слушателя, том для снимка),
// так что по ТИПУ объекта эти записи не отличить. Отличаются они ГЛАГОЛОМ, который
// каталог назвал сам: последний сегмент `permission` (`<module>.<resources>.<verb>`).
// Читается именно он, а не имя метода: имя — привычка автора (`Create`,
// `CreateFromSnapshot`), а глагол каталога — то, что энфорсится. Проверено
// инъекцией: create-child с именем метода `Create2` этим предикатом молчит, а
// прежним, читавшим имя, краснел ложно.
//
// Почему `Internal*` исключён: cluster-internal admin-RPC гейтятся ярусом
// намеренно (`security.md`), и соседний гейт каталога это отдельно утверждает.
func objectSelfPublicRows(rows []catalogRow, anchors map[string]bool) []catalogRow {
	var out []catalogRow
	for _, r := range rows {
		m := reFQN.FindStringSubmatch(r.FQN)
		if m == nil {
			continue
		}
		if strings.HasPrefix(m[1], "Internal") || permissionVerb(r.Permission) == "create" {
			continue
		}
		se := r.ScopeExtractor
		if se == nil || se.FromRequestField == "" || se.FromRequestField == "*" {
			continue
		}
		if anchors[se.ObjectType] || !authzmap.TypeHasVerbRelations(se.ObjectType) {
			continue
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FQN < out[j].FQN })
	return out
}

// permissionVerb — последний сегмент токена права (`storage.volumes.delete` →
// `delete`); "" для токена без точки.
func permissionVerb(permission string) string {
	i := strings.LastIndexByte(permission, '.')
	if i < 0 {
		return ""
	}
	return permission[i+1:]
}

// hierarchyAnchors — типы-предки иерархии. На них ярус законен и является
// носителем write-authz (`data-integrity.md`), поэтому объект-предок из
// population исключён.
var hierarchyAnchors = map[string]bool{"account": true, "project": true, "cluster": true}

// TestCreateOnlyGrantOpensNoObjectSelfRPC — несущая проба.
//
// Для каждого публичного RPC, адресующего собственный объект, отношение, которое
// он ТРЕБУЕТ, не должно резолвиться у субъекта, чьё правило назвало ровно один
// глагол `create`.
func TestCreateOnlyGrantOpensNoObjectSelfRPC(t *testing.T) {
	root := repoRootFromTest(t)
	dsl, err := os.ReadFile(filepath.Join(root, modelRelPath))
	if err != nil {
		t.Fatalf("каноническая модель %s не прочитана: %v", modelRelPath, err)
	}

	for _, rel := range []string{catalogRelPathGateway, catalogRelPathIAM} {
		rows := readCatalog(t, root, rel)
		population := objectSelfPublicRows(rows, hierarchyAnchors)
		t.Logf("осмотрено: %s — %d записей, из них публичных object-self (не Create): %d",
			rel, len(rows), len(population))
		if len(population) == 0 {
			t.Fatalf("%s: population пуста — предикат перестал читать свой предмет", rel)
		}

		// Кэш по типу: закрытие «что резолвит create-only выдача» считается один раз.
		createClosure := map[string]map[string]bool{}
		fullClosure := map[string]map[string]bool{}
		declared := map[string]map[string]bool{}
		for _, row := range population {
			fgaType := row.ScopeExtractor.ObjectType
			if _, ok := createClosure[fgaType]; !ok {
				dotted, ok := authzmap.DottedType(fgaType)
				if !ok {
					t.Fatalf("тип %s не резолвится обратно в точечный ключ — эмиттер не позвать", fgaType)
				}
				implies := implications(t, string(dsl), fgaType)

				createTuples, emitted := ruleObjectTuples(catalogfixture.Facts(), "user:usr_probe", []string{"create"}, dotted, "obj_probe")
				if !emitted {
					t.Fatalf("эмиссия для %s не состоялась — утверждения ниже были бы бессодержательными", dotted)
				}
				createClosure[fgaType] = closure(relationsOf(createTuples), implies)

				fullTuples, emitted := ruleObjectTuples(catalogfixture.Facts(), "user:usr_probe", []string{"*"}, dotted, "obj_probe")
				if !emitted {
					t.Fatalf("эмиссия полного правила для %s не состоялась", dotted)
				}
				fullClosure[fgaType] = closure(relationsOf(fullTuples), implies)
				declared[fgaType] = declaredRelations(t, string(dsl), fgaType)
			}

			// ОТРИЦАНИЕ: create-выдача не открывает этот RPC.
			if createClosure[fgaType][row.RequiredRel] {
				t.Errorf("%s: %s требует %q, и выдача, назвавшая ОДИН глагол `create`, это отношение резолвит (%v).\n"+
					"Значит право создать на этом ресурсе автоматически даёт то, о чём спрашивает %s — доступ шире выданного",
					rel, row.FQN, row.RequiredRel, sortedKeys(createClosure[fgaType]), row.FQN)
			}
			// ПАРНЫЙ ПОЛОЖИТЕЛЬНЫЙ: полная выдача этот же RPC открывает —
			// КРОМЕ отношений, невыдаваемых намеренно.
			//
			// Прежде здесь стояло безусловное требование, и оно несло скрытое
			// допущение: всякий гейт края открываем выдачей. Для права
			// «действовать ОТ ИМЕНИ человека» это неверно by construction —
			// обладать им можно только будучи этим человеком. Поэтому проверка
			// разведена на два вопроса, и оба обязаны отвечаться: отношение
			// ОБЪЯВЛЕНО моделью на этом типе (иначе каталог называет несуществующее
			// — прежний предмет контроля), и оно либо резолвится выдачей, либо
			// стоит в закрытом перечне невыдаваемых.
			if reason, byDesign := ungrantableByDesign[row.FQN]; byDesign {
				if !declared[fgaType][row.RequiredRel] {
					t.Errorf("%s: %s требует %q, которого модель на типе %s НЕ ОБЪЯВЛЯЕТ. Запись в перечне "+
						"невыдаваемых (%s) не отменяет этого: отношение, которого нет, гейтом не является — "+
						"край получил бы отказ всем и всегда",
						rel, row.FQN, row.RequiredRel, fgaType, reason)
				}
				if fullClosure[fgaType][row.RequiredRel] {
					t.Errorf("%s: %s объявлен невыдаваемым (%s), но полная выдача `*` его отношение %q уже "+
						"резолвит (%v). Запись пережила свой предмет — либо снимите её, либо верните "+
						"отношению невыдаваемость",
						rel, row.FQN, reason, row.RequiredRel, sortedKeys(fullClosure[fgaType]))
				}
				continue
			}
			if !fullClosure[fgaType][row.RequiredRel] {
				t.Errorf("%s: %s требует %q, которого не резолвит даже полная выдача `*` (%v) — "+
					"каталог называет отношение, которого модель на этом типе не знает; тогда отрицание выше ничего не утверждает",
					rel, row.FQN, row.RequiredRel, sortedKeys(fullClosure[fgaType]))
			}
		}
	}
}

// TestCreateOnlyGrantMaterializesSomething — контроль в обратную сторону.
//
// Проба выше запрещает; без этого утверждения её «зелёное» неотличимо от
// «create-выдача не даёт вообще ничего», то есть от сломанной материализации.
//
// ЧТО ИМЕННО КОНТРОЛИРУЕТСЯ И ПОЧЕМУ ЭТО ИЗМЕНИЛОСЬ. Прежде контроль требовал,
// чтобы create-выдача резолвила `v_create`. Отношение снято со всех типов, кроме
// `registry_registry`: «создать» — не операция над уже существующим объектом, и
// пообъектный `v_create` на томе или сети не спрашивал ни один путь запроса. Если
// оставить прежнюю формулировку, контроль краснел бы на ЗАКОННОЙ модели, требуя
// вернуть отношение, у которого нет читателя.
//
// Контроль поэтому переформулирован на то, что действительно доказывает живость
// материализации, и он СИЛЬНЕЕ прежнего, потому что утверждает обе половины:
//
//	(а) авторский глагол `create` СЧИТАН и классифицирован — на объект лёг ярус
//	    записи (`editor`), выведенный из класса глагола; выдача, которую эмиттер
//	    уронил бы на пол, не дала бы ни одного кортежа;
//	(б) пообъектные глаголы на ЭТИХ ЖЕ типах живы — выдача, назвавшая глагол,
//	    который тип объявляет, резолвит соответствующее `v_*`.
//
// Без (б) «ярус есть» было бы неотличимо от «v_* сломаны на всём типе», а именно
// на `v_*` и держится запрет соседней пробы.
func TestCreateOnlyGrantMaterializesSomething(t *testing.T) {
	root := repoRootFromTest(t)
	dsl, err := os.ReadFile(filepath.Join(root, modelRelPath))
	if err != nil {
		t.Fatalf("каноническая модель %s не прочитана: %v", modelRelPath, err)
	}

	checked := 0
	for _, dotted := range []string{"storage.volumes", "storage.snapshots", "storage.images", "vpc.network"} {
		fgaType, ok := authzmap.FGAObjectType(dotted)
		if !ok {
			t.Fatalf("точечный ключ %s не резолвится в тип модели", dotted)
		}
		implies := implications(t, string(dsl), fgaType)

		// (а) глагол считан → ярус записи на объекте.
		createTuples, emitted := ruleObjectTuples(catalogfixture.Facts(), "user:usr_probe", []string{"create"}, dotted, "obj_probe")
		if !emitted {
			t.Fatalf("эмиссия для %s не состоялась", dotted)
		}
		if len(createTuples) == 0 {
			t.Errorf("правило с глаголом `create` на %s не дало НИ ОДНОГО кортежа — выдача уронена на пол, "+
				"и запрет в соседней пробе стал бы тождественно истинным", dotted)
		}
		got := closure(relationsOf(createTuples), implies)
		if !got["editor"] {
			t.Errorf("правило с глаголом `create` на %s не резолвит ярус `editor` (%v) — авторский глагол "+
				"не классифицирован как запись, то есть эмиттер его не увидел", dotted, sortedKeys(got))
		}
		// `v_create` на этих типах больше не существует — если он появился, значит
		// кто-то вернул отношение без читателя (или эмиттер пишет висячий кортеж,
		// который владелец модели отвергает окончательно).
		if got["v_create"] {
			t.Errorf("на %s резолвится `v_create` (%v) — тип его не объявляет; это висячий кортеж "+
				"либо возвращённое отношение, которого никто не спрашивает", dotted, sortedKeys(got))
		}

		// (б) пообъектные глаголы этого типа живы.
		declared := authzmap.VerbRelationsOfType(fgaType)
		if len(declared) == 0 {
			t.Fatalf("тип %s не объявляет глагольных отношений — половина (б) была бы бессодержательна", fgaType)
		}
		liveVerb := strings.TrimPrefix(declared[0], "v_")
		liveTuples, emitted := ruleObjectTuples(catalogfixture.Facts(), "user:usr_probe", []string{liveVerb}, dotted, "obj_probe")
		if !emitted {
			t.Fatalf("эмиссия правила с глаголом %q на %s не состоялась", liveVerb, dotted)
		}
		if live := closure(relationsOf(liveTuples), implies); !live[declared[0]] {
			t.Errorf("правило с глаголом %q на %s не резолвит %q (%v) — пообъектная материализация "+
				"на этом типе сломана, и запрет соседней пробы держаться не на чем",
				liveVerb, dotted, declared[0], sortedKeys(live))
		}
		checked++
	}
	t.Logf("осмотрено: %d типов", checked)
}
