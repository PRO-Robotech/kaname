// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// acting_as_a_person_is_not_editing_his_record_test.go — гейт на КЛАСС: право
// ДЕЙСТВОВАТЬ ОТ ИМЕНИ человека не выводится из права ПРАВИТЬ ЕГО ЗАПИСЬ.
//
// # Предмет
//
// Выпуск персонального токена — это выдача удостоверения, которым предъявитель
// становится САМИМ ЧЕЛОВЕКОМ: всюду, где действует он, и во всех аккаунтах, где
// он состоит. Правка его записи (имя, почта, состояние) — управление строкой
// внутри одного аккаунта. Пока оба гейтятся одним отношением, второе право даёт
// первое, и получает его всякий, кому оно досталось по обычной выдаче внутри
// аккаунта — то есть и тот, кто человека всего лишь пригласил.
//
// Личность в этом дереве ГЛОБАЛЬНА: один человек — одна строка `iam_user` на все
// его аккаунты (миграция 20260822234500, пробы identity_is_global_*). Значит
// право, взятое из одного аккаунта, действует и за его пределами — вот почему
// разделение не косметическое.
//
// # Что здесь утверждается — и почему через КАТАЛОГ, а не через литерал
//
// Проба не знает наперёд, каким отношением гейтятся токены: она СПРАШИВАЕТ его у
// каталога прав (тот генерируется из proto и является единственным источником
// per-RPC решения края). Затем компилирует это отношение из КАНОНИЧЕСКОЙ модели и
// смотрит на источники разрешения. Литерал имени отношения здесь превратил бы
// гейт в проверку написания: он остался бы зелёным, если бы завтра токены
// вернули на отношение правки под другим именем.
//
// # Обе стороны, потому что односторонняя проба зеленеет на пустом
//
//   - ОТРИЦАНИЕ: у отношения токенов НЕТ источников уровня аккаунта — ни
//     пообъектной выдачи, ни администратора аккаунта, ни владельца аккаунта;
//   - ОТРИЦАНИЕ 2: у отношения токенов НЕТ прямого списка субъектов, то есть его
//     нельзя ВРУЧИТЬ ни кортежем, ни выдачей, ни материализацией. Без этого
//     утверждения запрет выше обходится одной строкой журнала;
//   - ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ 1: сам человек (`subject`) источник ИМЕЕТ — иначе
//     запрет зеленел бы на отношении, которого не держит вообще никто, и
//     собственная чеканка была бы сломана незаметно;
//   - ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ 2: у отношения ЧТЕНИЯ ЗАПИСИ (`UserService/Get`)
//     ровно те источники уровня аккаунта, отсутствие которых утверждается выше.
//     Без него «источников нет» неотличимо от «разбор ничего не нашёл».
//
// > [!note] Контролем была ПРАВКА записи, и она перестала им быть (#1102)
// > Пока правка гейтилась `v_update`, она была естественным контролем: «вот
// > право, у которого источники уровня аккаунта обязаны БЫТЬ». Вторая половина
// > директивы владельца увела её на `record_writer`, у которого их нет по тому
// > же основанию, что и здесь, — человек есть ГЛОБАЛЬНАЯ личность.
// >
// > Оставить прежний контроль значило бы получить пробу, которая утверждает
// > обратное сделанному и краснеет на верном дереве; молча снять его — получить
// > вакуумное отрицание. Контроль перенесён на ЧТЕНИЕ записи: видеть своих людей
// > — законное дело аккаунта, и источники уровня аккаунта у `v_get` остаются
// > намеренно, а не по недосмотру.
//
// # Чего проба НЕ утверждает, и это названо, а не умолчано
//
// Администратор облака (уровень 1) в план отношения не входит и входить не
// обязан: его надзор — плоское короткое замыкание на стороне службы
// (`authzguard.SubjectIsClusterAdmin`, зовётся из `AuthorizeService.verdict`
// ПОСЛЕ ответа формы), одинаковое для КАЖДОГО отношения модели. Утверждение об
// уровне 1 живёт там, где оно наблюдаемо, — в интеграционной пробе
// `services/iam/internal/service/acting_as_a_person_integration_test.go`.
package authzmap_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-iam/internal/authzplan"
)

// actingAsRPCs — публичные RPC, чей предмет есть ДЕЙСТВИЕ ОТ ИМЕНИ человека:
// выдача персонального удостоверения и его отзыв.
//
// Перечислены по FQN, потому что «действие от имени» — свойство СМЫСЛА RPC, а не
// его написания: вывести его из имени метода нельзя, и попытка вывести дала бы
// либо промах на переименовании, либо ложную находку на однокоренном методе.
// Перечень мал и закрыт; каждая запись обязана находиться в каталоге (иначе
// перечень пережил свой предмет — см. предпосылку в теле пробы).
var actingAsRPCs = []string{
	"kacho.cloud.iam.v1.UserTokenService/Issue",
	"kacho.cloud.iam.v1.UserTokenService/Revoke",
}

// recordReadRPC — чтение ЗАПИСИ человека. Положительный контроль: именно у него
// источники уровня аккаунта обязаны БЫТЬ.
//
// Правка записи контролем больше не служит: с #1102 она гейтится отношением, у
// которого этих источников нет — по тому же основанию, что закрывает и эта проба.
const recordReadRPC = "kacho.cloud.iam.v1.UserService/Get"

// accountLevelSources — источники разрешения, которых у отношения «действовать от
// имени» быть не должно.
//
// Названы ТРИ, потому что путей у пригласившего тоже три, и закрыть надо каждый:
//
//	{binding,  "",        <отношение>} — пообъектный кортеж, который реконсайлер
//	                                     материализует на свежей строке человека
//	                                     из выдачи, накрывающей аккаунт (invite.go
//	                                     зовёт reconcileObject на "iam.user");
//	{fact,     "account", "admin"}     — ДЕЛЕГИРОВАННЫЙ администратор аккаунта;
//	{fact,     "account", "owner"}     — владелец аккаунта.
type planSource struct {
	Kind       authzplan.AtomKind
	ParentType string
	Relation   string
}

func sourcesOf(t *testing.T, p authzplan.Plan) map[planSource]string {
	t.Helper()
	out := map[planSource]string{}
	for _, a := range p.Atoms {
		out[planSource{Kind: a.Kind, ParentType: a.ParentType, Relation: a.Relation}] = a.Origin
	}
	return out
}

// TestActingAsAPersonHasNoAccountLevelSource — гейт класса.
func TestActingAsAPersonHasNoAccountLevelSource(t *testing.T) {
	model := canonicalModel(t)
	catalog := catalogByFQN(t)

	// ПРЕДПОСЫЛКА. Каталог обязан нести КАЖДЫЙ перечисленный RPC. Запись, которой
	// каталог не знает, означает либо снятый RPC, либо переименованный — и в обоих
	// случаях перечень выше пережил свой предмет, а «ноль находок» стало бы
	// «ноль рассмотренного».
	require.NotEmpty(t, catalog, "каталог прав разобран в ноль записей — предпосылка гейта сломана")

	// Положительный контроль 2 — сперва, чтобы отрицание ниже не могло зеленеть на
	// сломанном разборе: у ПРАВКИ ЗАПИСИ источники уровня аккаунта обязаны быть.
	readEntry, ok := catalog[recordReadRPC]
	require.Truef(t, ok, "каталог не знает %s — контроль отрицания отсутствует", recordReadRPC)
	readPlan, err := model.Compile(readEntry.objectType, readEntry.relation)
	require.NoErrorf(t, err, "компиляция %s.%s (чтение записи)", readEntry.objectType, readEntry.relation)
	readSources := sourcesOf(t, readPlan)
	for _, want := range accountLevelSources(readEntry.relation) {
		require.Containsf(t, readSources, want,
			"КОНТРОЛЬ: у отношения чтения записи %s.%s обязан быть источник уровня аккаунта %+v. "+
				"Его отсутствие означает, что разбор модели ничего не нашёл, и тогда отрицание "+
				"ниже вакуумно", readEntry.objectType, readEntry.relation, want)
	}

	checked := 0
	for _, fqn := range actingAsRPCs {
		e, ok := catalog[fqn]
		require.Truef(t, ok, "каталог не знает %s — перечень «действий от имени» пережил свой предмет", fqn)
		require.Equalf(t, "iam_user", e.objectType,
			"%s гейтится не на объекте личности (%s) — предмет пробы сменился", fqn, e.objectType)

		plan, err := model.Compile(e.objectType, e.relation)
		require.NoErrorf(t, err, "компиляция %s.%s (%s)", e.objectType, e.relation, fqn)
		require.NotEmptyf(t, plan.Atoms, "план %s.%s пуст — ни одного источника разрешения",
			e.objectType, e.relation)
		got := sourcesOf(t, plan)

		// ОТРИЦАНИЕ.
		for _, banned := range accountLevelSources(e.relation) {
			origin, present := got[banned]
			require.Falsef(t, present,
				"%s гейтится отношением %s.%s, у которого источник уровня аккаунта %+v (%s).\n"+
					"Выпуск и отзыв персонального токена — ДЕЙСТВИЕ ОТ ИМЕНИ человека: "+
					"удостоверение действует всюду, где действует он, включая аккаунты, к которым "+
					"держатель этого источника отношения не имеет. Личность здесь глобальна "+
					"(одна строка iam_user на все аккаунты человека), поэтому право, взятое внутри "+
					"одного аккаунта, вышло бы за его границу.\n"+
					"Такое право нельзя выводить из права ПРАВИТЬ ЗАПИСЬ — это разные права, и "+
					"отношение у них обязано быть разное.",
				fqn, e.objectType, e.relation, banned, origin)
		}

		// ОТРИЦАНИЕ 2 — отношение НЕВЫДАВАЕМО.
		//
		// Отдельным утверждением, потому что предмет другой: выше закрыты пути, по
		// которым право ПРИЕЗЖАЕТ держателю выдачи внутри аккаунта, здесь — сама
		// возможность его ВЫДАТЬ. Прямой список субъектов у отношения означает, что
		// его можно вручить кортежем, и тогда запрет выше обходится одной строкой
		// журнала, а перечень банимых источников про неё ничего не знает: атом
		// собственного прямого списка в него не входит by construction.
		ownDirect := planSource{Kind: authzplan.AtomFact, ParentType: "", Relation: e.relation}
		if origin, present := got[ownDirect]; present {
			require.Failf(t, "отношение «действия от имени» стало выдаваемым",
				"%s гейтится отношением %s.%s, у которого ЕСТЬ прямой список субъектов (%s).\n"+
					"Значит право действовать от имени человека можно ВРУЧИТЬ — кортежем, выдачей "+
					"или материализацией, — и тогда разделение прав выше обходится одной записью.\n"+
					"Отношение обязано быть вычисляемым: единственный способ им обладать — БЫТЬ "+
					"этим человеком.", fqn, e.objectType, e.relation, origin)
		}

		// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ 1 — сам человек.
		self := planSource{Kind: authzplan.AtomFact, ParentType: "", Relation: "subject"}
		require.Containsf(t, got, self,
			"%s гейтится отношением %s.%s, у которого САМ ЧЕЛОВЕК не источник. Тогда запрет выше "+
				"держится не разделением прав, а тем, что отношения не держит никто, — и собственная "+
				"чеканка сломана незаметно.\nИсточники плана: %v",
			fqn, e.objectType, e.relation, sortedKeys(got))
		checked++
	}

	t.Logf("перепись: записей каталога прочитано %d · RPC «действие от имени» сверено %d · "+
		"контроль чтения записи %s.%s (источников %d)",
		len(catalog), checked, readEntry.objectType, readEntry.relation, len(readSources))
}

// accountLevelSources — три пути, которыми право доходит до держателя выдачи
// ВНУТРИ аккаунта. Глагол параметром: пообъектный кортеж адресуется именем самого
// спрошенного отношения.
func accountLevelSources(relation string) []planSource {
	return []planSource{
		{Kind: authzplan.AtomBinding, ParentType: "", Relation: relation},
		{Kind: authzplan.AtomFact, ParentType: "account", Relation: "admin"},
		{Kind: authzplan.AtomFact, ParentType: "account", Relation: "owner"},
	}
}

func sortedKeys(m map[planSource]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		parent := k.ParentType
		if parent == "" {
			parent = "<сам объект>"
		}
		kind := "факт"
		if k.Kind == authzplan.AtomBinding {
			kind = "выдача"
		}
		out = append(out, kind+" "+parent+"#"+k.Relation)
	}
	sort.Strings(out)
	return out
}

// ── источники ────────────────────────────────────────────────────────────────

type catalogGate struct {
	relation   string
	objectType string
}

func catalogByFQN(t *testing.T) map[string]catalogGate {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(monorepoRoot(t), catalogRelPath))
	require.NoErrorf(t, err, "каталог прав %s не прочитан", catalogRelPath)

	var entries []struct {
		FQN              string `json:"fqn"`
		RequiredRelation string `json:"required_relation"`
		ScopeExtractor   struct {
			ObjectType string `json:"object_type"`
		} `json:"scope_extractor"`
	}
	require.NoError(t, json.Unmarshal(data, &entries))

	out := make(map[string]catalogGate, len(entries))
	for _, e := range entries {
		out[e.FQN] = catalogGate{relation: e.RequiredRelation, objectType: e.ScopeExtractor.ObjectType}
	}
	return out
}

func canonicalModel(t *testing.T) *authzplan.Model {
	t.Helper()
	path, dsl, err := authzplan.ResolveCanonicalModel()
	require.NoError(t, err)
	require.NotEmptyf(t, dsl, "канонический файл модели пуст: %s", path)
	m, err := authzplan.ParseModel(string(dsl))
	require.NoErrorf(t, err, "разбор канонической модели %s", path)
	return m
}
