// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzmap_test

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/authzmap"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// nlb_target_membership_verbs_test.go — NLB-TGT-1: управление СОСТАВОМ группы целей
// отделено от изменения самой группы.
//
// Предмет: роль `loadbalancer.target_manager` объявляет `addTargets`/`removeTargets`,
// показывает их владельцу роли как то, что она даёт, — и не даёт ничего. Оба RPC
// гейтились отношением изменения группы, поэтому выдать право управлять составом, не
// выдав права менять саму группу, было НЕЛЬЗЯ.
//
// Здесь проверяется свойство МОДЕЛИ, и проверяется против того артефакта, который
// применяет hook-задача развёртывания (блок `model.json` конфигмапа), а не против DSL
// в дереве: DSL доказал бы форму исходника, артефакт — то, что энфорсится.
//
// Имя отношения НЕ выбирается, оно ВЫВОДИТСЯ: реконсайлер (пакет `…/access_binding/
// reconcile`, не этот) собирает его из авторского глагола правила, приставки и
// приведения имени, которое живёт в домене iam. Поэтому `addTargets` даёт ровно
// `v_addtargets`. Свобода здесь была бы расхождением: имя, написанное иначе, чем его
// собирает эмиттер, адресовало бы отношение, которого у типа нет, и запись была бы
// отвергнута владельцем модели окончательно. Утверждения ниже это не пересказывают,
// а СЧИТАЮТ теми же доменными функциями, что и эмиссия.

const (
	tmType     = "nlb_target_group"
	tmObject   = "nlb_target_group:tgr-tmprobe"
	tmVerbAdd  = "addTargets"    // авторское написание правила роли
	tmVerbRm   = "removeTargets" //
	tmRelAdd   = "v_addtargets"
	tmRelRm    = "v_removetargets"
	tmSubjUpd  = "user:usr-tmupdater"  // держит ТОЛЬКО v_update
	tmSubjAdd  = "user:usr-tmadder"    // держит ТОЛЬКО v_addtargets
	tmSubjView = "user:usr-tmviewer"   // держит ТОЛЬКО v_get
	tmSubjRm   = "user:usr-tmremover"  // держит ТОЛЬКО v_removetargets
	tmSubjNone = "user:usr-tmstranger" // не держит ничего
)

// TestNLBTargetGroup_DeclaresMembershipVerbs — набор глаголов ТИПА объявляет оба
// глагола управления составом.
//
// Это предпосылка эмиссии, а не украшение: эмиттер сверяет авторский глагол с набором
// ТИПА, и глагол вне набора молча пропускается (fail-closed). Пока набора нет, роль с
// `addTargets` не производит ни одного кортежа этого отношения ни при каких условиях —
// сколько бы раз её ни привязывали. Сверка ниже идёт ТОЙ ЖЕ доменной функцией, что и
// на пути эмиссии, а не её пересказом.
func TestNLBTargetGroup_DeclaresMembershipVerbs(t *testing.T) {
	verbs := authzmap.VerbsOfType(tmType)
	require.NotEmpty(t, verbs, "тип не глагольный — дальнейшие утверждения были бы бессодержательны")

	for _, authored := range []string{tmVerbAdd, tmVerbRm} {
		require.Truef(t, domain.IsVerbOfType(authored, verbs),
			"тип %q не объявляет глагол %q (набор: %v) — правило роли, называющее его, "+
				"не породит ни одного кортежа: глагол вне набора типа пропускается молча",
			tmType, authored, verbs)
	}

	// Сосед — ОБЫЧНЫЙ глагольный тип; его набор служит здесь базой сравнения
	// дважды: в положительном контроле сразу ниже и в отрицательном за ним.
	peer := authzmap.VerbsOfType("vpc_network")
	require.NotEmpty(t, peer, "сосед не глагольный — утверждения ниже ничего не утверждают")

	// Парный положительный на ту же ось: набор типа — НАДМНОЖЕСТВО обычного, то
	// есть «объявляет два новых» отличимо от «таблица типа сломана».
	//
	// База берётся у соседа, а не выписывается. Прежняя редакция перечисляла пять
	// имён, среди них `create`, — и пережила свой предмет, когда `v_create` сняли
	// со всех типов, кроме `registry_registry` (создание ресурса авторизуется
	// ярусом записи на родителе, а не пообъектным глаголом). Литерал этого не
	// узнал бы: он краснел бы на ЗАКОННОМ изменении модели, требуя вернуть
	// отношение, которого больше нет.
	for _, v := range peer {
		require.Truef(t, domain.IsVerbOfType(v, verbs),
			"тип %q не объявляет глагол %q, который объявляет обычный тип vpc_network "+
				"(набор типа: %v, набор соседа: %v) — набор перестал быть надмножеством",
			tmType, v, verbs, peer)
	}

	// Парный отрицательный: набор РАСШИРЕН у ЭТОГО типа, а не у платформы. Иначе
	// «объявили у типа» было бы неотличимо от «вернули глобальный словарь».
	for _, authored := range []string{tmVerbAdd, tmVerbRm} {
		require.Falsef(t, domain.IsVerbOfType(authored, peer),
			"глагол %q объявлен и у vpc_network (набор: %v) — набор снова стал платформенным, "+
				"а не атрибутом типа", authored, peer)
	}

	// Имя отношения собирается эмиттером, а не выписывается. Здесь утверждается,
	// что собранное имя ВХОДИТ в объявленный типом набор отношений: разойдись они —
	// эмиссия адресовала бы отношение, которого у типа нет.
	rels := authzmap.VerbRelationsOfType(tmType)
	for _, want := range []string{tmRelAdd, tmRelRm} {
		require.Containsf(t, rels, want,
			"набор отношений типа %q не содержит %q (набор: %v)", tmType, want, rels)
	}
	require.Equal(t, tmRelAdd, authzmap.VerbRelationPrefix+domain.NormalizeVerb(tmVerbAdd),
		"имя отношения разошлось с тем, что соберёт эмиттер из авторского написания")
	require.Equal(t, tmRelRm, authzmap.VerbRelationPrefix+domain.NormalizeVerb(tmVerbRm),
		"имя отношения разошлось с тем, что соберёт эмиттер из авторского написания")

	t.Logf("перепись: набор типа %s = %v (%d глаголов); набор соседа vpc_network = %v",
		tmType, verbs, len(verbs), peer)
}

// TestNLBTargetMembership_SupersetOfUpdate — свойство НАДМНОЖЕСТВА против
// ПРИМЕНЯЕМОГО вывода, реконсайлер не участвует (NLB-TGT-1-07, часть 1).
//
// Ради чего надмножество: тот, кто сегодня вправе править группу, держит выдачу,
// проецирующую глагол `update`. Вопрос о новом отношении обязан разрешиться
// ВЕТВЬЮ `or v_update` и найти ТУ ЖЕ выдачу — тогда переключение гейтинга не
// требует ре-материализации ни одной выдачи и не имеет окна, в котором прежний
// держатель отказан. Без надмножества переключение отключило бы всех редакторов
// до следующего прохода реконсайлера.
//
// Надмножество ОДНОСТОРОННЕ: держатель нового отношения не получает права менять
// саму группу — это и есть различение, ради которого под-фаза существует.
//
// ГДЕ БЕРЁТСЯ ИСХОД. Прежде проба поднимала движок отношений контейнером и клала
// по прямому кортежу на субъекта. Ни движка, ни карты чарта, из которой в него
// грузили заготовку модели, в дереве нет. Исход теперь считает форма вердикта
// поверх собственной базы iam, а право субъекта выражено ТЕМ ЖЕ, чем оно
// выражено в продукте, — ВЫДАЧЕЙ роли, проецирующей глагол. Это не ослабление, а
// уточнение: прямой глагольный кортеж своя база не производит вовсе (проекция
// журнала глаголы намеренно не переносит — их выводит форма), поэтому фикстура,
// писавшая его, описывала бы состояние, которого продукт не достигает.
func TestNLBTargetMembership_SupersetOfUpdate(t *testing.T) {
	withIAMTx(t, func(ctx context.Context, tx pgx.Tx) {
		w := seedTargetGroupWorld(t, ctx, tx)

		allows := func(subject, relation string) bool {
			t.Helper()
			return saAllows(t, ctx, tx, subject, relation, w.group)
		}

		// Отсутствие выдачи утверждается, а не подразумевается: иначе
		// «разрешено ветвью or v_update» неотличимо от «выдача всё-таки есть».
		require.Falsef(t, allows(tmSubjNone, tmRelAdd),
			"посторонний субъект разрешает %s — состояние не пусто, значит источник "+
				"разрешения ниже не установлен", tmRelAdd)

		// Несущее утверждение: держатель выдачи ТОЛЬКО на `update` управляет составом.
		require.Truef(t, allows(tmSubjUpd, tmRelAdd),
			"держатель выдачи на update не разрешает %s — ветви `or v_update` нет, значит "+
				"переключение гейтинга отключило бы всех сегодняшних редакторов", tmRelAdd)
		require.Truef(t, allows(tmSubjUpd, tmRelRm),
			"держатель выдачи на update не разрешает %s — то же окно отказа", tmRelRm)

		// Прямая выдача нового глагола работает сама по себе.
		require.Truef(t, allows(tmSubjAdd, tmRelAdd), "выдача на %s не разрешает его", tmVerbAdd)
		require.Truef(t, allows(tmSubjRm, tmRelRm), "выдача на %s не разрешает его", tmVerbRm)

		// Односторонность: управление составом НЕ даёт изменения самой группы.
		for _, subj := range []string{tmSubjAdd, tmSubjRm} {
			for _, rel := range []string{"v_update", "v_delete"} {
				require.Falsef(t, allows(subj, rel),
					"%s разрешает %s — надмножество стало эквивалентностью, различение исчезло",
					subj, rel)
			}
		}

		// Управление составом не выводится из чтения.
		for _, rel := range []string{tmRelAdd, tmRelRm} {
			require.Falsef(t, allows(tmSubjView, rel),
				"держатель выдачи только на get разрешает %s — наблюдатель получил управление "+
					"составом", rel)
		}
		// Парный положительный к предыдущему отрицанию: наблюдатель жив.
		require.True(t, allows(tmSubjView, "v_get"),
			"держатель выдачи на get не разрешает v_get — состояние сломано, и отрицания выше "+
				"зеленели бы на пустоте")

		// Управление составом не даёт друг друга: два глагола различимы между собой.
		require.Falsef(t, allows(tmSubjAdd, tmRelRm), "держатель %s разрешает %s", tmRelAdd, tmRelRm)
		require.Falsef(t, allows(tmSubjRm, tmRelAdd), "держатель %s разрешает %s", tmRelRm, tmRelAdd)
	})
}

// tmWorld — мир пробы: группа целей внутри проекта, и ни одного лишнего права.
type tmWorld struct {
	group saObject
}

// seedTargetGroupWorld кладёт аккаунт, проект, группу целей и ЧЕТЫРЕ выдачи —
// по одной на субъекта, каждая ровно с одним глаголом в проекции роли.
//
// По одному глаголу на роль — несущее свойство фикстуры, а не аккуратность: пока
// у субъекта ровно один глагол, у каждого «разрешено» ниже ровно один возможный
// источник, и «разрешилось ветвью вывода» отличимо от «разрешилось своей же
// выдачей».
func seedTargetGroupWorld(t *testing.T, ctx context.Context, tx pgx.Tx) tmWorld {
	t.Helper()
	const (
		acc  = "acc-tmprobe"
		prj  = "prj-tmprobe"
		root = "usr-tmrowowner"
		grp  = "tgr-tmprobe"
	)
	saExec(t, ctx, tx,
		`INSERT INTO kaname.accounts (id, name, owner_user_id) VALUES ($1, 'account-tm', $2)`,
		acc, root)
	saUser(t, ctx, tx, root, acc)
	saExec(t, ctx, tx,
		`INSERT INTO kaname.projects (id, account_id, name) VALUES ($1, $2, 'project-tm')`,
		prj, acc)
	saPointer(t, ctx, tx, "project", prj, "account", "account:"+acc)
	saEdge(t, ctx, tx, tmType, grp, "project", prj)

	for _, g := range []struct {
		subject string
		verb    string
	}{
		{tmSubjUpd, "update"},
		{tmSubjAdd, tmVerbAdd},
		{tmSubjRm, tmVerbRm},
		{tmSubjView, "get"},
	} {
		id := strings.TrimPrefix(g.subject, "user:")
		saUser(t, ctx, tx, id, acc)
		tmGrant(t, ctx, tx, acc, prj, id, g.verb)
	}
	// Посторонний — настоящая строка без единой выдачи: субъект, которого в базе
	// нет вовсе, отвечал бы отказом по другой причине, чем «права не выдано».
	saUser(t, ctx, tx, strings.TrimPrefix(tmSubjNone, "user:"), acc)

	return tmWorld{group: saObject{tmType, grp}}
}

// tmGrant заводит роль ровно на ОДИН глагол типа группы целей и привязывает её к
// субъекту на область проекта — той же тройкой строк, какой это делает продукт:
// проекция глаголов роли, якорная ветвь её правила и сама выдача с её субъектом.
//
// Имя глагола ПРИВОДИТСЯ доменной функцией, а не пишется руками: проекция роли
// хранится в канонической форме (ограничение схемы это и требует), и фикстура,
// написавшая `addTargets` дословно, посеяла бы строку, которой запрос не найдёт,
// — отличить это от «права нет» стало бы нечем.
func tmGrant(t *testing.T, ctx context.Context, tx pgx.Tx, account, project, subjectID, verb string) {
	t.Helper()
	role := "rol-tm-" + strings.ToLower(verb)
	binding := "abn-tm-" + subjectID
	catalogType := authzmap.CatalogTypeName(tmType)
	canonical := strings.ToLower(strings.TrimSpace(verb))

	saExec(t, ctx, tx,
		`INSERT INTO kaname.roles (id, account_id, name, permissions)
		 VALUES ($1, $2, $3, '["loadbalancer.targetGroups.*.get"]'::jsonb)
		 ON CONFLICT DO NOTHING`,
		role, account, "tm_"+canonical)
	saExec(t, ctx, tx,
		`INSERT INTO kaname.role_verb (role_id, object_type, verb) VALUES ($1, $2, $3)
		 ON CONFLICT DO NOTHING`,
		role, catalogType, canonical)
	saExec(t, ctx, tx,
		`INSERT INTO kaname.role_rule_selectors
		   (role_id, rule_fp, arm, object_types, match_labels)
		 VALUES ($1, 'fp-tm', 'anchor', ARRAY[$2::text], '{}'::jsonb)
		 ON CONFLICT DO NOTHING`,
		role, catalogType)
	saExec(t, ctx, tx,
		`INSERT INTO kaname.access_bindings
		   (id, subject_type, subject_id, role_id, resource_type, resource_id, status)
		 VALUES ($1, 'user', $2, $3, 'project', $4, 'ACTIVE')`,
		binding, subjectID, role, project)
	saExec(t, ctx, tx,
		`INSERT INTO kaname.access_binding_subjects (binding_id, subject_type, subject_id)
		 VALUES ($1, 'user', $2)`, binding, subjectID)
}

// TestNLBTargetMembership_IsExpandableRelation — отношение спрашиваемо ровно тогда,
// когда объявлено у типа (NLB-TGT-1-18).
//
// Иначе жило бы окно «энфорсится и неспрашиваемо»: точка решения уже требует отношение,
// а развёртка доступа по нему отвечает отказом формата — то есть выданное право
// невозможно ни увидеть, ни проверить.
func TestNLBTargetMembership_IsExpandableRelation(t *testing.T) {
	for _, rel := range []string{tmRelAdd, tmRelRm} {
		require.Truef(t, authzmap.IsExpandableRelation(rel),
			"развёртка доступа не принимает %q — отношение энфорсилось бы, оставаясь неспрашиваемым", rel)
	}
	// Парный отрицательный: множество РАСШИРЯЕМО, а не ОТКРЫТО — машинерия модели
	// в поверхность вопроса не попала.
	for _, rel := range []string{"sg_v_update", "g_admin_project", "system_admin", "owner"} {
		require.Falsef(t, authzmap.IsExpandableRelation(rel),
			"развёртка доступа приняла машинерию модели %q — множество стало открытым", rel)
	}
}
