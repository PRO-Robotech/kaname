// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package authzmap_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/services/iam/internal/authzmap"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	"github.com/PRO-Robotech/kacho/services/iam/internal/testsupport/fgatest"
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

// TestNLBTargetMembership_SupersetOfUpdate_OpenFGACheck — свойство НАДМНОЖЕСТВА
// против ПРИМЕНЯЕМОЙ модели, реконсайлер не участвует (NLB-TGT-1-07, часть 1).
//
// Ради чего надмножество: у того, кто сегодня вправе править группу, лежит прямой
// кортеж `v_update`. Запрос нового отношения обязан разрешиться ВЕТВЬЮ `or v_update` и
// найти ТОТ ЖЕ кортеж — тогда переключение гейтинга не требует ре-материализации ни
// одной выдачи и не имеет окна, в котором прежний держатель отказан. Без надмножества
// переключение отключило бы всех редакторов до следующего прохода реконсайлера.
//
// Надмножество ОДНОСТОРОННЕ: держатель нового отношения не получает права менять саму
// группу — это и есть различение, ради которого под-фаза существует.
func TestNLBTargetMembership_SupersetOfUpdate_OpenFGACheck(t *testing.T) {
	h := fgatest.NewFromModelJSON(t, readConfigMapModelJSON(t))
	ctx := context.Background()

	check := func(subject, relation string) bool {
		t.Helper()
		ok, err := h.Client.CheckWithContextConsistent(ctx, subject, relation, tmObject, nil)
		require.NoErrorf(t, err, "Check(%s, %s, %s)", subject, relation, tmObject)
		return ok
	}

	// Ровно по одному прямому кортежу на субъекта — больше в графе ничего нет,
	// поэтому каждое «разрешено» ниже имеет ровно один возможный источник.
	h.Write(t, tmSubjUpd, "v_update", tmObject)
	h.Write(t, tmSubjAdd, tmRelAdd, tmObject)
	h.Write(t, tmSubjRm, tmRelRm, tmObject)
	h.Write(t, tmSubjView, "v_get", tmObject)

	// Отсутствие прямого кортежа утверждается, а не подразумевается: иначе
	// «разрешено ветвью or v_update» неотличимо от «кортеж всё-таки лежит».
	require.Falsef(t, check(tmSubjNone, tmRelAdd),
		"посторонний субъект резолвит %s — граф не пуст, значит источник разрешения ниже не установлен", tmRelAdd)

	// Несущее утверждение: держатель ТОЛЬКО v_update управляет составом.
	require.Truef(t, check(tmSubjUpd, tmRelAdd),
		"держатель v_update не резолвит %s — ветви `or v_update` нет, значит переключение "+
			"гейтинга отключило бы всех сегодняшних редакторов", tmRelAdd)
	require.Truef(t, check(tmSubjUpd, tmRelRm),
		"держатель v_update не резолвит %s — то же окно отказа", tmRelRm)

	// Прямая выдача нового отношения работает сама по себе.
	require.Truef(t, check(tmSubjAdd, tmRelAdd), "прямой кортеж %s не резолвится", tmRelAdd)
	require.Truef(t, check(tmSubjRm, tmRelRm), "прямой кортеж %s не резолвится", tmRelRm)

	// Односторонность: управление составом НЕ даёт изменения самой группы.
	for _, subj := range []string{tmSubjAdd, tmSubjRm} {
		for _, rel := range []string{"v_update", "v_delete"} {
			require.Falsef(t, check(subj, rel),
				"%s резолвит %s — надмножество стало эквивалентностью, различение исчезло", subj, rel)
		}
	}

	// Управление составом не выводится из чтения.
	for _, rel := range []string{tmRelAdd, tmRelRm} {
		require.Falsef(t, check(tmSubjView, rel),
			"держатель только v_get резолвит %s — наблюдатель получил управление составом", rel)
	}
	// Парный положительный к предыдущему отрицанию: наблюдатель жив.
	require.True(t, check(tmSubjView, "v_get"), "держатель v_get не резолвит v_get — граф сломан")

	// Управление составом не даёт друг друга: два глагола различимы между собой.
	require.Falsef(t, check(tmSubjAdd, tmRelRm), "держатель %s резолвит %s", tmRelAdd, tmRelRm)
	require.Falsef(t, check(tmSubjRm, tmRelAdd), "держатель %s резолвит %s", tmRelRm, tmRelAdd)
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
