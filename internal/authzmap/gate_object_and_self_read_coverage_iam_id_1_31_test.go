// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// gate_object_and_self_read_coverage_iam_id_1_31_test.go — полоса RED,
// закрывающая ДВЕ дыры в покрытии сценария IAM-ID-1-31 (class-exposure на
// отпечатке 46d03ba4). Существующие пробы (сосед + близнец `admin from account`)
// честны и НЕ переписываются; эти две — сверх них.
//
// Обе дыры одного рода: структурная проба «объект гейта = iam_membership + тип
// заведён» зеленеет, а дефект тихо проезжает мимо — go-implementer мог бы
// зазеленить модель-пробы и всё равно внести поломку.
//
// ── ДЫРА (а): формирование объекта гейта у КРАЯ ────────────────────────────────
//
// Край строит объект вопроса как `fmt.Sprintf("%s:%s", object_type, id)`
// (`internal/service/authorize_service.go`, `p.object = ...`). Тип берётся из
// каталога (`scope_extractor.object_type`), идентификатор — из поля запроса,
// названного `scope_extractor.from_request_field`. Сегодня у `v_get`/`v_list`:
// `object_type=iam_user`, `from_request_field=user_id` → объект `iam_user:<user_id>`
// (корректен). Если реализация сменит ТОЛЬКО тип на `iam_membership`, оставив
// `from_request_field=user_id`, край соберёт `iam_membership:<user_id>` — членства
// с таким идентификатором НЕТ (членство адресуется парой аккаунт×человек либо
// собственным `mbr-…`), проверка не найдёт кортежа и fail-closed ОТКАЖЕТ законному
// администратору аккаунта A. Модель-пробы при этом зелены: тип заведён, object_type
// = iam_membership. Эта проба утверждает КОГЕРЕНТНОСТЬ: объект гейта = членство И
// идентификатор берётся НЕ из голого user_id.
//
// ── ДЫРА (б): близнец самочтения ──────────────────────────────────────────────
//
// На `iam_user` глагол `v_get` несёт `subject` (человек читает СВОЮ запись —
// самочтение), а `v_list` — не несёт. Существующий близнец проверяет только
// `admin from account`. Если реализация скопирует форму `v_list` на
// `iam_membership.v_get`, самочтение тихо сломается (человек перестанет читать сам
// себя), а обе прежние пробы останутся зелёными. Эта проба утверждает, что
// `iam_membership.v_get` ОБЯЗАН нести источник самочтения `subject`.
//
// Обе пробы — честный красный СЕГОДНЯ по причине отсутствия предмета (тип
// `iam_membership` не заведён, объект гейта ещё `iam_user`, поле ещё `user_id`),
// а не из-за сорванной фикстуры: каталог разобран, модель компилируется.
package authzmap_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/authzplan"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// scopeGate — пара (object_type, from_request_field) из scope_extractor записи
// каталога. Существующий `catalogByFQN` отдаёт только object_type; для дыры (а)
// нужно ещё поле-источник идентификатора, поэтому здесь свой узкий читатель.
type scopeGate struct {
	objectType string
	fromField  string
}

func scopeExtractorByFQN(t *testing.T) map[string]scopeGate {
	t.Helper()
	data, err := os.ReadFile(platformtree.RequirePath(t, catalogRelPath))
	require.NoErrorf(t, err, "каталог прав %s не прочитан", catalogRelPath)

	var entries []struct {
		FQN            string `json:"fqn"`
		ScopeExtractor struct {
			ObjectType       string `json:"object_type"`
			FromRequestField string `json:"from_request_field"`
		} `json:"scope_extractor"`
	}
	require.NoError(t, json.Unmarshal(data, &entries))

	out := make(map[string]scopeGate, len(entries))
	for _, e := range entries {
		out[e.FQN] = scopeGate{objectType: e.ScopeExtractor.ObjectType, fromField: e.ScopeExtractor.FromRequestField}
	}
	return out
}

// bareUserIDField — поле запроса, дающее идентификатор ГЛОБАЛЬНОЙ личности.
// Собранное с типом членства (`iam_membership:<user_id>`) оно даёт объект, строки
// под который не существует.
const bareUserIDField = "user_id"

// TestUserReadGate_IAMID131_EdgeBuildsMembershipObjectNotBareUser — ДЫРА (а),
// честный красный. Объект гейта для чтения личности край обязан собирать из
// идентификатора ЧЛЕНСТВА, а не из голого user_id.
func TestUserReadGate_IAMID131_EdgeBuildsMembershipObjectNotBareUser(t *testing.T) {
	scopes := scopeExtractorByFQN(t)

	// Фикстура: каталог разобран непусто — иначе красный ниже был бы «не выполнилось».
	require.NotEmpty(t, scopes, "каталог прав разобран в ноль записей — предпосылка гейта сломана")

	checked := 0
	for _, fqn := range userReadGateRPCs {
		sc, ok := scopes[fqn]
		require.Truef(t, ok, "каталог не знает %s — перечень «чтение личности» пережил свой предмет", fqn)

		// Объект гейта = членство (одно-аккаунтное).
		assert.Equalf(t, membershipObjectType, sc.objectType,
			"IAM-ID-1-31 (край): объект гейта %s собирается для типа %q, а обязан для %q. "+
				"Край строит объект как fmt.Sprintf(\"%%s:%%s\", object_type, id) — при типе %q объект будет "+
				"собран с идентификатором членства, а не личности.",
			fqn, sc.objectType, membershipObjectType, membershipObjectType)

		// Идентификатор объекта — НЕ голый user_id: иначе край соберёт
		// `iam_membership:<user_id>` — членства с таким id нет, и законному
		// администратору аккаунта A прилетит fail-closed отказ.
		assert.NotEqualf(t, bareUserIDField, sc.fromField,
			"IAM-ID-1-31 (край): АДМИНУ СВОЕГО АККАУНТА A СЛОМАЮТ ДОСТУП. Объект гейта %s "+
				"собирается из поля %q (идентификатор ГЛОБАЛЬНОЙ личности). Сменив тип объекта на %q, но "+
				"оставив источник id = %q, край соберёт `%s:<user_id>` — членства с таким идентификатором "+
				"НЕТ (членство адресуется парой аккаунт×человек либо собственным mbr-id), проверка не найдёт "+
				"кортежа и fail-closed ОТКАЖЕТ законному администратору аккаунта A. Идентификатор объекта "+
				"обязан приходить из идентификатора ЧЛЕНСТВА (пара account+user / membership_id). Модель-пробы "+
				"эту дыру не видят: тип заведён, object_type=iam_membership — они зелены.",
			fqn, sc.fromField, membershipObjectType, bareUserIDField, membershipObjectType)
		checked++
	}

	t.Logf("перепись: записей каталога прочитано %d · RPC чтения личности сверено %d · "+
		"объект гейта обязан быть %q, идентификатор — не из %q", len(scopes), checked, membershipObjectType, bareUserIDField)
}

// selfReadSource — источник самочтения: человек читает СВОЮ запись, будучи её
// subject-ом. На `iam_user.v_get` он есть, на `iam_user.v_list` — нет.
var selfReadSource = planSource{Kind: authzplan.AtomFact, ParentType: "", Relation: "subject"}

// TestUserReadGate_IAMID131_MembershipGetKeepsSelfRead — ДЫРА (б), честный
// красный. `iam_membership.v_get` обязан нести источник самочтения `subject`.
//
// Сегодня тип `iam_membership` не заведён — компиляция вернёт «тип не объявлен»:
// это и есть предмет пробы (самочтение проверить ещё не на чем), честный красный
// по отсутствию предмета, а не по фикстуре.
func TestUserReadGate_IAMID131_MembershipGetKeepsSelfRead(t *testing.T) {
	model := canonicalModel(t)

	plan, err := model.Compile(membershipObjectType, "v_get")
	require.NoErrorf(t, err,
		"IAM-ID-1-31 близнец самочтения: тип %q в модели ещё не заведён — самочтение своей записи "+
			"проверить не на чем (остаток S3.1). После заведения типа `%s.v_get` ОБЯЗАН нести источник "+
			"самочтения `subject`: копирование формы `v_list` (без subject) на `%s.v_get` тихо сломало бы "+
			"чтение человеком собственной записи, а прочие пробы остались бы зелёными.",
		membershipObjectType, membershipObjectType, membershipObjectType)

	got := sourcesOf(t, plan)
	require.Containsf(t, got, selfReadSource,
		"IAM-ID-1-31 близнец самочтения: у `%s.v_get` нет источника самочтения %+v — человек не читает "+
			"СВОЮ запись. На `iam_user.v_get` `subject` есть, на `v_list` нет; форму v_get нельзя подменять "+
			"формой v_list.\nИсточники: %v", membershipObjectType, selfReadSource, sortedKeys(got))

	t.Logf("перепись: тип %q объявлен: %v · источник самочтения %+v присутствует у v_get",
		membershipObjectType, model.Type(membershipObjectType) != nil, selfReadSource)
}
