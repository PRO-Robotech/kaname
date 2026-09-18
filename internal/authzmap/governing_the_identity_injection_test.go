// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// governing_the_identity_injection_test.go — доказательство, что гейт
// `TestGoverningTheIdentityHasNoAccountLevelSource` СПОСОБЕН упасть и СПОСОБЕН
// смолчать на отношении, которым гейтится `ResetSecondFactor` (kaname#254).
//
// Зелёный гейт означает одно из двух: свойство держится либо предикат ослеп. По
// прочтении эти два состояния неотличимы, поэтому здесь ставится опыт.
//
// # Предикат — ТОТ ЖЕ, а не копия
//
// Опыт зовёт `inspectCredentialRelation` — ту же функцию, что общий предикат
// класса «право над строкой личности»; на чистом дереве его вердикт об
// `identity_suspender` совпадает с тремя утверждениями гейта (нет источников
// уровня аккаунта · невыдаваемо · держит надзор облака), что и проверяется
// первой стороной опыта. Копия предиката доказывала бы, что работает копия.
//
// # Почему инъекция идёт по `identity_suspender`, а привязка — к ResetSecondFactor
//
// `ResetSecondFactor` гейтится каталогом на `iam_user.identity_suspender` (то же
// отношение, что Block/Unblock). Опыт инъектирует ИМЕННО это отношение и тут же
// утверждает, что каталог связывает `ResetSecondFactor` с ним, — иначе «краснеет
// после инъекции» доказывало бы свойство какого-то другого RPC.
//
// # ИНЪЕКЦИЯ ИДЁТ ПО ТИПУ, А НЕ ПО ПОДСТРОКЕ
//
// `replaceDefineInType` сужает замену блоком типа `iam_user` и требует ровно
// одного попадания (`define identity_suspender:` в модели одно); что механизм
// сужает по типу, а не по подстроке, доказано опытом в
// `removing_the_identity_injection_test.go`.
//
// # Вход НАСТОЯЩИЙ, а не синтетика
//
// Каждая ось возвращает форму, которая в этом дереве реально стоит у соседа по
// строке личности: `admin from account` — деривация аккаунтного администратора;
// `[user, service_account]` — прямой список (`editor`); `subject` — так объявлен
// `token_issuer`.
//
// # Осей ТРИ, потому что утверждений у гейта три
//
//	I.   источник уровня аккаунта ВОЗВРАЩАЕТСЯ и НАЗЫВАЕТСЯ;
//	II.  отношение становится ВЫДАВАЕМЫМ (прямой список субъектов);
//	III. надзор облака пропадает — распорядительный сброс становится недостижим.
package authzmap_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/authzplan"
)

const (
	// governingRelation / governingType — предмет опыта. Литерал здесь законен и
	// нужен: опыт РЕДАКТИРУЕТ текст модели, а редактировать можно только
	// названное. Гейт рядом имени не знает — он спрашивает его у каталога.
	governingRelation = "identity_suspender"
	governingType     = "iam_user"

	// governingResetSecondFactorFQN — RPC, ради которого запись внесена (#254);
	// опыт утверждает, что каталог связывает его с отношением выше.
	governingResetSecondFactorFQN = "kaname.cloud.iam.v1.UserService/ResetSecondFactor"

	// governingInjectedAccountLevel — сегодняшняя форма плюс аккаунтный
	// администратор: приносит источник уровня аккаунта (`account#admin`).
	governingInjectedAccountLevel = "define identity_suspender: super_admin from account or admin from account"
	// governingInjectedGrantable — сегодняшняя форма плюс прямой список субъектов:
	// круг держателей внешне тот же, но отношение становится ВЫДАВАЕМЫМ.
	governingInjectedGrantable = "define identity_suspender: [user, service_account] or super_admin from account"
	// governingInjectedNoCloud — сужение, забывшее надзор облака. Форма настоящая:
	// так объявлен `token_issuer`.
	governingInjectedNoCloud = "define identity_suspender: subject"
)

// governingCleanCanonical — канонический текст модели плюс проверка предпосылки:
// ни одной инъектируемой формы в нём быть не должно, иначе «краснеет после
// инъекции» краснело бы и без неё.
func governingCleanCanonical(t *testing.T) string {
	t.Helper()
	path, dsl, err := authzplan.ResolveCanonicalModel()
	require.NoError(t, err)
	require.NotEmptyf(t, dsl, "канонический файл модели пуст: %s", path)
	clean := string(dsl)
	for _, form := range []string{governingInjectedAccountLevel, governingInjectedGrantable, governingInjectedNoCloud} {
		require.NotContainsf(t, clean, form,
			"предпосылка опыта: в %s инъектируемой формы %q быть не должно", path, form)
	}
	return clean
}

func governingInjected(t *testing.T, clean, define string) *authzplan.Model {
	t.Helper()
	text := replaceDefineInType(t, clean, governingType, "define "+governingRelation+":", define)
	require.Containsf(t, text, define, "инъекция %q не внеслась — опыт не поставлен", define)
	m, err := authzplan.ParseModel(text)
	require.NoErrorf(t, err, "инъекция обязана оставаться разбираемой моделью, иначе краснеет "+
		"разбор, а не предикат")
	return m
}

// TestGoverningTheIdentityGate_InjectionCutsBothWays — три оси, обе стороны.
func TestGoverningTheIdentityGate_InjectionCutsBothWays(t *testing.T) {
	clean := governingCleanCanonical(t)
	cleanModel, err := authzplan.ParseModel(clean)
	require.NoError(t, err)

	// Привязка к предмету #254: каталог гейтит ResetSecondFactor ровно тем
	// отношением, которое инъектируется ниже. Разойдись они — опыт краснел бы над
	// свойством чужого RPC.
	catalog := catalogByFQN(t)
	e, ok := catalog[governingResetSecondFactorFQN]
	require.Truef(t, ok, "каталог не знает %s — привязка опыта к предмету #254 отсутствует",
		governingResetSecondFactorFQN)
	require.Equalf(t, governingType, e.objectType,
		"%s гейтится не на объекте личности (%s)", governingResetSecondFactorFQN, e.objectType)
	require.Equalf(t, governingRelation, e.relation,
		"%s гейтится отношением %s, а опыт инъектирует %s — опыт ставится не над тем",
		governingResetSecondFactorFQN, e.relation, governingRelation)

	// ── сторона 1: на чистом дереве предикат молчит по всем трём осям ──────────
	base := inspectCredentialRelation(t, cleanModel, governingType, governingRelation)
	require.Emptyf(t, base.AccountLevel,
		"на дереве без дефекта предикат называет источники уровня аккаунта %v — значит он "+
			"утверждает не то, что измеряет", planSourceNames(base.AccountLevel))
	require.False(t, base.Grantable, "на дереве без дефекта отношение объявлено выдаваемым")
	require.True(t, base.HasCloud, "на дереве без дефекта надзор облака не найден источником")

	// ── ось I: источник уровня аккаунта возвращается ──────────────────────────
	acct := inspectCredentialRelation(t, governingInjected(t, clean, governingInjectedAccountLevel),
		governingType, governingRelation)
	require.NotEmptyf(t, acct.AccountLevel,
		"инъекция %q не поймана: у отношения появился источник уровня аккаунта, а предикат молчит",
		governingInjectedAccountLevel)
	require.Containsf(t, planSourceNames(acct.AccountLevel), "факт account#admin",
		"находка не НАЗЫВАЕТ делегированного распорядителя аккаунта — перечень: %v",
		planSourceNames(acct.AccountLevel))
	require.Truef(t, acct.HasCloud,
		"ось I обязана менять РОВНО одно утверждение гейта: надзор облака здесь остаётся")
	require.Falsef(t, acct.Grantable,
		"ось I обязана менять РОВНО одно утверждение гейта: выдаваемости здесь не появляется")

	// ── ось II: отношение становится выдаваемым ───────────────────────────────
	grant := inspectCredentialRelation(t, governingInjected(t, clean, governingInjectedGrantable),
		governingType, governingRelation)
	require.Truef(t, grant.Grantable,
		"инъекция %q не поймана: у отношения появился прямой список субъектов — то есть право "+
			"распорядительного сброса можно ВРУЧИТЬ, — а предикат молчит", governingInjectedGrantable)
	require.Emptyf(t, grant.AccountLevel,
		"ось II обязана менять РОВНО одно утверждение гейта: источников уровня аккаунта здесь "+
			"не появляется (%v)", planSourceNames(grant.AccountLevel))
	require.Truef(t, grant.HasCloud,
		"ось II обязана менять РОВНО одно утверждение гейта: надзор облака здесь остаётся")

	// ── ось III: надзор облака пропал ─────────────────────────────────────────
	noCloud := inspectCredentialRelation(t, governingInjected(t, clean, governingInjectedNoCloud),
		governingType, governingRelation)
	require.Falsef(t, noCloud.HasCloud,
		"инъекция %q не поймана: распорядительный сброс стал недостижим НИКОМУ, а предикат молчит",
		governingInjectedNoCloud)
	require.Emptyf(t, noCloud.AccountLevel,
		"ось III обязана менять РОВНО одно утверждение гейта: источников уровня аккаунта здесь "+
			"не появляется (%v)", planSourceNames(noCloud.AccountLevel))

	t.Logf("опыт: осей проверено 3 · на чистом дереве источников %d (уровня аккаунта %d) · "+
		"по оси аккаунта найдено %d: %v · привязка каталога %s → %s.%s",
		len(base.Sources), len(base.AccountLevel), len(acct.AccountLevel),
		planSourceNames(acct.AccountLevel), governingResetSecondFactorFQN, e.objectType, e.relation)
}
