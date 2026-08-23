// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// acting_as_a_person_integration_test.go — «действовать ОТ ИМЕНИ человека» и
// «править ЕГО ЗАПИСЬ» решаются РАЗНО, на той двери, куда приходит каждый запрос
// платформы (`AuthorizeService.CheckRelation` — то, что зовёт
// `InternalIAMService.Check`).
//
// # Чем эта проба отличается от соседней в authzmap
//
// Гейт `authzmap/acting_as_a_person_is_not_editing_his_record_test.go` читает
// МОДЕЛЬ: он утверждает, что у отношения токенов нет источников уровня аккаунта.
// Здесь то же свойство спрашивается ВЕРДИКТОМ по закоммиченным строкам — то есть
// проверяется не текст модели, а исход. Разъехаться они могут молча: у края своя
// композиция (ответ формы плюс плоский надзор администратора облака), и провязана
// она в композиционном корне, а не в модели.
//
// Именно поэтому уровень 1 утверждается ЗДЕСЬ, а не там: короткое замыкание
// администратора облака в модель не входит и входить не должно.
//
// # Что сеется и чем именно — ВСЕ ТРИ пути, которыми право доходит до пригласившего
//
//	выдача на аккаунт с ролью, дающей правку `iam.user` — ровно то, что
//	  материализует реконсайлер на свежей строке приглашённого (invite.go зовёт
//	  reconcileObject "iam.user" сразу после коммита);
//	факт `admin @ account:<acc>` — ДЕЛЕГИРОВАННЫЙ администратор аккаунта;
//	факт `owner @ account:<acc>` — владелец аккаунта.
//
// Глагол прямым фактом НЕ сеется, и это не пробел фикстуры: проекция журнала
// отказывается переносить `v_*` в `relation_fact` намеренно (миграция 0098) —
// глагол выводится из выдачи, копия сделала бы сравнение тождеством. Поэтому
// пообъектный путь выражается ЕДИНСТВЕННЫМ способом, каким его выражает продукт:
// строками выдачи, роли и её селектора.
//
// Настоящий Postgres. Пропускается под кратким режимом.

package service_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// actingAsGateFromCatalog — отношение и тип объекта, которыми край гейтит выпуск
// персонального токена.
//
// Спрашивается У КАТАЛОГА, а не пишется литералом: каталог генерируется из proto
// и является единственным источником per-RPC решения края. Литерал здесь означал
// бы, что проба утверждает о СВОЁМ представлении гейта, а не о действующем.
func actingAsGateFromCatalog(t *testing.T, fqn string) (relation, objectType string) {
	t.Helper()
	root := monorepoRootForActingAs(t)
	const rel = "services/iam/internal/apps/kacho/seed/embedded/permission_catalog.json"
	data, err := os.ReadFile(filepath.Join(root, rel))
	require.NoErrorf(t, err, "каталог прав %s не прочитан — у пробы нет источника гейта", rel)

	var entries []struct {
		FQN              string `json:"fqn"`
		RequiredRelation string `json:"required_relation"`
		ScopeExtractor   struct {
			ObjectType string `json:"object_type"`
		} `json:"scope_extractor"`
	}
	require.NoError(t, json.Unmarshal(data, &entries))
	require.NotEmpty(t, entries, "каталог прав разобран в ноль записей")
	for _, e := range entries {
		if e.FQN == fqn {
			require.NotEmptyf(t, e.RequiredRelation, "%s в каталоге без required_relation", fqn)
			require.NotEmptyf(t, e.ScopeExtractor.ObjectType, "%s в каталоге без scope_extractor", fqn)
			return e.RequiredRelation, e.ScopeExtractor.ObjectType
		}
	}
	t.Fatalf("каталог не знает %s — проба утверждала бы о несуществующем гейте", fqn)
	return "", ""
}

func monorepoRootForActingAs(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	require.NoError(t, err)
	dir := wd
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		require.NotEqualf(t, parent, dir, "корень монорепо (go.mod) не найден от %s", wd)
		dir = parent
	}
}

// TestIssuingAPersonalTokenIsNotReachableFromInsideTheAccount — вердикт по
// закоммиченным строкам.
func TestIssuingAPersonalTokenIsNotReachableFromInsideTheAccount(t *testing.T) {
	w := newCIWorld(t)

	const (
		acc        = "acc-actas1"
		owner      = "usr-actasown1"
		inviter    = "usr-actasinv1"
		invitee    = "usr-actasnew1"
		stranger   = "usr-actasstr1"
		cloudAdmin = "usr-actascld1"
	)
	w.seedAccountWithOwner(t, acc, owner)
	w.seedUser(t, inviter, acc)
	w.seedUser(t, invitee, acc)
	w.seedUser(t, stranger, acc)
	w.seedUser(t, cloudAdmin, acc)

	obj := "iam_user:" + invitee

	// Путь 1 — ВЫДАЧА внутри аккаунта, чья роль даёт правку личности. Это тот
	// самый пообъектный доступ, который реконсайлер материализует на строке
	// приглашённого сразу после коммита приглашения.
	seedRoleGrantingUserEdit(t, w, "rol-actas1", "acb-actas1", inviter, acc)
	// Путь 2 — делегированный администратор аккаунта.
	w.factThroughJournal(t, "user:"+inviter, "admin", "account", acc)
	// Путь 3 — владелец аккаунта.
	w.factThroughJournal(t, "user:"+owner, "owner", "account", acc)
	// Сам человек. Кортеж пишется на заведении пользователя (internal_upsert.go).
	w.factThroughJournal(t, "user:"+invitee, "subject", "iam_user", invitee)
	// Уровень 1.
	w.factThroughJournal(t, "user:"+cloudAdmin, "system_admin", "cluster", "cluster_kacho_root")

	issueRel, issueType := actingAsGateFromCatalog(t, "kacho.cloud.iam.v1.UserTokenService/Issue")
	revokeRel, revokeType := actingAsGateFromCatalog(t, "kacho.cloud.iam.v1.UserTokenService/Revoke")
	require.Equalf(t, "iam_user", issueType, "выпуск токена гейтится не на объекте личности (%s)", issueType)
	require.Equalf(t, "iam_user", revokeType, "отзыв токена гейтится не на объекте личности (%s)", revokeType)

	// ── КОНТРОЛЬ ФИКСТУРЫ ────────────────────────────────────────────────────
	// Пригласивший ДЕЙСТВИТЕЛЬНО что-то держит на этой строке: правку записи.
	// Без этого утверждения отрицания ниже были бы истинны и на пустом посеве.
	require.True(t, w.allowed(t, "user:"+inviter, "v_update", obj),
		"КОНТРОЛЬ: пригласивший обязан держать правку записи — иначе фикстура ничего не посеяла "+
			"и все отрицания ниже вакуумны")
	require.True(t, w.allowed(t, "user:"+owner, "v_update", obj),
		"КОНТРОЛЬ: владелец аккаунта обязан держать правку записи на строке своего члена")

	// ── ОТРИЦАНИЕ — предмет пробы ────────────────────────────────────────────
	for _, c := range []struct {
		who, rel, what string
	}{
		{inviter, issueRel, "выпуск"},
		{inviter, revokeRel, "отзыв"},
		{owner, issueRel, "выпуск"},
		{owner, revokeRel, "отзыв"},
		{stranger, issueRel, "выпуск"},
	} {
		require.Falsef(t, w.allowed(t, "user:"+c.who, c.rel, obj),
			"%s персонального токена (%s) достался держателю права ВНУТРИ аккаунта (user:%s). "+
				"Удостоверение действует всюду, где действует его владелец, включая аккаунты, "+
				"к которым этот держатель отношения не имеет: личность здесь глобальна, одна "+
				"строка на все аккаунты человека. Право действовать ОТ ИМЕНИ не выводится из "+
				"права править запись.", c.what, c.rel, c.who)
	}

	// ── ПОЛОЖИТЕЛЬНЫЕ КОНТРОЛИ ───────────────────────────────────────────────
	// Сам человек. Без этого запрет выше зеленел бы на отношении, которого не
	// держит никто, — то есть на сломанной чеканке.
	require.True(t, w.allowed(t, "user:"+invitee, issueRel, obj),
		"сам человек обязан выпускать СВОЙ токен: удостоверение принадлежит ему")
	require.True(t, w.allowed(t, "user:"+invitee, revokeRel, obj),
		"сам человек обязан отзывать СВОЙ токен")
	// Уровень 1 — плоский надзор администратора облака, аварийный путь.
	require.True(t, w.allowed(t, "user:"+cloudAdmin, issueRel, obj),
		"уровень 1 (администратор облака) обязан сохранить выпуск: его надзор — плоское "+
			"короткое замыкание службы, а не источник в модели")

	// ПЕРЕЧЕНЬ СВОИХ УДОСТОВЕРЕНИЙ. Отзыв, недостижимый владельцу, отзывом не
	// является: идентификатор выдаётся один раз, и потерявший его без перечня
	// снять удостоверение не может. Поэтому чтение — надмножество прежнего:
	// сам человек ДОБАВЛЕН, держатель перечисления на личности НЕ снят.
	listRel, listType := actingAsGateFromCatalog(t, "kacho.cloud.iam.v1.UserTokenService/List")
	require.Equalf(t, "iam_user", listType, "перечень токенов гейтится не на объекте личности (%s)", listType)
	require.True(t, w.allowed(t, "user:"+invitee, listRel, obj),
		"сам человек обязан видеть перечень СВОИХ удостоверений — иначе потерянный "+
			"идентификатор делает отзыв недостижимым для владельца")
	require.True(t, w.allowed(t, "user:"+inviter, listRel, obj),
		"КОНТРОЛЬ надмножества: держатель перечисления на личности не потерял чтение — "+
			"изменение обязано было только ДОБАВИТЬ источник")
	require.False(t, w.allowed(t, "user:"+stranger, listRel, obj),
		"посторонний член аккаунта перечня чужих удостоверений не видит")

	// Чужой человек своим отношением до ЧУЖОЙ строки не достаёт.
	require.False(t, w.allowed(t, "user:"+invitee, issueRel, "iam_user:"+stranger),
		"собственное право не переносится на строку другого человека")

	t.Logf("перепись: гейт выпуска %s.%s · гейт отзыва %s.%s · гейт перечня %s.%s · "+
		"субъектов спрошено 6", issueType, issueRel, revokeType, revokeRel, listType, listRel)
}

// seedRoleGrantingUserEdit кладёт роль, дающую ПРАВКУ ЛИЧНОСТИ, и выдачу этой
// роли субъекту на весь аккаунт — тот самый путь, которым пообъектный доступ
// приезжает пригласившему.
//
// Три строки, и ни одна не лишняя: без проекции глаголов роль не даёт ничего, без
// селектора она не адресует ни одного объекта, без строки субъекта выдачи её не
// видит вопрос о доступе. Фикстура, кладущая меньше, доказывала бы запрет на
// пустоте.
func seedRoleGrantingUserEdit(t *testing.T, w *ciWorld, roleID, bindingID, subjectID, accountID string) {
	t.Helper()
	w.exec(t, `INSERT INTO kacho_iam.roles (id, name, permissions, rules, cluster_id)
	           VALUES ($1, 'test.useredit', '[]'::jsonb,
	                   jsonb_build_array(jsonb_build_object(
	                       'module', 'iam', 'resources', jsonb_build_array('user'),
	                       'verbs',  jsonb_build_array('update'))),
	                   'cluster_kacho_root')`, roleID)
	// Тип — в ТОЧЕЧНОЙ форме каталога: именно так его кладёт прод, и именно так
	// его читает вопрос о доступе.
	w.exec(t, `INSERT INTO kacho_iam.role_verb (role_id, object_type, verb)
	           VALUES ($1, 'iam.user', 'update')`, roleID)
	w.exec(t, `INSERT INTO kacho_iam.role_rule_selectors
	             (role_id, rule_fp, arm, object_types, match_labels)
	           VALUES ($1, 'fp-actas', 'anchor', ARRAY['iam.user'::text], '{}'::jsonb)`, roleID)
	w.exec(t, `INSERT INTO kacho_iam.access_bindings
	             (id, subject_type, subject_id, role_id, resource_type, resource_id, status)
	           VALUES ($1, 'user', $2, $3, 'account', $4, 'ACTIVE')`,
		bindingID, subjectID, roleID, accountID)
	w.exec(t, `INSERT INTO kacho_iam.access_binding_subjects (binding_id, subject_type, subject_id)
	           VALUES ($1, 'user', $2)`, bindingID, subjectID)
}
