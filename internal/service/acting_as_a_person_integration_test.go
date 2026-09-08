// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

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
	const rel = "services/iam/internal/apps/kaname/seed/embedded/permission_catalog.json"
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
	// Корнем берётся САМЫЙ ВНЕШНИЙ `go.mod`, а не первый встречный: у службы
	// теперь СВОЙ модуль, и подъём «до первого» останавливался бы в её каталоге,
	// а пути ниже называют место В ДЕРЕВЕ МОНОРЕПО — от корня.
	outermost := ""
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			outermost = dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			require.NotEmptyf(t, outermost, "корень монорепо (go.mod) не найден от %s", wd)
			return outermost
		}
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
	seedRoleGrantingUserRead(t, w, "rol-actas1", "acb-actas1", inviter, acc)
	// Путь 2 — делегированный администратор аккаунта.
	w.factThroughJournal(t, "user:"+inviter, "admin", "account", acc)
	// Путь 3 — владелец аккаунта.
	w.factThroughJournal(t, "user:"+owner, "owner", "account", acc)
	// Сам человек. Кортеж пишется на заведении пользователя (internal_upsert.go).
	w.factThroughJournal(t, "user:"+invitee, "subject", "iam_user", invitee)
	// Уровень 1.
	w.factThroughJournal(t, "user:"+cloudAdmin, "system_admin", "cluster", "cluster_root")

	issueRel, issueType := actingAsGateFromCatalog(t, "kaname.cloud.iam.v1.UserTokenService/Issue")
	revokeRel, revokeType := actingAsGateFromCatalog(t, "kaname.cloud.iam.v1.UserTokenService/Revoke")
	require.Equalf(t, "iam_user", issueType, "выпуск токена гейтится не на объекте личности (%s)", issueType)
	require.Equalf(t, "iam_user", revokeType, "отзыв токена гейтится не на объекте личности (%s)", revokeType)

	// ── КОНТРОЛЬ ФИКСТУРЫ ────────────────────────────────────────────────────
	// Пригласивший ДЕЙСТВИТЕЛЬНО что-то держит на этой строке: чтение записи.
	// Без этого утверждения отрицания ниже были бы истинны и на пустом посеве.
	//
	// Контроль СТОЯЛ НА ПРАВКЕ и переведён на чтение (#1128): `v_update` снят с
	// типа `iam_user`, поэтому вопрос о нём стал неразрешимым by construction —
	// дверь отвечает не «нет», а отказом. Чтение — то, что директива аккаунту
	// оставляет, и потому годится контролем живого посева.
	require.True(t, w.allowed(t, "user:"+inviter, "v_get", obj),
		"КОНТРОЛЬ: пригласивший обязан держать чтение записи — иначе фикстура ничего не посеяла "+
			"и все отрицания ниже вакуумны")
	require.True(t, w.allowed(t, "user:"+owner, "v_get", obj),
		"КОНТРОЛЬ: владелец аккаунта обязан держать чтение записи на строке своего члена")

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

	// ПЕРЕЧЕНЬ СВОИХ УДОСТОВЕРЕНИЙ — держателей РОВНО ДВА: сам человек и надзор
	// облака.
	//
	// Сам человек перечень видеть ОБЯЗАН: отзыв, недостижимый владельцу, отзывом
	// не является — идентификатор выдаётся один раз, и потерявший его без перечня
	// снять удостоверение не может.
	//
	// А держатель права уровня аккаунта — НЕТ, и здесь стояло обратное. Прежняя
	// редакция требовала «КОНТРОЛЬ надмножества: держатель перечисления на
	// личности не потерял чтение», и для #1086 это было верно: отношение стояло
	// формой `subject or v_list`, то есть чтение и вправду только ДОБАВЛЯЛО
	// источник к перечислению личностей.
	//
	// Форму сузило РЕШЕНИЕ ВЛАДЕЛЬЦА (2026-08-23, #1133): «пользователь не должен
	// видеть список токенов другого пользователя», и по той же линии — «тот кто
	// пригласил может только удалить/добавить права». Отношение стало `subject or
	// super_admin from account`, источников у него по компилятору модели стало
	// два вместо шести, — и прежнее утверждение начало закреплять ОТМЕНЁННОЕ
	// поведение: зеленело на неверном и краснело на верном.
	//
	// Поэтому оно ПЕРЕВЁРНУТО, а не снято. Снятое ничего не стережёт: вернуть
	// источник уровня аккаунта — одна правка модели, и она прошла бы молча.
	//
	// Различающая пара — ниже целиком: людей своего аккаунта распорядитель
	// перечисляет по-прежнему (`v_list` на `iam_user` источники уровня аккаунта
	// сохраняет намеренно), их удостоверения — нет.
	listRel, listType := actingAsGateFromCatalog(t, "kaname.cloud.iam.v1.UserTokenService/List")
	require.Equalf(t, "iam_user", listType, "перечень токенов гейтится не на объекте личности (%s)", listType)
	require.True(t, w.allowed(t, "user:"+invitee, listRel, obj),
		"сам человек обязан видеть перечень СВОИХ удостоверений — иначе потерянный "+
			"идентификатор делает отзыв недостижимым для владельца")
	// КОНТРОЛЬ ФИКСТУРЫ к обоим отказам ниже. Без него они истинны и на пустом
	// посеве — то есть не отличают сужение ЧТЕНИЯ УДОСТОВЕРЕНИЙ от фикстуры,
	// которая ничего не выдала. Спрашивается ровно то право уровня аккаунта,
	// которое решение владельца оставило нетронутым.
	require.True(t, w.allowed(t, "user:"+inviter, "v_list", obj),
		"КОНТРОЛЬ: пригласивший обязан перечислять ЛЮДЕЙ своего аккаунта — иначе отказ "+
			"ниже вакуумен и меряет пустой посев, а не сужение чтения удостоверений")
	require.True(t, w.allowed(t, "user:"+owner, "v_list", obj),
		"КОНТРОЛЬ: владелец аккаунта обязан перечислять ЛЮДЕЙ своего аккаунта")
	for _, who := range []struct{ id, role string }{
		{inviter, "пригласивший (делегированный распорядитель аккаунта)"},
		{owner, "владелец аккаунта"},
	} {
		require.Falsef(t, w.allowed(t, "user:"+who.id, listRel, obj),
			"перечень персональных удостоверений (%s) достался держателю права ВНУТРИ "+
				"аккаунта — %s (user:%s). Личность здесь глобальна: одна строка на все "+
				"аккаунты человека, — значит он увидел бы удостоверения, которыми человек "+
				"действует в аккаунтах, к которым этот держатель отношения не имеет. "+
				"Перечень удостоверений — сведения о личности, а не право на аккаунт.",
			listRel, who.role, who.id)
	}
	require.False(t, w.allowed(t, "user:"+stranger, listRel, obj),
		"посторонний член аккаунта перечня чужих удостоверений не видит")

	// Чужой человек своим отношением до ЧУЖОЙ строки не достаёт.
	require.False(t, w.allowed(t, "user:"+invitee, issueRel, "iam_user:"+stranger),
		"собственное право не переносится на строку другого человека")

	// Перепись СЧИТАЕТСЯ по множеству, а не пишется числом. Здесь стояло
	// «спрошено 6» при пяти различных субъектах — число пережило ту редакцию, в
	// которой было верным, и с тех пор молча лгало о величине осмотренного.
	subjectsAsked := map[string]bool{
		owner: true, inviter: true, invitee: true, stranger: true, cloudAdmin: true,
	}
	t.Logf("перепись: гейт выпуска %s.%s · гейт отзыва %s.%s · гейт перечня %s.%s · "+
		"субъектов спрошено %d · держателей перечня удостоверений ожидается 2 "+
		"(сам человек и надзор облака)",
		issueType, issueRel, revokeType, revokeRel, listType, listRel, len(subjectsAsked))
}

// seedRoleGrantingUserRead кладёт роль, дающую ЧТЕНИЕ ЗАПИСИ личности, и выдачу
// этой роли субъекту на весь аккаунт: тот самый путь, которым пообъектный доступ
// приезжает пригласившему.
//
// ЗДЕСЬ СТОЯЛА ПРАВКА (`update`), и глагол сменён не ради удобства. `v_update`
// снят с типа `iam_user` (#1128): правку записи спрашивает `record_writer`,
// запрет — `identity_suspender`, и читателя у глагола не осталось. Роль,
// называющая `update` на `iam.user`, теперь разрешается в ПУСТОЙ набор —
// материализация сверяется с набором типа и отбрасывает чужой глагол. Значит
// прежняя фикстура клала строку проекции, которой продукт больше не производит,
// то есть была СНИСХОДИТЕЛЬНЕЕ продукта — ровно тот класс, ради которого
// дублёров и разбирают.
//
// Чтение выбрано потому, что это и есть то, что директива аккаунту ОСТАВЛЯЕТ:
// читать своих людей. Роль `iam.user.view` живёт, глагол `v_get` тип объявляет,
// и контроль на нём утверждает живой посев, а не выдуманный.
func seedRoleGrantingUserRead(t *testing.T, w *ciWorld, roleID, bindingID, subjectID, accountID string) {
	t.Helper()
	w.exec(t, `INSERT INTO kaname.roles (id, name, permissions, rules, cluster_id)
	           VALUES ($1, 'test.userread', '[]'::jsonb,
	                   jsonb_build_array(jsonb_build_object(
	                       'module', 'iam', 'resources', jsonb_build_array('user'),
	                       'verbs',  jsonb_build_array('get'))),
	                   'cluster_root')`, roleID)
	// Тип — в ТОЧЕЧНОЙ форме каталога: именно так его кладёт прод, и именно так
	// его читает вопрос о доступе.
	w.exec(t, `INSERT INTO kaname.role_verb (role_id, object_type, verb)
	           VALUES ($1, 'iam.user', 'get')`, roleID)
	w.exec(t, `INSERT INTO kaname.role_rule_selectors
	             (role_id, rule_fp, arm, object_types, match_labels)
	           VALUES ($1, 'fp-actas', 'anchor', ARRAY['iam.user'::text], '{}'::jsonb)`, roleID)
	w.exec(t, `INSERT INTO kaname.access_bindings
	             (id, subject_type, subject_id, role_id, resource_type, resource_id, status)
	           VALUES ($1, 'user', $2, $3, 'account', $4, 'ACTIVE')`,
		bindingID, subjectID, roleID, accountID)
	w.exec(t, `INSERT INTO kaname.access_binding_subjects (binding_id, subject_type, subject_id)
	           VALUES ($1, 'user', $2)`, bindingID, subjectID)
}
