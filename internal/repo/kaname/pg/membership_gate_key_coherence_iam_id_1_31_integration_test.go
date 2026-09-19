// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// membership_gate_key_coherence_iam_id_1_31_integration_test.go — ДОБОР B1 к
// красной полосе сценария IAM-ID-1-31 (приёмка IAM-ID-1, S3.1).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРИВЯЗКА — К СУЩЕСТВУ, А НЕ К ОТПЕЧАТКУ
//
// СУЩЕСТВО, которое утверждает эта проба: объект гейта чтения личности — ЧЛЕНСТВО,
// адресуемое СОБСТВЕННЫМ неизменяемым идентификатором (`iam_membership:<mbr-…>`),
// и админ соседнего аккаунта через этот объект до личности не дотягивается.
//
// Отпечаток родительской приёмки сейчас ДВИЖЕТСЯ (круг ревью не закрыт):
// c5937b4e → 24b4bf85 → следующий. Он ПОДЛЕЖИТ ПЕРЕПИНУ здесь после закрытия
// круга. Прежний отпечаток f4ffbd08 обесценен и намеренно НЕ называется якорем:
// вердикт привязан к отпечатку, а не к имени документа
// (`change-graph.md §2`), поэтому ссылка на обесцененный была бы ложью о том,
// что именно одобрено.
//
// ─────────────────────────────────────────────────────────────────────────────
// ФОРМА КЛЮЧА — ВАРИАНТ D: СОБСТВЕННЫЙ id ЧЛЕНСТВА, ЧИТАЕМЫЙ ИЗ СТРОКИ
//
// Объект гейта — `iam_membership:<mbr-…>`, где `mbr-…` это `memberships.id`:
// реальная колонка с посаженным ограничением формы (`memberships_id_form_check`),
// неизменяемая на всю жизнь строки (ban #15). Край берёт её из поля запроса
// `membership_id` — деривация читает ОДНО поле верхнего уровня.
//
// Композит `<account>:<user>` ОТВЕРГНУТ: он потребовал бы расширить арность
// деривации в фундаменте (прецедентов ноль, радиус 15 не-тестовых файлов двух
// продуктов), а у членства уже есть стабильный id.
//
// ПОЧЕМУ ЭТО УСИЛЕНИЕ, А НЕ ПОДГОНКА. Прежняя редакция РЕКОНСТРУИРОВАЛА ключ
// конкатенацией (`<account>:<user>`) — то есть проба воспроизводила то, что
// обязан производить продукт, и кортежа под таким ключом не было бы НИКОГДА, ни
// до реализации, ни после: красный приходил от самой конкатенации, а не от
// отсутствия предмета. Теперь ключ ЧИТАЕТСЯ из посеянной строки, а тип и
// источник идентификатора — из КАТАЛОГА ПРАВ, то есть оттуда же, откуда их берёт
// край. Проба перестала дублировать логику продукта и начала её сверять.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ — КОГЕРЕНТНОСТЬ КРАЙ↔РЕКОНСАЙЛЕР, А НЕ ОДНА ИЗ ДВУХ СТОРОН
//
// Разрыв невидим ни с одной стороны по отдельности
// (`security-hardening §«Разрыв, невидимый ни с одной стороны по отдельности»`):
//
//   - СТРУКТУРНАЯ полоса (`internal/authzmap`) читает каталог и компилирует
//     модель — она не исполняет реального доступа и не знает, материализован ли
//     кортеж;
//   - ЭТА проба исполняет реальный доступ по журналу прямого факта — но объект
//     вопроса она обязана брать ТАМ ЖЕ, ГДЕ ЕГО БЕРЁТ КРАЙ, иначе она утверждает
//     про объект, которого край никогда не соберёт (ровно порок прежней редакции).
//
// Поэтому объект здесь ВЫВОДИТСЯ из записи каталога (`object_type` +
// `from_request_field`) и применяется к РЕАЛЬНОЙ посеянной строке членства.
// Утверждение переворачивается ровно тогда, когда переезжает гейт, — и ни на шаг
// раньше: самоистечение by construction, без выписанного наперёд литерала.
//
// ─────────────────────────────────────────────────────────────────────────────
// ДВЕ СТОРОНЫ (§gate-authoring «отрицание только в паре с положительным»)
//
//   - ПОЛОЖИТЕЛЬНЫЙ БЛИЗНЕЦ: админ СВОЕГО аккаунта A обязан достать личность через
//     объект гейта. Без него отрицание вакуумно: «до объекта не достаёт никто»
//     истинно тривиально на непроматериализованном объекте — ровно этим и был
//     зелен прежний отрицательный близнец.
//   - ОТРИЦАНИЕ (ПРЕДМЕТ, красное сегодня): админ СОСЕДНЕГО аккаунта B НЕ вправе
//     достать личность через объект гейта. Один изменённый факт против близнеца:
//     ТОТ ЖЕ объект, отличается лишь аккаунт админа (A против B).
//
// Сегодня гейт стоит на `iam_user:<p>` — ГЛОБАЛЬНОЙ личности, у которой предков
// столько, сколько у человека членств, — и админ соседнего аккаунта до неё
// ДОТЯГИВАЕТСЯ. Это и есть честный красный: предмета (переезда гейта на членство)
// НЕТ. Прежняя редакция этой утечки не ловила вовсе — она спрашивала про объект,
// которого край не собирает.
//
// TEST-ONLY (ban #13): прод-код не тронут.
// Прогон: `go test ./internal/repo/kaname/pg/ -run MembershipGate_IAMID131`
// (testcontainers + Docker). Пропускается под -short.

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// catalogPathForGate — каталог прав: та же координата, по которой его читает
// структурная полоса. Он и есть источник, из которого край берёт тип объекта и
// поле-источник идентификатора.
const catalogPathForGate = "services/iam/internal/apps/kaname/seed/embedded/permission_catalog.json"

// identityObjectTypes — типы, под которыми живёт объект гейта чтения личности:
// сегодняшний (ГЛОБАЛЬНАЯ личность) и целевой (одно-аккаунтное членство).
// Перечень нужен, чтобы вывести RPC чтения личности из каталога, не выписывая их
// имён: половинный переезд (один глагол переехал, другой нет) обязан попасть в
// обход, а не выпасть из него.
var identityObjectTypes = map[string]struct{}{
	"iam_user":       {},
	"iam_membership": {},
}

// identityReadRelations — отношения ЧТЕНИЯ, на которых стоит гейт личности.
var identityReadRelations = map[string]struct{}{"v_get": {}, "v_list": {}}

// identityReadGate — запись каталога, по которой КРАЙ собирает объект вопроса:
// `fmt.Sprintf("%s:%s", object_type, <значение поля from_request_field>)`.
type identityReadGate struct {
	fqn        string
	objectType string
	fromField  string
}

// identityReadGates — ВЫВОДИТ перечень RPC чтения личности ИЗ КАТАЛОГА, а не из
// выписанного литерала: литерал пережил бы переезд гейта молча, а вывод следует
// за ним by construction.
func identityReadGates(t *testing.T) []identityReadGate {
	t.Helper()
	data, err := os.ReadFile(platformtree.RequirePath(t, catalogPathForGate))
	require.NoErrorf(t, err, "каталог прав %s не прочитан — судить объект гейта нечем", catalogPathForGate)

	var entries []struct {
		FQN              string `json:"fqn"`
		RequiredRelation string `json:"required_relation"`
		ScopeExtractor   struct {
			ObjectType       string `json:"object_type"`
			FromRequestField string `json:"from_request_field"`
		} `json:"scope_extractor"`
	}
	require.NoError(t, json.Unmarshal(data, &entries))

	out := make([]identityReadGate, 0, 2)
	for _, e := range entries {
		if _, ok := identityReadRelations[e.RequiredRelation]; !ok {
			continue
		}
		if _, ok := identityObjectTypes[e.ScopeExtractor.ObjectType]; !ok {
			continue
		}
		out = append(out, identityReadGate{
			fqn:        e.FQN,
			objectType: e.ScopeExtractor.ObjectType,
			fromField:  e.ScopeExtractor.FromRequestField,
		})
	}
	// Непустота — предпосылка: на пустом перечне оба утверждения ниже были бы
	// истинны тривиально, и проба отчиталась бы зелёным, не спросив ничего
	// (`change-graph.md §7`: пустой предмет не даёт зелёного).
	require.NotEmptyf(t, out,
		"каталог прочитан (%d записей), но ни одного RPC чтения личности в нём не найдено — "+
			"перечень пережил свой предмет: либо отношения чтения переименованы, либо тип объекта "+
			"личности больше не входит в %v. Пустой обход не даёт вердикта", len(entries), identityObjectTypes)
	return out
}

// objectFor — объект вопроса, собранный ТАК ЖЕ, КАК ЕГО СОБИРАЕТ КРАЙ: тип из
// каталога, идентификатор — значение того поля запроса, которое каталог назвал
// источником.
//
// Распознаватель обязан знать ВСЕ законные формы поля-источника
// (`testing.md §«Гейт на класс»` п. 7): форма, о которой он не знает, дала бы не
// красное и не зелёное, а МОЛЧАНИЕ. Поэтому неизвестное поле — громкий отказ, а
// не пропуск.
func (g identityReadGate) objectFor(t *testing.T, userID domain.UserID, membershipID string) string {
	t.Helper()
	switch g.fromField {
	case "user_id":
		return g.objectType + ":" + string(userID)
	case "membership_id":
		return g.objectType + ":" + membershipID
	default:
		require.FailNowf(t, "поле-источник идентификатора не опознано",
			"каталог называет источником идентификатора объекта гейта %s поле %q, а проба знает только "+
				"%q (идентификатор ГЛОБАЛЬНОЙ личности) и %q (собственный id членства). Значения для этого "+
				"поля у пробы нет, поэтому собрать объект так, как его собирает край, она не может: это "+
				"«не выполнилось», а не вердикт. Допиши форму в objectFor вместе с её значением в фикстуре",
			g.fqn, g.fromField, "user_id", "membership_id")
		return ""
	}
}

// membershipObjectID — собственный неизменяемый идентификатор членства, ПРОЧИТАННЫЙ
// из посеянной строки.
//
// Ключ authz-объекта проба НЕ РЕКОНСТРУИРУЕТ. Прежняя редакция склеивала его
// конкатенацией `<account>:<user>` — то есть воспроизводила логику продукта, и
// расхождение с продуктом было невыразимо by construction: проба сверялась сама с
// собой. Здесь берётся РЕАЛЬНАЯ колонка `memberships.id`, форму которой держит
// ограничение БД `memberships_id_form_check`.
func membershipObjectID(t *testing.T, ctx context.Context, pool *pgxpool.Pool, userID domain.UserID, accountID domain.AccountID) string {
	t.Helper()
	var id string
	require.NoErrorf(t, pool.QueryRow(ctx,
		`SELECT id FROM kaname.memberships WHERE user_id = $1 AND account_id = $2`,
		string(userID), string(accountID)).Scan(&id),
		"строка членства (%s → %s) не прочитана — читать ключ authz-объекта неоткуда", userID, accountID)
	require.NotEmpty(t, id, "членство прочитано с пустым идентификатором — ключ объекта гейта пуст")
	return id
}

// requireMembershipIDIsFormBound — предпосылка формы ключа: идентификатор членства
// связан ограничением БД, а не соглашением пробы.
//
// Утверждается НАЛИЧИЕ ограничения, а не его текст: переписав регулярное выражение
// сюда, проба завела бы ВТОРОЕ место об одном предмете, и разошлись бы они молча.
func requireMembershipIDIsFormBound(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM pg_constraint WHERE conname = 'memberships_id_form_check'`).Scan(&n))
	require.Equalf(t, 1, n,
		"ограничение формы `memberships_id_form_check` в базе не найдено — идентификатор членства "+
			"перестал быть связанной координатой, и адресовать им объект гейта больше нельзя (ban #15)")
}

// bindingReachesObject — реальный доступ СКВОЗЬ материализацию: достаёт ли
// субъект `fgaUser` объект `object` через выдачу `bID` — есть ли в журнале
// прямого факта ХОТЯ БЫ ОДИН материализованный кортеж (любого отношения) этой
// выдачи на этот объект. Отношение-агностичен намеренно: «достаёт личность» —
// это факт достижимости, а не конкретный ярус.
func bindingReachesObject(t *testing.T, ctx context.Context, pool *pgxpool.Pool, bID domain.AccessBindingID, fgaUser, object string) bool {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.access_binding_emitted_tuples
		  WHERE binding_id = $1 AND fga_user = $2 AND object = $3`,
		string(bID), fgaUser, object).Scan(&n))
	return n > 0
}

// accountParentsOf — аккаунты, которые цепь областей называет предками объекта.
func accountParentsOf(t *testing.T, ctx context.Context, pool *pgxpool.Pool, objectType, objectID string) []string {
	t.Helper()
	rows, err := pool.Query(ctx,
		`SELECT parent_id FROM kaname.resource_scope_edge
		  WHERE object_type = $1 AND object_id = $2 AND parent_type = 'account'
		  ORDER BY parent_id`, objectType, objectID)
	require.NoError(t, err)
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		require.NoError(t, rows.Scan(&id))
		out = append(out, id)
	}
	require.NoError(t, rows.Err())
	return out
}

// TestMembershipGate_IAMID131_OwnAccountReaches_NeighbourIsolated — ДОБОР B1,
// ЧЕСТНЫЙ КРАСНЫЙ. Когерентность край↔реконсайлер на РЕАЛЬНОМ объекте членства.
func TestMembershipGate_IAMID131_OwnAccountReaches_NeighbourIsolated(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)
	rec, _ := newReconciler(pool)

	// ── фикстура: человек-личность в ДВУХ аккаунтах A и B ─────────────────────
	ownerA := mustSeedUser(t, ctx, pool, "b1-own-a")
	ownerB := mustSeedUser(t, ctx, pool, "b1-own-b")
	accA := seedAccount(t, ctx, repo, "acc-b1-a", ownerA)
	accB := seedAccount(t, ctx, repo, "acc-b1-b", ownerB)

	p := domain.UserID(seedNativeUser(t, ctx, pool, accA.ID, "b1p"))
	// Членства заводятся явно и идемпотентно (ON CONFLICT DO UPDATE): зеркало S1
	// могло уже завести членство в колонке-аккаунте A, второе членство в B кладём
	// сами — расхождение, ради которого сценарий и написан.
	seedMembership(t, ctx, pool, p, accA.ID, "ACTIVE")
	seedMembership(t, ctx, pool, p, accB.ID, "ACTIVE")

	var nmem int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.memberships WHERE user_id = $1`, string(p)).Scan(&nmem))
	require.Equal(t, 2, nmem,
		"предпосылка сценария: у личности ровно два членства (A и B) — иначе изоляция соседа беспредметна")

	// ── КЛЮЧ ЧИТАЕТСЯ ИЗ СТРОКИ, А НЕ СОБИРАЕТСЯ ПРОБОЙ ───────────────────────
	requireMembershipIDIsFormBound(t, ctx, pool)
	mbrA := membershipObjectID(t, ctx, pool, p, accA.ID)
	mbrB := membershipObjectID(t, ctx, pool, p, accB.ID)
	require.NotEqual(t, mbrA, mbrB,
		"членства в разных аккаунтах обязаны быть РАЗНЫМИ объектами: одно-аккаунтность гейта держится "+
			"тем, что у каждой пары человек×аккаунт свой неизменяемый id")

	// ── предпосылка замысла: одно-аккаунтность членства против много-аккаунтности
	//    личности. Это ПРИЧИНА, по которой тип членства заведён: у личности
	//    предков столько, сколько членств, и `admin from account` читает любого.
	mbrParents := accountParentsOf(t, ctx, pool, "iam_membership", mbrA)
	userParents := accountParentsOf(t, ctx, pool, "iam_user", string(p))
	require.Equalf(t, []string{string(accA.ID)}, mbrParents,
		"цепь областей обязана называть у членства РОВНО ОДИН аккаунт-предок (A) — на этом стоит весь "+
			"замысел S3.1. Названо: %v", mbrParents)
	require.Lenf(t, userParents, 2,
		"предпосылка утечки: у ГЛОБАЛЬНОЙ личности предков столько, сколько членств (ожидались два: A и B). "+
			"Названо: %v. Без двух предков соседний админ не дотянулся бы и отрицание ниже было бы вакуумным",
		userParents)

	require.NoError(t, seed.BackfillOwnerBindings(ctx, pool))
	ownerBIDA := ownerBindingFor(t, ctx, pool, accA.ID)
	ownerBIDB := ownerBindingFor(t, ctx, pool, accB.ID)

	// ── контроль машинности: реконсайлер и журнал реально материализуют ───────
	// Порядок несущий (`change-graph.md §5`): СНАЧАЛА вся проверка фикстуры, и
	// лишь ПОТОМ проба возможности. Иначе сломанная фикстура выдала бы себя за
	// отсутствующую возможность.
	require.NoError(t, rec.ReconcileBinding(ctx, ownerBIDA))
	require.NoError(t, rec.ReconcileBinding(ctx, ownerBIDB))
	objMbrA := "iam_membership:" + mbrA
	objMbrB := "iam_membership:" + mbrB
	require.True(t,
		bindingReachesObject(t, ctx, pool, ownerBIDA, "user:"+string(ownerA), objMbrA),
		"машинность: реконсайлер материализует кортеж области по членству — админ аккаунта A достаёт "+
			"СВОЁ членство "+objMbrA+". Без этого контроля красный ниже читался бы как «не выполнилось»")
	require.True(t,
		bindingReachesObject(t, ctx, pool, ownerBIDB, "user:"+string(ownerB), objMbrB),
		"машинность (вторая сторона): админ аккаунта B достаёт СВОЁ членство "+objMbrB+". Обе выдачи живы, "+
			"поэтому молчание на чужом объекте ниже — это изоляция, а не мёртвая выдача")
	require.False(t,
		bindingReachesObject(t, ctx, pool, ownerBIDB, "user:"+string(ownerB), objMbrA),
		"изоляция by construction: админ соседнего аккаунта B не достаёт членство "+objMbrA+", "+
			"принадлежащее аккаунту A. Это свойство ОБЪЕКТА членства — оно уже есть, и именно на него "+
			"обязан переехать гейт")

	// ── ПРЕДМЕТ: КОГЕРЕНТНОСТЬ — объект, который СОБИРАЕТ КРАЙ ────────────────
	// Объект берётся из каталога прав (тип + поле-источник идентификатора) и
	// применяется к РЕАЛЬНОЙ посеянной строке членства. Утверждение перевернётся
	// ровно тогда, когда переедет гейт.
	gates := identityReadGates(t)
	for _, g := range gates {
		obj := g.objectFor(t, p, mbrA)

		// ПОЛОЖИТЕЛЬНЫЙ БЛИЗНЕЦ: свой админ достаёт личность через объект гейта.
		assert.Truef(t,
			bindingReachesObject(t, ctx, pool, ownerBIDA, "user:"+string(ownerA), obj),
			"IAM-ID-1-31 (B1) — БЛИЗНЕЦ. Админ СВОЕГО аккаунта A обязан достать личность через объект "+
				"гейта %s (RPC %s, тип %q, идентификатор из поля %q). Красное здесь означало бы, что переезд "+
				"гейта СЛОМАЛ законный доступ: край собрал объект, под которым кортежа нет.",
			obj, g.fqn, g.objectType, g.fromField)

		// ОТРИЦАНИЕ (ПРЕДМЕТ): соседний админ НЕ достаёт личность через объект гейта.
		// Один изменённый факт против близнеца — аккаунт админа.
		assert.Falsef(t,
			bindingReachesObject(t, ctx, pool, ownerBIDB, "user:"+string(ownerB), obj),
			"IAM-ID-1-31 (B1) — КОГЕРЕНТНОСТЬ КРАЙ↔РЕКОНСАЙЛЕР, ПРЕДМЕТ. Админ СОСЕДНЕГО аккаунта B "+
				"ДОТЯГИВАЕТСЯ до личности через объект гейта %s (RPC %s, тип %q, идентификатор из поля %q). "+
				"Гейт всё ещё спрашивает про ГЛОБАЛЬНУЮ личность, у которой предков столько, сколько у "+
				"человека членств (%v), поэтому `admin from account` разворачивается в администратора ЛЮБОГО "+
				"из них. Реконсайлер СВОЮ половину уже держит: одно-аккаунтный объект членства %s "+
				"материализован и соседу недоступен (проверено выше). Предмет отсутствует ИМЕННО на стороне "+
				"края: тип объекта обязан стать `iam_membership`, а источник идентификатора — полем "+
				"`membership_id`. Ни структурная полоса, ни эта проба по отдельности разрыва не видят: "+
				"первая не исполняет доступа, вторая обязана брать объект там же, где его берёт край.",
			obj, g.fqn, g.objectType, g.fromField, userParents, objMbrA)
	}

	t.Logf("перепись: членств у личности %d · ключи ПРОЧИТАНЫ из строк (A=%s, B=%s) · "+
		"предков у членства %d, у личности %d · RPC чтения личности выведено из каталога %d · "+
		"объект гейта сегодня %q, идентификатор из поля %q",
		nmem, mbrA, mbrB, len(mbrParents), len(userParents), len(gates), gates[0].objectType, gates[0].fromField)
}
