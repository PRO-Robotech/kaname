// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package relverdict_test

// derivation_reverse_integration_test.go — ОБРАТНЫЕ вопросы находят право,
// которое модель ВЫВОДИТ.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ЗДЕСЬ ПРОВЕРЯЕТСЯ И ПОЧЕМУ ЭТО НЕ ОТТЕНОК
//
// Прямой вопрос уже раскладывается по модели (`derivation_integration_test.go`).
// Обратные — перечисление объектов, перечисление субъектов и разбор оснований —
// раскладывались не по ней, а по ИМЕНИ отношения. Форма, ищущая имя буквально,
// отвечает «нет» держателю права, которое модель ему даёт, и на обратном вопросе
// это выглядит хуже, чем отказ: администратор облака НЕ ВИДИТ СЕБЯ в списке тех,
// кто имеет право, а его объекты не попадают в перечисление доступного. Ответ
// при этом не пуст и не помечен неполным — он просто тише правды, и по нему
// принимают решение «доступа нет».
//
// Проба ставит источник максимально ДАЛЕКО от вопроса — ровно как прямая: право
// лежит на кластере строкой `system_admin`, спрашивают `v_get` на сети, между
// ними проект и аккаунт. Совпадение имён исключено by construction.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ОТРИЦАНИЕ ЗДЕСЬ НЕСУЩЕЕ, А НЕ ВЕЖЛИВОЕ
//
// Утверждение «выводимое право находится» зеленеет на любой форме, которая
// находит ВСЁ. Поэтому рядом с каждым положительным стоит субъект, чьё право
// выводится из источника в ЧУЖОЙ области (владелец другого аккаунта), и субъект
// без единой строки. Первый ловит вывод, потерявший границу области; второй —
// вывод, ставший всеразрешением.

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg/relverdict"
)

// seedTwoAccountsChain строит ДВЕ цепи под одним кластером:
//
//	net-XX → prj-1 → acc-1 ─┐
//	net-99 → prj-9 → acc-2 ─┴→ cluster
//
// Две нужны затем, что вывод обязан не только доставать, но и ОСТАНАВЛИВАТЬСЯ:
// владелец acc-2 не имеет ничего в acc-1, хотя источник у него того же вида.
func seedTwoAccountsChain(t *testing.T, ctx context.Context, tx pgx.Tx, nets []string) {
	t.Helper()
	seedTenant(t, ctx, tx)
	exec(t, ctx, tx,
		`INSERT INTO kacho_iam.accounts (id, name, owner_user_id)
		 VALUES ('acc-2', 'other-account', 'usr-1') ON CONFLICT DO NOTHING`)
	exec(t, ctx, tx,
		`INSERT INTO kacho_iam.projects (id, account_id, name) VALUES ('prj-9', 'acc-2', 'other')
		 ON CONFLICT DO NOTHING`)
	// Субъекты — НАСТОЯЩИМИ строками: выдача ссылается на пользователя внешним
	// ключом, и посев, обходящий его, доказывал бы работу запроса на данных,
	// которых в проде не бывает.
	exec(t, ctx, tx,
		`INSERT INTO kacho_iam.users (id, external_id, email, account_id)
		 VALUES ('usr-admin',    'ext-admin', 'admin@kacho.local', 'acc-1'),
		        ('usr-outsider', 'ext-out',   'out@kacho.local',   'acc-2')
		 ON CONFLICT DO NOTHING`)
	// ПО ОДНОМУ РЕБРУ НА ЗВЕНО — форма, которую производят производители дерева.
	// Цепь до корня собирается ОБХОДОМ, и фикстура обязана оставлять его
	// наблюдаемым: положи она замыкание, различить обход и одно чтение стало бы
	// нечем.
	exec(t, ctx, tx,
		`INSERT INTO kacho_iam.resource_parent_edge
		   (object_type, object_id, parent_type, parent_id, depth)
		 VALUES ('project', 'prj-1', 'account', 'acc-1', 1),
		        ('project', 'prj-9', 'account', 'acc-2', 1),
		        ('account', 'acc-1', 'cluster', 'cluster_kacho_root', 1),
		        ('account', 'acc-2', 'cluster', 'cluster_kacho_root', 1)`)
	for _, id := range nets {
		exec(t, ctx, tx,
			`INSERT INTO kacho_iam.resource_mirror (object_type, object_id) VALUES ($2, $1)`,
			id, catalogFormOf(t, "vpc_network"))
		exec(t, ctx, tx,
			`INSERT INTO kacho_iam.resource_parent_edge
			   (object_type, object_id, parent_type, parent_id, depth)
			 VALUES ('vpc_network', $1, 'project', 'prj-1', 1)`, id)
	}
	// Сеть ЧУЖОГО аккаунта — та же форма, другая область.
	exec(t, ctx, tx,
		`INSERT INTO kacho_iam.resource_mirror (object_type, object_id) VALUES ($1, 'net-99')`,
		catalogFormOf(t, "vpc_network"))
	exec(t, ctx, tx,
		`INSERT INTO kacho_iam.resource_parent_edge
		   (object_type, object_id, parent_type, parent_id, depth)
		 VALUES ('vpc_network', 'net-99', 'project', 'prj-9', 1)`)
}

// seedCloudAdminAndForeignOwner кладёт два источника ОДНОГО вида на разной
// высоте: администратор облака на кластере и владелец чужого аккаунта.
func seedCloudAdminAndForeignOwner(t *testing.T, ctx context.Context, tx pgx.Tx) {
	t.Helper()
	exec(t, ctx, tx,
		`INSERT INTO kacho_iam.relation_fact (object_type, object_id, relation, subject)
		 VALUES ('cluster', 'cluster_kacho_root', 'system_admin', 'user:usr-admin'),
		        ('account', 'acc-2',              'owner',        'user:usr-outsider')`)
}

func listAll(t *testing.T, ctx context.Context, tx pgx.Tx, subject string, limit int) []string {
	t.Helper()
	var seen []string
	after := ""
	for page := 0; page < 50; page++ {
		ids, next, err := relverdict.List(ctx, tx, relverdict.ListQuery{
			Subject: subject, ObjectType: "vpc_network", Relation: "v_get",
			AfterID: after, Limit: limit,
		})
		if err != nil {
			t.Fatalf("страница %d для %s: %v", page, subject, err)
		}
		seen = append(seen, ids...)
		if next == "" {
			return seen
		}
		after = next
	}
	t.Fatalf("обход для %s не сошёлся за 50 страниц — продолжение не двигается", subject)
	return nil
}

// Перечисление обязано отдать объекты, право на которые модель ВЫВОДИТ.
func TestList_CloudAdministratorSeesWhatTheModelDerives(t *testing.T) {
	withTx(t, func(ctx context.Context, tx pgx.Tx) {
		nets := []string{"net-01", "net-02", "net-03"}
		seedTwoAccountsChain(t, ctx, tx, nets)
		seedCloudAdminAndForeignOwner(t, ctx, tx)

		got := listAll(t, ctx, tx, "user:usr-admin", 100)
		set := map[string]bool{}
		for _, id := range got {
			set[id] = true
		}
		for _, want := range nets {
			if !set[want] {
				t.Errorf("объект %s не попал в перечисление для администратора облака (%v). "+
					"Строка лежит на кластере под именем system_admin, спрашивают v_get на "+
					"сети — форма, ищущая имя буквально, скрывает объект при живом праве",
					want, got)
			}
		}
		// Администратор ОБЛАКА видит и чужой аккаунт: его право каскадит на всё
		// внутри кластера. Утверждение положительное, а не «не видит»: перепутать
		// эти две стороны значило бы закрепить дефект вместо свойства.
		if !set["net-99"] {
			t.Errorf("администратор облака не увидел объект второго аккаунта (%v) — "+
				"его право распространяется на всё внутри кластера", got)
		}

		// Отрицание 1: тот же вид источника, но в ЧУЖОЙ области. Владелец acc-2
		// не видит ничего из acc-1 — иначе вывод потерял границу области.
		outsider := listAll(t, ctx, tx, "user:usr-outsider", 100)
		for _, id := range outsider {
			if id != "net-99" {
				t.Errorf("владелец чужого аккаунта увидел %s (%v) — вывод достал за границу "+
					"своей области", id, outsider)
			}
		}
		if len(outsider) != 1 {
			t.Errorf("владелец acc-2 увидел %d объектов (%v), ожидался ровно свой один — "+
				"положительный контроль к отрицанию выше", len(outsider), outsider)
		}

		// Отрицание 2: субъект без единой строки не видит ничего.
		if nobody := listAll(t, ctx, tx, "user:usr-nobody", 100); len(nobody) != 0 {
			t.Errorf("субъект без прав увидел %d объектов: %v", len(nobody), nobody)
		}

		t.Logf("осмотрено: объектов в зеркале %d, администратор облака увидел %d %v",
			len(nets)+1, len(got), got)
	})
}

// Страница и её продолжение сохраняются, а объект с НЕСКОЛЬКИМИ основаниями
// называется ровно один раз.
//
// Дубль здесь не косметика: перечисление отдаёт страницу по курсору, и повтор
// идентификатора либо съедает место в странице, либо (при повторе на границе)
// сдвигает курсор так, что следующая страница начинается не там.
func TestList_PagesThroughDerivedObjectsWithoutLossOrDuplication(t *testing.T) {
	withTx(t, func(ctx context.Context, tx pgx.Tx) {
		nets := []string{"net-01", "net-02", "net-03", "net-04", "net-05"}
		seedTwoAccountsChain(t, ctx, tx, nets)
		seedCloudAdminAndForeignOwner(t, ctx, tx)

		// Второе основание на ТОМ ЖЕ объекте: прямой факт на самой сети.
		exec(t, ctx, tx,
			`INSERT INTO kacho_iam.relation_fact (object_type, object_id, relation, subject)
			 VALUES ('vpc_network', 'net-02', 'v_get', 'user:usr-admin')`)
		// Третье основание: выдача роли на проект — тому же субъекту.
		seedRole(t, ctx, tx, "rol-der", "vpc_network", "get", "anchor", "{}")
		exec(t, ctx, tx,
			`INSERT INTO kacho_iam.access_bindings
			   (id, subject_type, subject_id, role_id, resource_type, resource_id, status)
			 VALUES ('acb-der', 'user', 'usr-admin', 'rol-der', 'project', 'prj-1', 'ACTIVE')`)
		exec(t, ctx, tx,
			`INSERT INTO kacho_iam.access_binding_subjects (binding_id, subject_type, subject_id)
			 VALUES ('acb-der', 'user', 'usr-admin')`)

		// Объект в зеркале, но ВНЕ всякой цепи: до него не достаёт ни один
		// источник, включая кластерный. Без него «страница верна» зеленело бы на
		// форме, отдающей весь тип.
		exec(t, ctx, tx,
			`INSERT INTO kacho_iam.resource_mirror (object_type, object_id) VALUES ($1, 'net-orphan')`,
			catalogFormOf(t, "vpc_network"))

		count := map[string]int{}
		got := listAll(t, ctx, tx, "user:usr-admin", 2)
		for _, id := range got {
			count[id]++
		}
		for _, want := range append(append([]string{}, nets...), "net-99") {
			switch count[want] {
			case 1: // ровно один раз — и это предмет утверждения
			case 0:
				t.Errorf("объект %s потерян при обходе страницами по 2 (%v)", want, got)
			default:
				t.Errorf("объект %s назван %d раза (%v) — два основания дали два места в "+
					"странице, и курсор сдвинулся не туда", want, count[want], got)
			}
		}
		if count["net-orphan"] != 0 {
			t.Errorf("объект вне всякой цепи попал в перечисление (%v) — вывод стал "+
				"всеразрешением", got)
		}
		if len(got) != len(nets)+1 {
			t.Errorf("обход отдал %d объектов (%v), ожидалось %d", len(got), got, len(nets)+1)
		}

		t.Logf("осмотрено: страницами по 2 отдано %d объектов, оснований на net-02 три, "+
			"вне цепи 1", len(got))
	})
}

// Перечисление субъектов обязано назвать того, чьё право ВЫВОДИТСЯ.
func TestSubjects_CloudAdministratorIsAmongTheSubjects(t *testing.T) {
	withTx(t, func(ctx context.Context, tx pgx.Tx) {
		seedTwoAccountsChain(t, ctx, tx, []string{"net-01"})
		seedCloudAdminAndForeignOwner(t, ctx, tx)

		got, _, err := relverdict.Subjects(ctx, tx, relverdict.SubjectsQuery{
			ObjectType: "vpc_network", ObjectID: "net-01", Relation: "v_get", Limit: 100,
		})
		if err != nil {
			t.Fatalf("перечисление субъектов: %v", err)
		}
		set := map[string]bool{}
		for _, s := range got {
			set[s] = true
		}
		if !set["user:usr-admin"] {
			t.Errorf("администратор облака не назван среди субъектов (%v) — по такому ответу "+
				"заключают, что доступа у него нет, тогда как модель его даёт", got)
		}
		// Отрицание: владелец ЧУЖОГО аккаунта права на этот объект не имеет.
		if set["user:usr-outsider"] {
			t.Errorf("назван владелец чужого аккаунта (%v) — вывод достал за границу области", got)
		}
		// Отрицание: субъект без строк.
		if set["user:usr-nobody"] {
			t.Errorf("назван субъект без единой строки (%v)", got)
		}

		t.Logf("осмотрено: субъектов %d %v", len(got), got)
	})
}

// Разбор обязан назвать выводимое основание И место, где оно лежит.
//
// Без места ответ бесполезен ровно там, где он нужнее всего: «право есть»
// известно и так, а вопрос задают, чтобы понять, ЧТО СНЯТЬ. Основание на
// кластере, названное без кластера, отправляет искать выдачу на самом объекте —
// и там её нет.
func TestExpand_NamesTheDerivedGroundAndWhereItLies(t *testing.T) {
	withTx(t, func(ctx context.Context, tx pgx.Tx) {
		seedTwoAccountsChain(t, ctx, tx, []string{"net-01"})
		seedCloudAdminAndForeignOwner(t, ctx, tx)

		got, err := relverdict.Expand(ctx, tx, "vpc_network", "net-01", "v_get")
		if err != nil {
			t.Fatalf("разбор: %v", err)
		}
		var derived *relverdict.Source
		for i := range got {
			if got[i].Subject == "user:usr-admin" {
				derived = &got[i]
			}
			if got[i].Subject == "user:usr-outsider" {
				t.Errorf("названо основание владельца чужого аккаунта: %+v", got[i])
			}
		}
		if derived == nil {
			t.Fatalf("выводимое основание не названо (%+v) — разбор, молчащий про источник, "+
				"по которому доступ реально есть, читается как «оснований нет»", got)
		}
		if derived.Kind != "fact" {
			t.Errorf("вид основания %q, ожидался fact: %+v", derived.Kind, *derived)
		}
		if derived.ScopeType != "cluster" || derived.ScopeID != "cluster_kacho_root" {
			t.Errorf("основание названо без места, где лежит (%+v) — снять его негде: на самом "+
				"объекте такой строки нет", *derived)
		}
		if derived.Detail == "" {
			t.Errorf("основание названо без отношения (%+v) — неизвестно, ЧТО снимать", *derived)
		}

		t.Logf("осмотрено: оснований %d, выводимое %+v", len(got), *derived)
	})
}

// Отношение, которого модель не знает, — ОШИБКА для КАЖДОГО из трёх вопросов, а
// не пустой ответ.
//
// Пустой ответ на опечатку неотличим от честного «никто/ничего», и искать его
// идут в правах, где строки нет ни у кого.
func TestReverseQuestions_RelationUnknownToTheModelIsAnErrorNotAnEmptyAnswer(t *testing.T) {
	withTx(t, func(ctx context.Context, tx pgx.Tx) {
		seedTwoAccountsChain(t, ctx, tx, []string{"net-01"})

		if ids, _, err := relverdict.List(ctx, tx, relverdict.ListQuery{
			Subject: "user:usr-1", ObjectType: "vpc_network", Relation: "v_gte", Limit: 10,
		}); err == nil {
			t.Errorf("перечисление приняло отношение, которого в модели нет, и вернуло %v", ids)
		}
		if subs, _, err := relverdict.Subjects(ctx, tx, relverdict.SubjectsQuery{
			ObjectType: "vpc_network", ObjectID: "net-01", Relation: "v_gte", Limit: 10,
		}); err == nil {
			t.Errorf("перечисление субъектов приняло отношение, которого в модели нет, "+
				"и вернуло %v", subs)
		}
		if src, err := relverdict.Expand(ctx, tx, "vpc_network", "net-01", "v_gte"); err == nil {
			t.Errorf("разбор принял отношение, которого в модели нет, и вернул %v", src)
		}

		// Положительный контроль рядом: известное отношение проходит. Без него
		// три отрицания выше зеленели бы на форме, отвергающей ВСЁ.
		if _, _, err := relverdict.List(ctx, tx, relverdict.ListQuery{
			Subject: "user:usr-1", ObjectType: "vpc_network", Relation: "v_get", Limit: 10,
		}); err != nil {
			t.Errorf("известное отношение отвергнуто: %v", err)
		}
	})
}

// Ответы обратных вопросов и прямого обязаны сходиться на ОДНОМ и том же
// состоянии базы.
//
// Проба сравнивает не с ожиданием автора, а два ответа между собой: перечисление
// говорит «этот объект доступен», прямой вопрос обязан сказать про него Allow.
// Расхождение здесь означает, что две формы одного пакета разошлись в том, что
// считают правом, — и разошлись бы молча.
func TestReverseAndDirectAnswersAgreeOnTheSameState(t *testing.T) {
	withTx(t, func(ctx context.Context, tx pgx.Tx) {
		nets := []string{"net-01", "net-02"}
		seedTwoAccountsChain(t, ctx, tx, nets)
		seedCloudAdminAndForeignOwner(t, ctx, tx)

		for _, subject := range []string{"user:usr-admin", "user:usr-outsider", "user:usr-nobody"} {
			listed := map[string]bool{}
			for _, id := range listAll(t, ctx, tx, subject, 100) {
				listed[id] = true
			}
			for _, id := range append(append([]string{}, nets...), "net-99") {
				v, _, err := relverdict.Ask(ctx, tx, relverdict.Query{
					Subject: subject, ObjectType: "vpc_network", ObjectID: id, Relation: "v_get",
				})
				if err != nil {
					t.Fatalf("прямой вопрос %s о %s: %v", subject, id, err)
				}
				want := v == relverdict.Allow
				if listed[id] != want {
					t.Errorf("расхождение форм на %s/%s: перечисление=%v, прямой вопрос=%s",
						subject, id, listed[id], v)
				}
				// Субъекты обратного вопроса обязаны согласиться с прямым по тому же
				// объекту: право, найденное одним, обязано быть видно другому.
				subs, _, err := relverdict.Subjects(ctx, tx, relverdict.SubjectsQuery{
					ObjectType: "vpc_network", ObjectID: id, Relation: "v_get", Limit: 100,
				})
				if err != nil {
					t.Fatalf("субъекты %s: %v", id, err)
				}
				named := false
				for _, s := range subs {
					if s == subject {
						named = true
					}
				}
				if named != want {
					t.Errorf("расхождение форм на %s/%s: субъекты=%v (%v), прямой вопрос=%s",
						subject, id, named, subs, v)
				}
			}
		}
		t.Logf("осмотрено: сверено %d пар (субъект × объект) тремя формами", 3*(len(nets)+1))
	})
}

// Курсор перечисления не теряет и не повторяет объект при странице в ОДНУ
// строку — граница, на которой ошибка курсора видна раньше всего.
func TestList_CursorHoldsAtPageSizeOne(t *testing.T) {
	withTx(t, func(ctx context.Context, tx pgx.Tx) {
		nets := []string{"net-01", "net-02", "net-03"}
		seedTwoAccountsChain(t, ctx, tx, nets)
		seedCloudAdminAndForeignOwner(t, ctx, tx)

		got := listAll(t, ctx, tx, "user:usr-admin", 1)
		want := append(append([]string{}, nets...), "net-99")
		if len(got) != len(want) {
			t.Fatalf("страницами по одной отдано %d (%v), ожидалось %d", len(got), got, len(want))
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("порядок обхода разошёлся: %v, ожидалось %v", got, want)
			}
		}
		t.Logf("осмотрено: страниц %d, объектов %d", len(got)+1, len(got))
	})
}
