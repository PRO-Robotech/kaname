// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package audit_test

// user_block_integration_test.go — запрет участию виден ТАМ, ГДЕ ВЫДАЮТ, и
// записан как событие.
//
// Две вещи проверяются вместе намеренно, потому что каждая по отдельности и есть
// дефект, который этот файл исключает:
//
//   - след записывает КТО, КОГО и КОГДА, событием своего рода, а не диффом поля.
//     «Заблокировал человека» и «переименовал метку» не должны читаться в журнале
//     одинаково через год;
//   - состояние реально доезжает до читателя, который решает выдачу. Проба,
//     останавливающаяся на «строка записана», зеленела бы ровно так же, если бы
//     запись уходила туда, куда никто не смотрит, — а это и есть форма исходного
//     дефекта: колонка, по которой решают семь мест, и ни одного писателя.
//
// ПОЧЕМУ ЭТО ЗДЕСЬ, А НЕ ЧЕРЕЗ КРАЙ. Положительный путь через api-gateway
// требует расходуемой действующей личности, состоящей в аккаунте, которым мы
// администрируем, а фикстура края такой не сеет: каждому принципалу
// провизионируется его собственный домашний аккаунт, и заблокировать принципала
// фикстуры значит отравить её на весь прогон. Поэтому наблюдаемый исход
// закрепляется здесь, на настоящей базе и настоящих читателях, а через край
// закреплены негативы и сам маршрут.
//
// Run: `go test ./internal/apps/kaname/api/audit/... -run UserBlock`. Пропускается с -short.

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/pkg/ids"

	internaliam "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/internal_iam"
	userapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/user"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kaname/cloud/iam/v1"
)

// userInviteStatus читает состояние СТРОКИ ЛИЧНОСТИ напрямую из базы.
//
// Прежде здесь стояло «строки членства» — верно ровно до того, как ключ
// идентичности перестал включать аккаунт (20260823050000). Сегодня строка у
// человека одна, а членства живут отдельной таблицей, и старое имя посылало бы
// читателя искать состояние не там.
func userInviteStatus(ctx context.Context, t *testing.T, env *testEnv, uid domain.UserID) string {
	t.Helper()
	var st string
	require.NoError(t, env.pool.QueryRow(ctx,
		`SELECT invite_status FROM kaname.users WHERE id = $1`, string(uid)).Scan(&st))
	return st
}

// TestUserBlock_RecordsTheEventAndReachesTheIssuanceGates — сомкнулись ли
// писатель и читатели.
//
// Читателей здесь ДВА, и оба настоящие: тот, что решает выдачу персонального
// токена (`AccountForUser` — прямо тот аксессор, чьё состояние гейт
// subjectstategate запрещает выбрасывать), и тот, что резолвит субъект для края
// (`LookupSubject`). Одного было бы мало: они читают разными запросами, и
// состояние, доехавшее до одного, могло не доехать до другого — именно так
// когда-то и разошлись две половины одного пути.
func TestUserBlock_RecordsTheEventAndReachesTheIssuanceGates(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	admin, accID := seedUserAccount(t, ctx, env.pool, "blkadm")

	// Расходуемая действующая личность в ТОМ ЖЕ аккаунте — предмет запрета.
	// Расходуемая: заблокировать администратора фикстуры значит отравить её на
	// весь прогон, поэтому запрещается отдельно заведённый человек.
	target := seedExtraUser(t, ctx, env.pool, accID, "blktarget")
	targetExt := fmt.Sprintf("extra-blktarget-%s", target)

	gate := kanamepg.NewUserOAuthClientRepo(env.pool)
	lookup := internaliam.NewLookupSubjectUseCase(env.repo)

	// ── Контрольный случай: до запрета обе двери отвечают «да» ────────────────
	_, mayAuth, err := gate.AccountForUser(ctx, target)
	require.NoError(t, err)
	require.True(t, mayAuth, "действующее членство аутентифицируется — это контрольный случай")

	resp, err := lookup.Execute(ctx, &iamv1.LookupSubjectRequest{
		Key: &iamv1.LookupSubjectRequest_ExternalId{ExternalId: targetExt},
	})
	require.NoError(t, err, "и край резолвит его как действующего субъекта")
	require.Equal(t, string(target), resp.GetUser().GetId())

	// ── Запрет ───────────────────────────────────────────────────────────────
	block := userapp.NewBlockUserUseCase(env.repo, env.opsRepo)
	op, err := block.Execute(withPrincipal(admin), target)
	require.NoError(t, err)
	require.NotEmpty(t, op.ID, "мутация отвечает Operation")
	awaitWorkers(t)

	row := requireOneAuditRow(ctx, t, env.pool, "iam.user.blocked", string(target))
	require.Equal(t, "user", row.payload["resource_type"])
	require.Equal(t, string(target), row.payload["resource_id"], "след называет КОГО")
	require.Equal(t, string(accID), row.payload["account_id"])
	require.Equal(t, string(admin), row.payload["actor"], "след называет КТО")
	require.Equal(t, "BLOCKED", row.payload["invite_status"], "и состояние, в котором строка осталась")
	require.Regexp(t, evtIDFormat, row.id)
	require.NotNil(t, row.tenant)
	require.Equal(t, string(accID), *row.tenant, "аккаунт членства назван полем события")

	// Персональных данных в следе нет — перечислено поимённо, иначе «PII не
	// пишем» остаётся обещанием, а не свойством.
	for _, k := range []string{"email", "display_name", "external_id", "name"} {
		require.NotContains(t, row.payload, k, "персональное поле в следе: %s", k)
	}

	// ── Наблюдаемый исход: обе двери закрылись ────────────────────────────────
	_, mayAuth, err = gate.AccountForUser(ctx, target)
	require.NoError(t, err)
	require.False(t, mayAuth,
		"выдача обязана отказать — это и есть наблюдаемый исход, и именно его "+
			"не заметила бы проба, останавливающаяся на «строка записана»")

	_, err = lookup.Execute(ctx, &iamv1.LookupSubjectRequest{
		Key: &iamv1.LookupSubjectRequest_ExternalId{ExternalId: targetExt},
	})
	require.Error(t, err, "и край больше не резолвит его как действующего")
	require.Contains(t, err.Error(), "blocked",
		"причина названа словами: «есть, но нельзя» и «нет такого» — разные ответы, "+
			"и пустое множество край читает как приглашение провизионировать заново")

	require.Equal(t, "BLOCKED", userInviteStatus(ctx, t, env, target))

	// ── Повтор — успех, и он тоже оставляет след ──────────────────────────────
	_, err = block.Execute(withPrincipal(admin), target)
	require.NoError(t, err, "аргумент — состояние, а не переход: повтор обязан проходить")
	awaitWorkers(t)
	require.Len(t, auditRowsByEventResource(ctx, t, env.pool, "iam.user.blocked", string(target)), 2,
		"повтор тоже записан: повтор без следа — повтор, которого никто не видит")
	require.Equal(t, "BLOCKED", userInviteStatus(ctx, t, env, target))

	// ── Снятие ───────────────────────────────────────────────────────────────
	unblock := userapp.NewUnblockUserUseCase(env.repo, env.opsRepo)
	_, err = unblock.Execute(withPrincipal(admin), target)
	require.NoError(t, err)
	awaitWorkers(t)

	back := requireOneAuditRow(ctx, t, env.pool, "iam.user.unblocked", string(target))
	require.Equal(t, string(admin), back.payload["actor"])
	require.Equal(t, "ACTIVE", back.payload["invite_status"])

	_, mayAuth, err = gate.AccountForUser(ctx, target)
	require.NoError(t, err)
	require.True(t, mayAuth,
		"и участие возможно снова — односторонний контроль это контроль, "+
			"которым оператор не воспользуется")
	resp, err = lookup.Execute(ctx, &iamv1.LookupSubjectRequest{
		Key: &iamv1.LookupSubjectRequest_ExternalId{ExternalId: targetExt},
	})
	require.NoError(t, err)
	require.Equal(t, string(target), resp.GetUser().GetId())
}

// TestUserBlock_ReachesEveryAccountBecauseThePersonIsOneRow — запрет
// принадлежит ЛИЧНОСТИ, поэтому действует во всех её аккаунтах разом, а
// принадлежностей не трогает.
//
// ЧТО ЗДЕСЬ СТОЯЛО РАНЬШЕ И ПОЧЕМУ ЭТОГО БОЛЬШЕ НЕТ. Прежняя проба называлась
// «запрет принадлежит СТРОКЕ членства» и строила набор из ДВУХ строк `users`
// одной личности — действующей в аккаунте A и запрещённой в B, — чтобы
// показать: запись коснулась одной строки, соседняя осталась как была.
// Построить такой набор больше нельзя. Миграция
// 20260823050000_users_identity_uniqueness_goes_global ввела ГЛОБАЛЬНЫЕ ключи
// по почте и по внешнему субъекту, и первая же попытка засеять вторую строку
// получает 23505 — замер: обе прежние пробы падали ИМЕННО НА ПОСЕВЕ, до
// единого утверждения. Один человек — ОДНА строка; принадлежность аккаунтам
// выражают строки `memberships`, и их у него сколько угодно.
//
// Свойство «сколько строк одной личности может быть действующими» держит теперь
// КЛЮЧ БАЗЫ, а не эта проба, и утверждать его прежней фикстурой нельзя —
// фикстуры не существует. Оно проверяется отдельно и с обеих сторон:
// TestUserIdentity_SecondRowForThePersonIsRefusedWithoutLeakingSQL ниже.
//
// Что осталось осмысленным и проверяется здесь:
//
//  1. запрет ДОСТИГАЕТ каждого аккаунта человека — не потому, что он объявлен
//     «широким», а потому, что отвечать по-разному больше нечему: строка одна,
//     значит и ответ у неё один. Это содержательная замена прежнему
//     «row-scoped», а не его ослабление: прежде область действия была
//     предметом утверждения, теперь она следствие ключа, и проба обязана
//     показать именно следствие — перепись строк личности рядом с исходом;
//  2. запрет НЕ трогает принадлежности: блокировка есть свойство личности, а не
//     членства (решение владельца по вопросу В-8; то же говорят миграции 470001
//     и 20260823053000). Членство заблокированного человека остаётся обычным —
//     иначе снятие запрета молча теряло бы принадлежность, которую человеку
//     выдавал вовсе не тот, кто его запрещал;
//  3. снятие возвращает участие, и тоже везде, и тоже не трогая членств:
//     односторонний контроль — это контроль, которым оператор не воспользуется.
func TestUserBlock_ReachesEveryAccountBecauseThePersonIsOneRow(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	adminA, accA := seedUserAccount(t, ctx, env.pool, "blkonea")
	_, accB := seedUserAccount(t, ctx, env.pool, "blkoneb")

	// Человек, состоящий в ДВУХ аккаунтах: одна строка личности плюс вторая
	// принадлежность. Именно то, чего прежняя модель выразить не умела.
	ext := domain.ExternalSubject("ext-one-row-identity")
	email := domain.Email("onerow@example.com")
	person := seedIdentity(t, ctx, env, accA, ext, email, "ACTIVE")
	addMembership(t, ctx, env, person, accB)

	// Предпосылка фикстуры утверждается, а не подразумевается: проба, чья
	// предпосылка не сложилась, зеленеет на пустом месте.
	require.Equal(t, 1, countIdentityRowsByEmail(ctx, t, env, email),
		"почта человека глобальна — строка у него одна")
	require.Equal(t, 1, countIdentityRowsByExternalID(ctx, t, env, ext),
		"внешний субъект человека глобален — строка у него одна")
	require.Equal(t,
		map[string]string{string(accA): "ACTIVE", string(accB): "ACTIVE"},
		membershipStates(ctx, t, env, person),
		"человек состоит в двух аккаунтах — иначе утверждать про «везде» не о чем")

	gate := kanamepg.NewUserOAuthClientRepo(env.pool)
	lookup := internaliam.NewLookupSubjectUseCase(env.repo)
	block := userapp.NewBlockUserUseCase(env.repo, env.opsRepo)
	unblock := userapp.NewUnblockUserUseCase(env.repo, env.opsRepo)

	// ── Контрольный случай: до запрета обе двери отвечают «да» ────────────────
	_, mayAuth, err := gate.AccountForUser(ctx, person)
	require.NoError(t, err)
	require.True(t, mayAuth, "действующая личность аутентифицируется — контрольный случай")
	resp, err := lookup.Execute(ctx, &iamv1.LookupSubjectRequest{
		Key: &iamv1.LookupSubjectRequest_ExternalId{ExternalId: string(ext)},
	})
	require.NoError(t, err, "и край резолвит её как действующего субъекта")
	require.Equal(t, string(person), resp.GetUser().GetId())

	// ── Запрет ───────────────────────────────────────────────────────────────
	_, err = block.Execute(withPrincipal(adminA), person)
	require.NoError(t, err)
	awaitWorkers(t)
	require.Equal(t, "BLOCKED", userInviteStatus(ctx, t, env, person))

	// Достигает ВЕЗДЕ — и вот почему: второй строки, которая могла бы ответить
	// иначе, не существует. Перепись стоит рядом с исходом намеренно: без неё
	// «человек не аутентифицируется» неотличимо от «мы спросили не про всё».
	require.Equal(t, 1, countIdentityRowsByEmail(ctx, t, env, email),
		"запрет не завёл человеку второй строки, из которой он входил бы дальше")
	_, mayAuth, err = gate.AccountForUser(ctx, person)
	require.NoError(t, err)
	require.False(t, mayAuth, "выдача обязана отказать — это наблюдаемый исход")
	_, err = lookup.Execute(ctx, &iamv1.LookupSubjectRequest{
		Key: &iamv1.LookupSubjectRequest_ExternalId{ExternalId: string(ext)},
	})
	require.Error(t, err, "и край больше не резолвит человека как действующего")
	require.Contains(t, err.Error(), "blocked",
		"причина названа словами: «есть, но нельзя» и «нет такого» — разные ответы, "+
			"и пустое множество край читает как приглашение провизионировать заново")

	// Принадлежности не тронуты — блокировка есть свойство личности.
	require.Equal(t,
		map[string]string{string(accA): "ACTIVE", string(accB): "ACTIVE"},
		membershipStates(ctx, t, env, person),
		"членство заблокированного человека остаётся обычным: иначе запрет молча "+
			"отбирал бы принадлежность, которую выдавал не тот, кто запрещал")

	// ── Снятие ───────────────────────────────────────────────────────────────
	_, err = unblock.Execute(withPrincipal(adminA), person)
	require.NoError(t, err)
	awaitWorkers(t)
	require.Equal(t, "ACTIVE", userInviteStatus(ctx, t, env, person))

	_, mayAuth, err = gate.AccountForUser(ctx, person)
	require.NoError(t, err)
	require.True(t, mayAuth, "участие возможно снова")
	resp, err = lookup.Execute(ctx, &iamv1.LookupSubjectRequest{
		Key: &iamv1.LookupSubjectRequest_ExternalId{ExternalId: string(ext)},
	})
	require.NoError(t, err, "и край снова резолвит человека")
	require.Equal(t, string(person), resp.GetUser().GetId())
	require.Equal(t,
		map[string]string{string(accA): "ACTIVE", string(accB): "ACTIVE"},
		membershipStates(ctx, t, env, person),
		"снятие принадлежностей тоже не трогает — симметрично запрету")
}

// TestUserIdentity_SecondRowForThePersonIsRefusedWithoutLeakingSQL — второй
// строки `users` у одного человека не бывает, отказывает КЛЮЧ БАЗЫ, и его отказ
// доезжает до вызывающего без единого слова из внутренностей базы.
//
// ЧТО ЗДЕСЬ СТОЯЛО РАНЬШЕ. Проба называлась
// «SecondActiveMembershipIsRefusedWithoutLeakingSQL» и добивалась отказа
// СНЯТИЕМ ЗАПРЕТА: у личности были две строки — действующая в аккаунте A и
// запрещённая в B, — и попытка снять запрет со второй нарушала частичный ключ
// `users_active_external_id_uniq` (только среди ACTIVE). Этот путь исчез вместе
// со своей предпосылкой: пара «действующая + запрещённая» теперь отвергается
// ГЛОБАЛЬНЫМ ключом ещё на посеве, то есть раньше, чем дело дойдёт до снятия
// (замер: прежняя проба падала на второй строке фикстуры).
//
// Но у прежней пробы было ДВА предмета, и они независимы. Первый — «сколько
// строк личности бывает действующими» — перешёл к ключу и утверждается здесь
// уже про него. Второй — «отказ, приходящий из базы нарушением уникальности, не
// течёт наружу текстом SQL» — к числу строк отношения не имеет вовсе и обязан
// остаться проверенным. Он и проверяется, на том самом наборе, ради которого
// прежняя проба существовала.
//
// ПОЧЕМУ ЭТО ВАЖНЕЕ, ЧЕМ БЫЛО. Оба новых ключа
// (`users_identity_email_uniq`, `users_identity_external_id_uniq`) записи в
// таблице канонических текстов НЕ имеют, поэтому их сообщение собирает общая
// ветка. Ключ, заведённый без маппинга, обязан молчать о себе САМ — а не
// потому, что кто-то помнил дописать строку в таблицу. Утверждается ПАРА (код и
// сообщение): проверка одного кода зеленела бы ровно на утечке, ради которой
// утверждение написано, а проверка одного текста не заметила бы отказ,
// приехавший под чужим кодом.
func TestUserIdentity_SecondRowForThePersonIsRefusedWithoutLeakingSQL(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	_, accA := seedUserAccount(t, ctx, env.pool, "iddupa")
	_, accB := seedUserAccount(t, ctx, env.pool, "iddupb")

	// ── Ось 1: почта ─────────────────────────────────────────────────────────
	// Второй аккаунт взят намеренно: пер-аккаунтный ключ 0001 остаётся лежать
	// рядом (миграция — экспанд, старых ключей она не снимает), и в ОДНОМ
	// аккаунте отвергал бы он. Разные аккаунты оставляют ровно один
	// применимый ключ — глобальный, тот самый, чьё поведение проверяется.
	sharedEmail := domain.Email("secondrow@example.com")
	first := seedIdentity(t, ctx, env, accA, "ext-second-row-email", sharedEmail, "ACTIVE")

	err := insertActiveIdentityRow(ctx, t, env, domain.User{
		ID:          domain.UserID(ids.NewID(domain.PrefixUser)),
		AccountID:   accB,
		ExternalID:  "ext-second-row-email-other",
		Email:       sharedEmail,
		DisplayName: "Second Row By Email",
	})
	requireRefusedWithoutLeakingSQL(t, err)
	require.Equal(t, 1, countIdentityRowsByEmail(ctx, t, env, sharedEmail),
		"отказ, у которого остался эффект, — не отказ")
	require.Equal(t, "ACTIVE", userInviteStatus(ctx, t, env, first),
		"и первая строка осталась такой, какой была")

	// ── Ось 2: внешний субъект, в НАБОРЕ, который прежде был законным ─────────
	// Прежний ключ 0011 накрывал только действующие строки, поэтому «действующая
	// + запрещённая» одной личности сходились и жили рядом — на этом наборе и
	// стояла прежняя проба. Глобальный ключ состояния не смотрит, значит набор
	// отвергается целиком, и отвергает его именно он: 0011 здесь молчит, у него
	// в поле зрения одна действующая строка.
	sharedExt := domain.ExternalSubject("ext-second-row-subject")
	blocked := seedIdentity(t, ctx, env, accA, sharedExt, "blockedrow@example.com", "BLOCKED")

	err = insertActiveIdentityRow(ctx, t, env, domain.User{
		ID:          domain.UserID(ids.NewID(domain.PrefixUser)),
		AccountID:   accB,
		ExternalID:  sharedExt,
		Email:       "activerow@example.com",
		DisplayName: "Second Row By Subject",
	})
	requireRefusedWithoutLeakingSQL(t, err)
	require.Equal(t, 1, countIdentityRowsByExternalID(ctx, t, env, sharedExt),
		"второй строки не появилось")
	require.Equal(t, "BLOCKED", userInviteStatus(ctx, t, env, blocked),
		"запрещённая строка осталась запрещённой: отвергнутая вставка эффекта не оставила")

	// ── Положительный контроль ───────────────────────────────────────────────
	// Без него оба отрицания выше зеленели бы на схеме, отвергающей ВСЁ, и
	// «ключ отвергает второго» было бы неотличимо от «писатель сломан».
	newcomerEmail := domain.Email("genuinely-different@example.com")
	newcomerExt := domain.ExternalSubject("ext-genuinely-different")
	require.NoError(t, insertActiveIdentityRow(ctx, t, env, domain.User{
		ID:          domain.UserID(ids.NewID(domain.PrefixUser)),
		AccountID:   accB,
		ExternalID:  newcomerExt,
		Email:       newcomerEmail,
		DisplayName: "Genuinely Different Person",
	}), "настоящий другой человек заводится тем же писателем — иначе отрицания выше пусты")
	require.Equal(t, 1, countIdentityRowsByEmail(ctx, t, env, newcomerEmail),
		"и он в базе ровно один")
}

// TestUserBlock_PendingInvitationIsRefused — приглашение, которое ещё никто не
// подтвердил, не блокируется, и отказ не оставляет ни следа, ни эффекта.
func TestUserBlock_PendingInvitationIsRefused(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	admin, accID := seedUserAccount(t, ctx, env.pool, "blkpend")

	pending := domain.UserID(ids.NewID(domain.PrefixUser))
	_, err := env.pool.Exec(ctx, `
		INSERT INTO kaname.users (id, account_id, external_id, email, display_name, invite_status)
		VALUES ($1, $2, '', $3, $4, 'PENDING')`,
		string(pending), string(accID), "pending-blk@example.com", "Pending")
	require.NoError(t, err)

	_, err = userapp.NewBlockUserUseCase(env.repo, env.opsRepo).
		Execute(withPrincipal(admin), pending)
	require.Error(t, err)
	require.Contains(t, err.Error(), fmt.Sprintf("User %s is not active", pending))

	require.Equal(t, "PENDING", userInviteStatus(ctx, t, env, pending),
		"отказ, у которого остался эффект, — не отказ")
	require.Zero(t, countAuditByResource(ctx, t, env.pool, string(pending)),
		"отвергнутый вызов события не оставляет")
}

// seedIdentity вставляет СТРОКУ ЛИЧНОСТИ — ту единственную, что теперь бывает у
// человека, — с принадлежностью аккаунту, названному колонкой `account_id`.
//
// Прежде на этом месте стоял `seedMembership`, заводивший по строке `users` на
// КАЖДЫЙ аккаунт: пока ключ уникальности включал аккаунт, «тот же человек в
// другом аккаунте» был другой строкой с другим идентификатором. С глобальным
// ключом (20260823050000) такой посев отвергается базой, и хелпер разделён на
// два — личность и её принадлежности, — потому что это теперь разные сущности,
// а не две проекции одной.
//
// Состояние — параметр: набор строк личности им больше не ограничивается (её
// строка одна в любом состоянии), но пробам ниже нужны и действующая, и
// запрещённая как ИСХОДНОЕ условие.
func seedIdentity(t *testing.T, ctx context.Context, env *testEnv,
	accID domain.AccountID, ext domain.ExternalSubject, email domain.Email, status string) domain.UserID {
	t.Helper()
	uid := domain.UserID(ids.NewID(domain.PrefixUser))
	_, err := env.pool.Exec(ctx, `
		INSERT INTO kaname.users (id, account_id, external_id, email, display_name, invite_status)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		string(uid), string(accID), string(ext), string(email), "Identity", status)
	require.NoError(t, err, "seed %s identity in %s", status, accID)
	return uid
}

// addMembership заводит человеку принадлежность ЕЩЁ ОДНОМУ аккаунту — то, чем
// после отрыва принадлежности от строки выражается «человек состоит в двух
// аккаунтах».
//
// Идентификатор берётся у той же функции, какой пользуется зеркалящий триггер
// (`membership_mirror_id`), а не выдумывается. Две причины, и обе несущие: форма
// идентификатора закреплена CHECK'ом (`mbr-` + 17 знаков крокфорда), а строка
// посева обязана совпадать с той, какую завёл бы прод, — иначе фикстура
// утверждала бы про набор, которого продовый путь не производит.
func addMembership(t *testing.T, ctx context.Context, env *testEnv,
	uid domain.UserID, accID domain.AccountID) {
	t.Helper()
	_, err := env.pool.Exec(ctx, `
		INSERT INTO kaname.memberships (id, user_id, account_id, state)
		VALUES (kaname.membership_mirror_id($1, $2), $1, $2, 'ACTIVE')`,
		string(uid), string(accID))
	require.NoError(t, err, "add membership of %s in %s", uid, accID)
}

// membershipStates читает принадлежности человека как отображение
// «аккаунт → состояние».
//
// Отображение, а не список: предмет утверждения — НАБОР, а порядок строк ответом
// базы не закреплён, и сверка по индексу закрепляла бы случайность вместо
// свойства (api-conventions.md §«Порядок повторяющегося поля»).
func membershipStates(ctx context.Context, t *testing.T, env *testEnv, uid domain.UserID) map[string]string {
	t.Helper()
	rows, err := env.pool.Query(ctx,
		`SELECT account_id, state FROM kaname.memberships WHERE user_id = $1`, string(uid))
	require.NoError(t, err)
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var acc, state string
		require.NoError(t, rows.Scan(&acc, &state))
		out[acc] = state
	}
	require.NoError(t, rows.Err())
	return out
}

// countIdentityRowsByEmail — сколько строк `users` отвечают одной почте.
//
// Единица счёта названа явно, потому что ровно она и есть предмет перехода: было
// «по строке на аккаунт», стало «одна на человека». Сравнение идёт тем же
// `lower()`, каким его делает ключ: считать чувствительно к регистру значило бы
// мерить не то, что держит база.
func countIdentityRowsByEmail(ctx context.Context, t *testing.T, env *testEnv, email domain.Email) int {
	t.Helper()
	var n int
	require.NoError(t, env.pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.users WHERE lower(email) = lower($1)`,
		string(email)).Scan(&n))
	return n
}

// countIdentityRowsByExternalID — то же по внешнему субъекту. Пустой внешний
// субъект (неподтверждённое приглашение) ключом не накрыт, поэтому и здесь он
// исключён: считать надо ровно то множество, которое ключ и стережёт.
func countIdentityRowsByExternalID(ctx context.Context, t *testing.T, env *testEnv, ext domain.ExternalSubject) int {
	t.Helper()
	var n int
	require.NoError(t, env.pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.users WHERE external_id = $1 AND external_id <> ''`,
		string(ext)).Scan(&n))
	return n
}

// insertActiveIdentityRow пытается завести ДЕЙСТВУЮЩУЮ строку личности настоящим
// писателем (`UsersW().InsertActive`) и возвращает то, что увидел бы вызывающий:
// ошибку, пропущенную через тот же `shared.MapRepoErr`, каким её пропускают
// use-case'ы.
//
// Сырую ошибку репозитория утверждать нельзя — она не то, что доезжает до
// клиента, а проба про утечку обязана смотреть на провод. Успех коммитится,
// отказ откатывается: положительный контроль обязан оставить строку, иначе он
// не отличает «писатель работает» от «писатель молча ничего не сделал».
func insertActiveIdentityRow(ctx context.Context, t *testing.T, env *testEnv, u domain.User) error {
	t.Helper()
	w, err := env.repo.Writer(ctx)
	require.NoError(t, err)
	if _, ierr := w.UsersW().InsertActive(ctx, u); ierr != nil {
		_ = w.Rollback(ctx)
		return shared.MapRepoErr(ierr)
	}
	require.NoError(t, w.Commit(ctx))
	return nil
}

// requireRefusedWithoutLeakingSQL — отказ пришёл, он назван кодом контракта, и в
// его тексте нет ничего из внутренностей базы.
//
// Имена ключей перечислены ПОИМЁННО, включая два новых глобальных: у них нет
// записи в таблице канонических текстов, поэтому сообщение им собирает общая
// ветка — и это ровно тот случай, ради которого утверждение стоит здесь. Ключ,
// заведённый без маппинга, обязан молчать о себе сам.
func requireRefusedWithoutLeakingSQL(t *testing.T, err error) {
	t.Helper()
	require.Error(t, err,
		"второй строки одной личности не бывает — глобальный ключ обязан отвергнуть")
	st, ok := status.FromError(err)
	require.True(t, ok, "отказ доезжает до вызывающего статусом контракта")
	require.Equal(t, codes.AlreadyExists, st.Code(),
		"конфликт уникальности — это ALREADY_EXISTS, а не INTERNAL и не FAILED_PRECONDITION")

	msg := st.Message()
	for _, leak := range []string{
		"users_identity_email_uniq",
		"users_identity_external_id_uniq",
		"users_account_email_unique",
		"users_active_external_id_uniq",
		"SQLSTATE",
		"23505",
		"duplicate key",
		"kaname",
		"pgx",
	} {
		require.NotContains(t, msg, leak,
			"внутренность базы в тексте отказа: %s (это разведка схемы для вызывающего)", leak)
	}
	require.Contains(t, msg, "already exists",
		"вызывающий получает внятную причину, а не внутреннюю ошибку")
}
