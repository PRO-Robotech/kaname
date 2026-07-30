// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

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
// требует расходуемого действующего членства ВНУТРИ аккаунта, которым мы
// администрируем, а фикстура края такого не сеет: каждому принципалу
// провизионируется его собственный домашний аккаунт, и заблокировать принципала
// фикстуры значит отравить её на весь прогон. Поэтому наблюдаемый исход
// закрепляется здесь, на настоящей базе и настоящих читателях, а через край
// закреплены негативы и сам маршрут.
//
// Run: `go test ./internal/apps/kacho/api/audit/... -run UserBlock`. Пропускается с -short.

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/ids"

	internaliam "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/internal_iam"
	userapp "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/user"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
)

// userInviteStatus читает состояние строки членства напрямую из базы.
func userInviteStatus(ctx context.Context, t *testing.T, env *testEnv, uid domain.UserID) string {
	t.Helper()
	var st string
	require.NoError(t, env.pool.QueryRow(ctx,
		`SELECT invite_status FROM kacho_iam.users WHERE id = $1`, string(uid)).Scan(&st))
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

	// Расходуемое действующее членство в ТОМ ЖЕ аккаунте — предмет запрета.
	target := seedExtraUser(t, ctx, env.pool, accID, "blktarget")
	targetExt := fmt.Sprintf("extra-blktarget-%s", target)

	gate := kachopg.NewUserOAuthClientRepo(env.pool)
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

// TestUserBlock_IsRowScopedAndRespectsTheOneActiveIdentityInvariant — запрет
// принадлежит СТРОКЕ членства, и схема ограничивает, сколько их может быть
// действующими.
//
// ЧТО ЗДЕСЬ ВЫЯСНИЛОСЬ И ЧЕГО Я НЕ ЗНАЛ, КОГДА ПИСАЛ ПРИЁМКУ. Миграция 0011
// держит глобальный частичный UNIQUE по внешней личности среди ДЕЙСТВУЮЩИХ
// строк: «one ACTIVE identity-row per Kratos sub, globally». Значит набор строк
// одной личности — это ровно одно действующее членство плюс сколько угодно
// запрещённых (неподтверждённые приглашения внешней личности не несут вовсе и в
// набор не попадают). Сценарий «действующая в A и действующая в B» база
// запрещает, и первая же попытка его засеять получила 23505 — то есть приёмка
// требовала проверить состояние, которого не существует.
//
// Отсюда два следствия, и оба проверяются ниже:
//
//  1. запретить действующее членство — значит лишить личность единственной
//     действующей строки, поэтому аутентифицироваться она перестаёт везде. Это
//     НЕ «identity-wide запрет»: запись коснулась одной строки, а платформенный
//     эффект вытекает из инварианта схемы, а не из области действия;
//  2. снятие тоже row-scoped: вернув одно членство, оно НЕ трогает остальные
//     запрещённые строки той же личности — иначе снятие в одном аккаунте тихо
//     возвращало бы доступ в другой, которого администратор того аккаунта не
//     разрешал.
func TestUserBlock_IsRowScopedAndRespectsTheOneActiveIdentityInvariant(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	adminA, accA := seedUserAccount(t, ctx, env.pool, "blkrowa")
	_, accB := seedUserAccount(t, ctx, env.pool, "blkrowb")

	// Конструктивный набор одной личности: действующее членство в A и запрещённое
	// в B. Двух действующих схема не допускает — см. преамбулу.
	ext := domain.ExternalSubject("ext-row-scoped-identity")
	email := domain.Email("rowscoped@example.com")
	inA := seedMembership(t, ctx, env, accA, ext, email, "ACTIVE")
	inB := seedMembership(t, ctx, env, accB, ext, email, "BLOCKED")

	lookup := internaliam.NewLookupSubjectUseCase(env.repo)
	block := userapp.NewBlockUserUseCase(env.repo, env.opsRepo)
	unblock := userapp.NewUnblockUserUseCase(env.repo, env.opsRepo)

	// ── Снятие не трогает чужие строки ────────────────────────────────────────
	// Запрещаем единственное действующее членство, затем возвращаем его. Строка в
	// B обязана остаться запрещённой на КАЖДОМ шаге: администратор аккаунта A не
	// вправе вернуть доступ в аккаунт B.
	_, err := block.Execute(withPrincipal(adminA), inA)
	require.NoError(t, err)
	awaitWorkers(t)
	require.Equal(t, "BLOCKED", userInviteStatus(ctx, t, env, inA))
	require.Equal(t, "BLOCKED", userInviteStatus(ctx, t, env, inB))

	// Действующих строк не осталось — личность не аутентифицируется. Это
	// следствие инварианта схемы, а не области действия запрета.
	_, err = lookup.Execute(ctx, &iamv1.LookupSubjectRequest{
		Key: &iamv1.LookupSubjectRequest_ExternalId{ExternalId: string(ext)},
	})
	require.Error(t, err, "у личности не осталось действующего членства")
	require.Contains(t, err.Error(), "blocked")

	_, err = unblock.Execute(withPrincipal(adminA), inA)
	require.NoError(t, err)
	awaitWorkers(t)
	require.Equal(t, "ACTIVE", userInviteStatus(ctx, t, env, inA))
	require.Equal(t, "BLOCKED", userInviteStatus(ctx, t, env, inB),
		"снятие в одном аккаунте НЕ возвращает доступ в другой: иначе администратор A "+
			"тихо отменял бы решение администратора B")

	resp, err := lookup.Execute(ctx, &iamv1.LookupSubjectRequest{
		Key: &iamv1.LookupSubjectRequest_ExternalId{ExternalId: string(ext)},
	})
	require.NoError(t, err, "вернувшееся членство снова аутентифицируется")
	require.Equal(t, string(inA), resp.GetUser().GetId())
}

// TestUserUnblock_SecondActiveMembershipIsRefusedWithoutLeakingSQL — снять
// запрет со второй строки, когда у личности уже есть действующая, нельзя: это
// нарушило бы глобальный инвариант «одна действующая строка на личность».
//
// Проверяется не только КОД, но и ТЕКСТ: конфликт приходит из базы как нарушение
// уникальности, и путь без маппинга отдал бы наружу имя констрейнта и обрывок
// SQL. Утверждение на сообщении — единственное, что ловит регрессию этого класса
// (проверка одного кода зеленела бы и на утечке).
func TestUserUnblock_SecondActiveMembershipIsRefusedWithoutLeakingSQL(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	adminA, accA := seedUserAccount(t, ctx, env.pool, "blkdupa")
	_, accB := seedUserAccount(t, ctx, env.pool, "blkdupb")

	ext := domain.ExternalSubject("ext-second-active")
	email := domain.Email("secondactive@example.com")
	_ = seedMembership(t, ctx, env, accA, ext, email, "ACTIVE")
	inB := seedMembership(t, ctx, env, accB, ext, email, "BLOCKED")

	op, err := userapp.NewUnblockUserUseCase(env.repo, env.opsRepo).
		Execute(withPrincipal(adminA), inB)
	require.NoError(t, err, "отказ приходит из writer-tx, поэтому Operation порождается")
	awaitWorkers(t)

	done, err := env.opsRepo.Get(ctx, op.ID)
	require.NoError(t, err)
	require.True(t, done.Done)
	require.NotNil(t, done.Error,
		"снятие обязано провалиться: инвариант «одна действующая строка на личность» "+
			"держится на уровне базы")

	msg := done.Error.GetMessage()
	require.NotContains(t, msg, "users_active_external_id_uniq",
		"имя констрейнта наружу не уходит")
	require.NotContains(t, msg, "SQLSTATE")
	require.NotContains(t, msg, "duplicate key")
	require.Contains(t, msg, "already exists",
		"вызывающий получает внятную причину, а не внутреннюю ошибку")

	require.Equal(t, "BLOCKED", userInviteStatus(ctx, t, env, inB),
		"провалившееся снятие эффекта не оставило")
}

// TestUserBlock_PendingInvitationIsRefused — приглашение, которое ещё никто не
// подтвердил, не блокируется, и отказ не оставляет ни следа, ни эффекта.
func TestUserBlock_PendingInvitationIsRefused(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	admin, accID := seedUserAccount(t, ctx, env.pool, "blkpend")

	pending := domain.UserID(ids.NewID(domain.PrefixUser))
	_, err := env.pool.Exec(ctx, `
		INSERT INTO kacho_iam.users (id, account_id, external_id, email, display_name, invite_status)
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

// seedMembership вставляет строку членства для заданной личности в заданном
// аккаунте. Отдельный хелпер, потому что предмет этих проб — именно НЕСКОЛЬКО
// членств одной личности, а существующие сиды дают по одному.
// seedMembership вставляет строку членства заданной личности в заданном аккаунте
// с заданным состоянием. Состояние — параметр, потому что предмет этих проб
// именно НАБОР строк одной личности, а он по схеме может содержать лишь одну
// действующую (миграция 0011).
func seedMembership(t *testing.T, ctx context.Context, env *testEnv,
	accID domain.AccountID, ext domain.ExternalSubject, email domain.Email, status string) domain.UserID {
	t.Helper()
	uid := domain.UserID(ids.NewID(domain.PrefixUser))
	_, err := env.pool.Exec(ctx, `
		INSERT INTO kacho_iam.users (id, account_id, external_id, email, display_name, invite_status)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		string(uid), string(accID), string(ext), string(email), "Membership", status)
	require.NoError(t, err, "seed %s membership in %s", status, accID)
	return uid
}
