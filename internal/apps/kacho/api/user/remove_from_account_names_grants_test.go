// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// remove_from_account_names_grants_test.go — отказ исключения ОБЯЗАН НАЗВАТЬ
// выдачи, которые мешают (задача продукта #1686).
//
// # Предмет — обещание контракта, у которого не было производителя
//
// `user_service.proto` (RemoveFromAccount) обещает дословно: «the refusal is
// FAILED_PRECONDITION with the grants named, never a silent orphaning of a right
// whose bearer is gone». Первая половина — «отвергнуть, а не осиротить» — держится
// КОНСТРУКЦИЕЙ (отложенный триггер `membership_carrying_rights_is_kept`,
// миграция 472002) и верна. Вторая — «с перечисленными выдачами» — не имела
// исполнителя: текст называл человека и аккаунт, выдач — ни одной.
//
// Отказ существует затем, чтобы клиент построил СЛЕДУЮЩИЙ ШАГ, а по имени
// человека и аккаунта его не построить: чтобы исключить, надо отозвать
// мешающие выдачи, а какие именно — отказ не говорил.
//
// # Почему проба стоит ЗДЕСЬ, а не у отображения ошибок
//
// Триггер отложенный: он срабатывает на КОММИТЕ, и к этому моменту транзакция
// мертва — спросить у неё, какие выдачи помешали, нельзя ни одним запросом.
// Значит перечень добывается ОТДЕЛЬНЫМ чтением, а место, где есть и репозиторий,
// и уже полученный отказ, — use-case. Проба у отображения ошибок (`pgmaperr`)
// этого утверждать не может: там нет соединения.
//
// # Граница названа с обеих сторон, и это несущая половина
//
// Названы ровно те выдачи, которые ДЕРЖАТ членство, — по предикату самого
// триггера: живые, адресующие этого человека, в области этого аккаунта либо его
// проекта. Выдача того же человека в ЧУЖОМ аккаунте не называется: иначе отказ
// стал бы рассказывать распорядителю одного аккаунта про другой, то есть выдавал
// бы наружу больше, чем предмет отказа.

package user

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	kachopg "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg"
	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/ids"
	"github.com/PRO-Robotech/kacho/pkg/pgtest"
)

// dsnWithSchema — DSN этой пробы с путём поиска сервиса. Репозиторий пишет
// неквалифицированными именами, поэтому без него первый же INSERT отвечает
// «нет такой таблицы», и проба падала бы на ФИКСТУРЕ, а не на предмете.
func dsnWithSchema(t *testing.T) string {
	t.Helper()
	return pgtest.NewDB(t)
}

// seedUserWithAccount заводит человека и его аккаунт; членство ставит зеркало S1.
func seedUserWithAccount(t *testing.T, ctx context.Context, repo Repo, suffix string) (domain.UserID, domain.AccountID) {
	t.Helper()
	uid := domain.UserID(ids.NewID(domain.PrefixUser))
	accID := domain.AccountID(ids.NewID(domain.PrefixAccount))

	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	committed := false
	defer func() {
		if !committed {
			_ = w.Rollback(ctx)
		}
	}()

	_, err = w.UsersW().InsertActive(ctx, domain.User{
		ID:           uid,
		AccountID:    accID,
		ExternalID:   domain.ExternalSubject("ext-" + suffix + "-" + string(uid)),
		Email:        domain.Email(fmt.Sprintf("u-%s-%s@example.com", strings.ToLower(suffix), strings.ToLower(string(uid[4:10])))),
		DisplayName:  domain.DisplayName("User " + suffix),
		InviteStatus: domain.InviteStatusActive,
	})
	require.NoError(t, err)
	_, err = w.AccountsW().Insert(ctx, domain.Account{
		ID:          accID,
		Name:        domain.AccountName(fmt.Sprintf("acc-%s-%s", strings.ToLower(suffix), strings.ToLower(string(accID[4:10])))),
		OwnerUserID: uid,
		Labels:      domain.Labels{},
	})
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))
	committed = true
	return uid, accID
}

// grantOnAccount кладёт ЖИВУЮ выдачу человеку в области названного аккаунта.
// Сырым SQL намеренно: предмет пробы — текст отказа, а не путь выдачи прав.
func grantOnAccount(t *testing.T, ctx context.Context, pool *pgxpool.Pool,
	userID domain.UserID, accID domain.AccountID, roleID string,
) string {
	t.Helper()
	bindingID := ids.NewID("acb")
	_, err := pool.Exec(ctx, `
		INSERT INTO kacho_iam.access_bindings
		    (id, subject_type, subject_id, role_id, resource_type, resource_id, status)
		VALUES ($1, 'user', $2, $3, 'account', $4, 'ACTIVE')`,
		bindingID, string(userID), roleID, string(accID))
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `
		INSERT INTO kacho_iam.access_binding_subjects (binding_id, subject_type, subject_id, ordinal)
		VALUES ($1, 'user', $2, 0)`, bindingID, string(userID))
	require.NoError(t, err)
	return bindingID
}

func someRoleID(t *testing.T, ctx context.Context, pool *pgxpool.Pool) string {
	t.Helper()
	var id string
	require.NoError(t, pool.QueryRow(ctx, `SELECT id FROM kacho_iam.roles LIMIT 1`).Scan(&id))
	require.NotEmpty(t, id, "ПРЕДПОСЫЛКА: в дереве обязана быть хоть одна роль")
	return id
}

// errorInfoOf достаёт машинный признак полосы из деталей отказа.
func errorInfoOf(t *testing.T, err error) *errdetails.ErrorInfo {
	t.Helper()
	st, ok := status.FromError(err)
	require.True(t, ok, "отказ обязан быть gRPC-статусом")
	for _, d := range st.Details() {
		if ei, ok := d.(*errdetails.ErrorInfo); ok {
			return ei
		}
	}
	return nil
}

// TestRemoveFromAccount_RefusalNamesTheGrantsThatHold — #1686.
//
// Утверждает ПАРУ: код и текст. Кода одного мало — FAILED_PRECONDITION приходит и
// на отказе, который выдач не называет, то есть ровно на дефекте.
func TestRemoveFromAccount_RefusalNamesTheGrantsThatHold(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, dsnWithSchema(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	repo := kachopg.New(pool, nil)

	uid, accID := seedUserWithAccount(t, ctx, repo, "hold")
	role := someRoleID(t, ctx, pool)
	blocking := grantOnAccount(t, ctx, pool, uid, accID, role)

	// Выдача того же человека в ЧУЖОМ аккаунте — она членство НЕ держит и в
	// отказе называться не должна (граница анти-оракула).
	_, foreignAcc := seedUserWithAccount(t, ctx, repo, "othr")
	foreign := grantOnAccount(t, ctx, pool, uid, foreignAcc, role)

	uc := NewRemoveFromAccountUseCase(repo, nil)
	_, err = uc.doRemove(ctx, uid, accID, "usr-actor")

	require.Error(t, err, "членство, несущее живую выдачу, снять нельзя")
	st, ok := status.FromError(err)
	require.True(t, ok)
	require.Equal(t, codes.FailedPrecondition, st.Code(),
		"контракт называет полосу отказа именно так")

	// ── НЕСУЩЕЕ: выдача, которая мешает, НАЗВАНА ─────────────────────────────
	require.Contains(t, st.Message(), blocking,
		"контракт обещает отказ «with the grants named»: без идентификатора выдачи "+
			"клиент не может построить следующий шаг — отозвать её")

	// ── тон контракта цел: признак полосы наружу НЕ уезжает ─────────────────
	// Признак — служебный префикс цепочки, снимаемый `StripSentinel`. Утечь он
	// может молча: сообщение с ним по-прежнему содержит и человека, и выдачу,
	// поэтому утверждения выше остались бы зелёными.
	require.True(t, strings.HasPrefix(st.Message(), "User "+string(uid)+" still has active access bindings"),
		"тон отказа — часть контракта и обязан начинаться с прежней фразы; "+
			"перечень ДОПОЛНЯЕТ её, а не заменяет. Получено: %q", st.Message())
	require.NotContains(t, st.Message(), "failed precondition",
		"служебный признак цепочки на провод не уезжает")

	// ── граница: чужая выдача НЕ названа ────────────────────────────────────
	require.NotContains(t, st.Message(), foreign,
		"названы только выдачи, ДЕРЖАЩИЕ это членство; выдача в другом аккаунте "+
			"его не держит, и отказ не вправе о ней рассказывать")

	// ── машинный признак: клиент ключуется на него, а не на прозу ───────────
	ei := errorInfoOf(t, err)
	require.NotNil(t, ei, "отказ обязан нести машинный признак полосы")
	require.Equal(t, "MEMBERSHIP_CARRIES_RIGHTS", ei.GetReason())
	require.Equal(t, blocking, ei.GetMetadata()["blocking_binding_ids"],
		"перечень уезжает и машинно — разбирать прозу клиент не обязан")
	require.Equal(t, "1", ei.GetMetadata()["blocking_binding_count"])
}

// TestRemoveFromAccount_SucceedsOnceTheGrantIsGone — ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ.
//
// Без него утверждение выше зеленело бы на реализации, отвергающей ЛЮБОЕ
// исключение: «отказ называет выдачи» ничего не стоит, если отказ приходит всегда.
func TestRemoveFromAccount_SucceedsOnceTheGrantIsGone(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, dsnWithSchema(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	repo := kachopg.New(pool, nil)

	uid, accID := seedUserWithAccount(t, ctx, repo, "free")
	role := someRoleID(t, ctx, pool)
	blocking := grantOnAccount(t, ctx, pool, uid, accID, role)

	_, err = pool.Exec(ctx, `DELETE FROM kacho_iam.access_bindings WHERE id = $1`, blocking)
	require.NoError(t, err)

	uc := NewRemoveFromAccountUseCase(repo, nil)
	_, err = uc.doRemove(ctx, uid, accID, "usr-actor")
	require.NoError(t, err, "выдач нет — исключение обязано проходить")
}

// TestRemoveFromAccount_RefusalNamesGrantsScopedOnAccountProjects — предикат
// чтения ПОВТОРЯЕТ триггер, и это единственная ось, где копия может разойтись
// молча.
//
// Триггер держит членство и выдачей, лежащей на ПРОЕКТЕ этого аккаунта, — не
// только на самом аккаунте. Разойдись чтение с ним по этой оси, и отказ пришёл
// бы с ПУСТЫМ перечнем: «исключить нельзя, а что мешает — не скажу». Со стороны
// это неотличимо от исправной работы, потому что код и первая половина текста
// остаются прежними.
func TestRemoveFromAccount_RefusalNamesGrantsScopedOnAccountProjects(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, dsnWithSchema(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	repo := kachopg.New(pool, nil)

	uid, accID := seedUserWithAccount(t, ctx, repo, "proj")
	role := someRoleID(t, ctx, pool)

	projID := ids.NewID(domain.PrefixProject)
	_, err = pool.Exec(ctx, `
		INSERT INTO kacho_iam.projects (id, account_id, name, description, labels, created_at)
		VALUES ($1, $2, $3, '', '{}'::jsonb, now())`,
		projID, string(accID), "p-"+strings.ToLower(projID[4:12]))
	require.NoError(t, err)

	bindingID := ids.NewID("acb")
	_, err = pool.Exec(ctx, `
		INSERT INTO kacho_iam.access_bindings
		    (id, subject_type, subject_id, role_id, resource_type, resource_id, status)
		VALUES ($1, 'user', $2, $3, 'project', $4, 'ACTIVE')`,
		bindingID, string(uid), role, projID)
	require.NoError(t, err)

	uc := NewRemoveFromAccountUseCase(repo, nil)
	_, err = uc.doRemove(ctx, uid, accID, "usr-actor")

	require.Error(t, err, "выдача на проекте аккаунта держит членство так же, как выдача на самом аккаунте")
	st, ok := status.FromError(err)
	require.True(t, ok)
	require.Equal(t, codes.FailedPrecondition, st.Code())
	require.Contains(t, st.Message(), bindingID,
		"перечень читается ТЕМ ЖЕ предикатом, что и триггер: разойдясь по этой оси, "+
			"отказ пришёл бы с пустым перечнем и выглядел бы исправным")
}
