// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package user

// invite_email_out_of_log_test.go — почта приглашаемого не пишется в поток
// журнала на пути ПРИГЛАШЕНИЯ (задача #2482).
//
// # Почему отдельной пробой, а не расширением соседней
//
// `invite_activation_observability_test.go` объявляет заголовком и текстом
// падения, что почта не попадает в журнал «ни на одном из путей», а телом
// исполняет ОДИН — активацию (`doUpsert`). Это заявление шире сделанного: путь
// приглашения (`InviteUserUseCase.Execute`) им не осмотрен вовсе, и почта
// писалась именно там. Пути ведут разные use-case'ы с разными дублёрами, и
// свести их в одну пробу значило бы либо подменить предмет, либо завести
// фикстуру, снисходительную к обоим.
//
// # Какая ветвь исполняется
//
// Запись делает `resolveCanonicalSubjectID`, и только когда канонической
// оказывается ЧУЖАЯ строка: приглашаемый уже ACTIVE в другом аккаунте, поэтому
// выдача проекта привязывается к той строке, а не к свежей. Дублёр чтения
// отдаёт ровно это; без такого исхода ветвь не исполняется и проба зеленела бы
// на ненажатой кнопке.
//
// # Что утверждается
//
// ОТСУТСТВИЕ подстроки в буфере журнала, а не факт вызова логгера
// (`testing.md` §Regression-lock: PII-фикс локается на уровне наблюдаемого).
// Рядом — положительный контроль: оба не-личных коррелятора обязаны остаться,
// иначе «почты нет» зеленело бы и на правке, снявшей запись целиком, — а она
// объясняет, почему выдача ушла на другую строку, и без неё разбор невозможен.

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/operations"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamerepo "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
	repoproject "github.com/PRO-Robotech/kaname/internal/repo/kaname/project"
	reporole "github.com/PRO-Robotech/kaname/internal/repo/kaname/role"
	repouser "github.com/PRO-Robotech/kaname/internal/repo/kaname/user"
	"github.com/PRO-Robotech/kaname/internal/testsupport/logbuf"
)

const (
	inviteLogEmail       = "invitee-canonical@example.test"
	inviteLogProject     = "prj0000000000000log1"
	inviteLogRole        = "rol0000000000000log1"
	inviteLogCanonicalID = "usr0000000000canon01"
)

// ── дублёр: канонической оказывается ЧУЖАЯ строка ───────────────────────────
//
// Одно-фактность относительно `invPrincRepo`: отличается исходом
// `FindActiveByEmail` и наличием каталога проекта/роли, без которого
// project-scoped приглашение до записи не доходит.

type inviteLogRepo struct {
	*invPrincRepo
	rowMu           sync.Mutex
	perAccountRowID domain.UserID
}

func (f *inviteLogRepo) rememberRow(id domain.UserID) {
	f.rowMu.Lock()
	defer f.rowMu.Unlock()
	f.perAccountRowID = id
}

func (f *inviteLogRepo) row() domain.UserID {
	f.rowMu.Lock()
	defer f.rowMu.Unlock()
	return f.perAccountRowID
}

func (f *inviteLogRepo) Reader(ctx context.Context) (kanamerepo.Reader, error) {
	inner, err := f.invPrincRepo.Reader(ctx)
	if err != nil {
		return nil, err
	}
	return inviteLogReader{Reader: inner}, nil
}

func (f *inviteLogRepo) Writer(ctx context.Context) (kanamerepo.Writer, error) {
	inner, err := f.invPrincRepo.Writer(ctx)
	if err != nil {
		return nil, err
	}
	return inviteLogWriter{Writer: inner, parent: f}, nil
}

type inviteLogReader struct{ kanamerepo.Reader }

func (r inviteLogReader) Users() repouser.ReaderIface       { return inviteLogUserRdr{} }
func (r inviteLogReader) Projects() repoproject.ReaderIface { return inviteLogProjectRdr{} }
func (r inviteLogReader) Roles() reporole.ReaderIface       { return inviteLogRoleRdr{} }

type inviteLogWriter struct {
	kanamerepo.Writer
	parent *inviteLogRepo
}

func (w inviteLogWriter) Users() repouser.ReaderIface       { return inviteLogUserRdr{} }
func (w inviteLogWriter) Projects() repoproject.ReaderIface { return inviteLogProjectRdr{} }
func (w inviteLogWriter) Roles() reporole.ReaderIface       { return inviteLogRoleRdr{} }
func (w inviteLogWriter) AccessBindingsW() access_binding.WriterIface {
	return inviteLogABWtr{}
}

// UsersW — запоминает идентификатор СВЕЖЕЙ строки аккаунта: положительный
// контроль ниже требует его дословно, а выдумывать значение нельзя — тогда
// проба утверждала бы про свою константу, а не про запись.
func (w inviteLogWriter) UsersW() repouser.WriterIface {
	return inviteLogUserWtr{WriterIface: w.Writer.UsersW(), parent: w.parent}
}

type inviteLogUserWtr struct {
	repouser.WriterIface
	parent *inviteLogRepo
}

func (w inviteLogUserWtr) InsertPending(ctx context.Context, u domain.User, _ time.Time) (domain.User, bool, error) {
	w.parent.rememberRow(u.ID)
	return w.WriterIface.InsertPending(ctx, u, time.Time{})
}

type inviteLogUserRdr struct{ invPrincUserRdr }

// FindActiveByEmail — приглашаемый уже ACTIVE в ЧУЖОМ аккаунте: именно этот
// исход уводит выдачу на каноническую строку и включает запись в журнал.
func (inviteLogUserRdr) FindActiveByEmail(context.Context, domain.Email) ([]domain.User, error) {
	return []domain.User{{
		ID:           inviteLogCanonicalID,
		AccountID:    "acc0000000000000othr",
		Email:        inviteLogEmail,
		InviteStatus: domain.InviteStatusActive,
	}}, nil
}

type inviteLogProjectRdr struct{ repoproject.ReaderIface }

func (inviteLogProjectRdr) Get(_ context.Context, id domain.ProjectID) (domain.Project, error) {
	return domain.Project{ID: id, AccountID: domain.AccountID(invPrincAccount)}, nil
}

type inviteLogRoleRdr struct{ reporole.ReaderIface }

func (inviteLogRoleRdr) Get(_ context.Context, id domain.RoleID) (domain.Role, error) {
	// Системная роль — назначаема на любой области, поэтому шлюз приглашения
	// пропускает её и путь доходит до записи выдачи.
	return domain.Role{ID: id, IsSystem: true}, nil
}

type inviteLogABWtr struct{ access_binding.WriterIface }

func (inviteLogABWtr) Insert(_ context.Context, b domain.AccessBinding) (domain.AccessBinding, error) {
	if b.ID == "" {
		b.ID = "abd0000000000000log1"
	}
	return b, nil
}

func (inviteLogABWtr) InsertSubjects(context.Context, domain.AccessBindingID, []domain.Subject) error {
	return nil
}

// inviteWithCanonicalRow прогоняет одно project-scoped приглашение с провязанным
// логгером и возвращает буфер журнала вместе с идентификатором свежей строки.
//
// Буфер журнала — `logbuf.Buffer`, а не голый `bytes.Buffer`: в него пишет
// исполнитель операции из СВОЕЙ горутины, а читает проба из своей и из горутины
// `require.Eventually`. Голый буфер давал здесь гонку, которую детектор ловил не
// на каждом процессе — и проба краснела на чужих запросах слияния.
func inviteWithCanonicalRow(t *testing.T) (logText string, perAccountRowID string) {
	t.Helper()

	repo := &inviteLogRepo{invPrincRepo: &invPrincRepo{}}
	logBuf := &logbuf.Buffer{}
	logger := slog.New(slog.NewTextHandler(logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// Логгер провязывается ПОЛЕМ, а не через WithRelationStore: тот же вызов
	// заменил бы и страж прав на nil, и приглашение упало бы на вопросе о
	// правах, не дойдя до записи, чей текст судит проба.
	uc := NewInviteUserUseCase(repo, newFakeUsrOps(), invPrincAllowAll{})
	uc.logger = logger

	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: "usr0000000000000invl"})
	op, err := uc.Execute(ctx, InviteUserInput{
		AccountID: domain.AccountID(invPrincAccount),
		Email:     domain.Email(inviteLogEmail),
		ProjectID: domain.ProjectID(inviteLogProject),
		RoleID:    domain.RoleID(inviteLogRole),
	})
	require.NoError(t, err, "приглашение обязано быть принято")
	require.NotNil(t, op)

	require.Eventually(t, func() bool {
		repo.mu.Lock()
		defer repo.mu.Unlock()
		return repo.inserted
	}, 5*time.Second, 10*time.Millisecond,
		"приглашение обязано дойти до писателя — иначе ветвь записи не исполнялась")

	// Ветвь записи исполняется ПОСЛЕ вставки; дожидаемся самой записи, а не
	// её предусловия, иначе проба судила бы пустой буфер.
	require.Eventually(t, func() bool {
		return strings.Contains(logBuf.String(), "canonical_row")
	}, 5*time.Second, 10*time.Millisecond,
		"запись о канонической строке не состоялась — ветвь, чью запись судит проба, не исполнилась")

	return logBuf.String(), string(repo.row())
}

// TestInvite_CanonicalRowRecord_KeepsEmailOutOfTheLog — предмет задачи.
func TestInvite_CanonicalRowRecord_KeepsEmailOutOfTheLog(t *testing.T) {
	logText, _ := inviteWithCanonicalRow(t)

	require.NotContains(t, logText, inviteLogEmail,
		"почта приглашаемого не пишется в поток журнала на пути приглашения "+
			"(security.md §Hardening п.2): поток уезжает оператору, чью политику "+
			"хранения мы не знаем, а коррелировать здесь есть по чему — оба "+
			"не-личных идентификатора строки стоят в той же записи")
}

// Положительный контроль: не-личные корреляторы обязаны ОСТАТЬСЯ.
//
// Без него «почты нет» зеленело бы на правке, снявшей запись целиком, — а
// именно она объясняет, почему выдача ушла на чужую строку.
func TestInvite_CanonicalRowRecord_KeepsBothNonPersonalCorrelators(t *testing.T) {
	logText, perAccountRow := inviteWithCanonicalRow(t)

	require.Contains(t, logText, "canonical_row",
		"запись обязана называть каноническую строку — без неё разбор «почему выдача "+
			"ушла на другой идентификатор» невозможен")
	require.Contains(t, logText, inviteLogCanonicalID,
		"каноническая строка обязана быть названа ЗНАЧЕНИЕМ, а не одним ключом")
	require.Contains(t, logText, "per_account_row",
		"строка аккаунта обязана остаться вторым коррелятором")
	require.Contains(t, logText, perAccountRow,
		"строка аккаунта обязана быть названа значением: ключ без значения не коррелирует")
}
