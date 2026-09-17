// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

// login_method_repo.go — адаптер хранилища способа входа человека и
// подтверждённости адреса (фаза Ф2, часть П1, задача PRO-Robotech/kacho#1268).
// Исполняет порт `internal/apps/kaname/api/loginmethod.Store`.
//
// Инварианты держит база (ban #10), адаптер только переводит отказы:
//   - PRIMARY KEY (user_id, kind)          → 23505 → ALREADY_EXISTS;
//   - FK user_id → users(id) ON DELETE CASCADE → 23503 → FAILED_PRECONDITION;
//   - CHECK вид из словаря, материал непуст → 23514 → INTERNAL: оба значения
//     судит тип до вставки, и срабатывание ограничения — НАШ дефект;
//   - смена `users.email` снимает `users.email_verified_at` триггером того же
//     оператора; запись отметки сверяет значение адреса в своём операторе.
//
// Это ЕДИНСТВЕННЫЙ файл кода Go, где таблица секрета названа — литералом,
// склейкой либо константой — и где материал выходит из своего типа
// (`Reveal`). Разрешение дано ФАЙЛУ, а не пакету: соседние файлы пакета
// адаптера ни выхода, ни константы имени таблицы не касаются. Держит гейт
// дерева `internal/check` `TestLoginVerifierStaysInside`: второй читатель
// колонки получил бы материал строкой, минуя тип.
//
// Предел времени у вызова — контекст вызывающего, как у всех адаптеров службы:
// собственного у адаптера нет. Вызывающий без срока (утилита переноса П3)
// обязан нести его сам.

import (
	"context"
	stderrors "errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
)

// loginMethodsTable — имя таблицы секрета. Объявлено здесь ОДИН раз и за
// пределы этого файла не выходит: константа видна всему пакету, и её
// использование в соседнем файле было бы вторым читателем колонки.
const loginMethodsTable = "user_login_methods"

// isLoginMethodsTable — «отказ пришёл от таблицы секрета?». Предикат, а не
// имя: переводчик отказов сверяет таблицу отказа, не получая её имени в руки.
func isLoginMethodsTable(name string) bool { return name == loginMethodsTable }

// LoginMethodRepo — хранилище способа входа и подтверждённости адреса.
type LoginMethodRepo struct {
	pool *pgxpool.Pool
}

// NewLoginMethodRepo конструирует.
func NewLoginMethodRepo(pool *pgxpool.Pool) *LoginMethodRepo {
	return &LoginMethodRepo{pool: pool}
}

// loginMethodHint — подсказка переводчику отказов: человек и вид, и НИЧЕГО
// сверх — материал в подсказку не кладётся никогда, иначе он доехал бы до
// текста отказа.
func loginMethodHint(user domain.UserID, kind domain.LoginMethodKind) string {
	return string(user) + "|" + string(kind)
}

// splitLoginMethodHint — обратный разбор; короткая форма (без вида) не ломает
// разбор и возвращает пустой вид.
func splitLoginMethodHint(hint string) (user, kind string) {
	user, kind, _ = strings.Cut(hint, "|")
	return user, kind
}

// Create заводит способ. Строку судит тип ДО базы — отказ входа поэтому
// различим кодом с отказом ограничения таблицы (INVALID_ARGUMENT против
// INTERNAL).
func (r *LoginMethodRepo) Create(ctx context.Context, m domain.LoginMethod) (domain.LoginMethod, error) {
	return insertLoginMethod(ctx, r.pool, m)
}

// loginMethodQuerier — то, что исполняет вставку: пул (глагол `Create`) либо
// транзакция вызывающего (регистрация Ф4 кладёт строку способа входа одним
// исходом с зеркалом и сессией).
type loginMethodQuerier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// insertLoginMethod — ЕДИНСТВЕННЫЙ оператор вставки строки способа входа.
// Живёт в этом файле, потому что называет таблицу секрета и выпускает материал
// оператору базы (гейт `TestLoginVerifierStaysInside`).
func insertLoginMethod(ctx context.Context, q loginMethodQuerier, m domain.LoginMethod) (domain.LoginMethod, error) {
	if err := m.Validate(); err != nil {
		return domain.LoginMethod{}, iamerr.Wrapf(iamerr.ErrInvalidArg, "%s", err.Error())
	}
	sql := `INSERT INTO ` + loginMethodsTable + ` (user_id, kind, verifier)
	      VALUES ($1, $2, $3)
	      RETURNING created_at`
	var created time.Time
	if err := q.QueryRow(ctx, sql, string(m.UserID), string(m.Kind), m.Verifier.Reveal()).Scan(&created); err != nil {
		return domain.LoginMethod{}, mapErr(err, "LoginMethod.Create", loginMethodHint(m.UserID, m.Kind))
	}
	out := m
	out.CreatedAt = created
	return out, nil
}

// InsertLoginMethod — строка способа входа в транзакции регистрации (порт
// `registration.Writer`). Метод писателя регистрации объявлен ЗДЕСЬ, а не в его
// файле: право назвать таблицу секрета дано этому файлу.
func (w *RegistrationWriter) InsertLoginMethod(ctx context.Context, m domain.LoginMethod) error {
	_, err := insertLoginMethod(ctx, w.tx, m)
	return err
}

// Get читает способ человека данного вида.
func (r *LoginMethodRepo) Get(ctx context.Context, userID domain.UserID, kind domain.LoginMethodKind) (domain.LoginMethod, error) {
	if userID == "" {
		return domain.LoginMethod{}, iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument login_method.user_id: required")
	}
	if err := kind.Validate(); err != nil {
		return domain.LoginMethod{}, iamerr.Wrapf(iamerr.ErrInvalidArg, "%s", err.Error())
	}
	q := `SELECT verifier, created_at FROM ` + loginMethodsTable + ` WHERE user_id = $1 AND kind = $2`
	var (
		material string
		created  time.Time
	)
	err := r.pool.QueryRow(ctx, q, string(userID), string(kind)).Scan(&material, &created)
	if stderrors.Is(err, pgx.ErrNoRows) {
		return domain.LoginMethod{}, iamerr.Wrapf(iamerr.ErrNotFound, "Login method %s of user %s not found", kind, userID)
	}
	if err != nil {
		return domain.LoginMethod{}, mapErr(err, "LoginMethod.Get", loginMethodHint(userID, kind))
	}
	verifier, verr := domain.NewLoginVerifier(material)
	if verr != nil {
		// Пустого материала ограничение таблицы не пропускает; прочитать его
		// значит найти строку, записанную мимо схемы, — НАШ дефект, а не «нет
		// способа».
		return domain.LoginMethod{}, iamerr.Wrapf(iamerr.ErrInternal, "stored login method is malformed")
	}
	return domain.LoginMethod{UserID: userID, Kind: kind, Verifier: verifier, CreatedAt: created}, nil
}

// MarkEmailVerified записывает момент подтверждения ТОЛЬКО на подтверждённое
// значение: сверка адреса и запись отметки — один оператор, поэтому смена
// адреса, зафиксированная раньше, делает запись пустой, а зафиксированная позже
// снимает отметку триггером. Между «спросить» и «записать» чужой фиксации не
// помещается.
//
// Существование человека читается в том же операторе ради ТЕКСТА отказа: без
// него «человека нет» и «адрес не тот» были бы неразличимы.
func (r *LoginMethodRepo) MarkEmailVerified(ctx context.Context, userID domain.UserID, address domain.Email, at time.Time) error {
	if at.IsZero() {
		return iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument email_verified_at: required")
	}
	if userID == "" {
		return iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument user_id: required")
	}
	const q = `
		WITH person AS (SELECT 1 FROM users WHERE id = $1),
		     marked AS (
		       UPDATE users SET email_verified_at = $3
		        WHERE id = $1 AND email = $2
		       RETURNING 1)
		SELECT EXISTS (SELECT 1 FROM person), EXISTS (SELECT 1 FROM marked)`
	var exists, marked bool
	if err := r.pool.QueryRow(ctx, q, string(userID), string(address), at).Scan(&exists, &marked); err != nil {
		return mapErr(err, "User.MarkEmailVerified", string(userID))
	}
	switch {
	case !exists:
		return iamerr.Wrapf(iamerr.ErrNotFound, "User %s not found", userID)
	case !marked:
		// Текущий адрес в отказ не кладётся: вызывающий подтверждал СВОЁ
		// значение, и чужое ему не отвечает.
		return iamerr.Wrapf(iamerr.ErrFailedPrecondition, "User %s email does not match the address being verified", userID)
	}
	return nil
}

// EmailVerification — момент подтверждения текущего адреса.
func (r *LoginMethodRepo) EmailVerification(ctx context.Context, userID domain.UserID) (time.Time, bool, error) {
	if userID == "" {
		return time.Time{}, false, iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument user_id: required")
	}
	var at *time.Time
	err := r.pool.QueryRow(ctx, `SELECT email_verified_at FROM users WHERE id = $1`, string(userID)).Scan(&at)
	if stderrors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, false, iamerr.Wrapf(iamerr.ErrNotFound, "User %s not found", userID)
	}
	if err != nil {
		return time.Time{}, false, mapErr(err, "User.EmailVerification", string(userID))
	}
	if at == nil {
		return time.Time{}, false, nil
	}
	return *at, true, nil
}

// replaceLoginVerifierTx — ЗАМЕЩЕНИЕ материала одним оператором (ID-PW-1
// PWV-10, фаза Ф3 `kacho#1269`): новое значение кладётся `UPDATE` по паре
// (человек, вид); строки нет — replaced=false, вставки нет (заводит способ
// только `Create`). Два одновременных замещения одним значением — оба проходят,
// запись одна: у `UPDATE` одной строки конкурента разводит замок строки.
//
// Живёт в ЭТОМ файле, потому что называет таблицу секрета и выпускает материал
// оператору базы — оба права даны только этому файлу (гейт
// `TestLoginVerifierStaysInside`). Транзакцию приносит вызывающий (полоса входа
// и смена пароля кладут материал ОДНИМ исходом с прочими записями).
func replaceLoginVerifierTx(ctx context.Context, tx pgx.Tx, m domain.LoginMethod) (bool, error) {
	if err := m.Validate(); err != nil {
		return false, iamerr.Wrapf(iamerr.ErrInvalidArg, "%s", err.Error())
	}
	q := `UPDATE ` + loginMethodsTable + ` SET verifier = $3 WHERE user_id = $1 AND kind = $2`
	tag, err := tx.Exec(ctx, q, string(m.UserID), string(m.Kind), m.Verifier.Reveal())
	if err != nil {
		return false, mapErr(err, "LoginMethod.Replace", loginMethodHint(m.UserID, m.Kind))
	}
	return tag.RowsAffected() == 1, nil
}
