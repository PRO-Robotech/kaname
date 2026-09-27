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
//   - CHECK вид из словаря, состояние из словаря, «pending — только у totp»,
//     материал непуст → 23514 → INTERNAL: все значения судит тип до вставки, и
//     срабатывание ограничения — НАШ дефект;
//   - смена `users.email` снимает `users.email_verified_at` триггером того же
//     оператора; запись отметки сверяет значение адреса в своём операторе.
//
// Второй фактор (Ф12, kacho#1281) — операторы ниже, все в ЭТОМ файле, потому
// что каждый называет таблицу секрета: заведение одним оператором под ключом
// «человек, вид», CAS подтверждения, условная запись принятого шага, набор
// запасных кодов под замком строки, снятие обеих строк, уборка истёкших
// заведений. Материал ни один из них НЕ читает строкой мимо типа: набор
// потребляется по ЗНАЧЕНИЮ ЭЛЕМЕНТА, которое приносит проверяющий (он вычислил
// его из предъявленного кода и соли — это не материал строки), а форма набора
// (элементы между запятыми, запятая по краям) объявлена проверяющим и
// исполняется здесь одним `replace`.
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

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/loginmethod"
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
	sql := `INSERT INTO ` + loginMethodsTable + ` (user_id, kind, verifier, state)
	      VALUES ($1, $2, $3, $4)
	      RETURNING created_at`
	var created time.Time
	if err := q.QueryRow(ctx, sql, string(m.UserID), string(m.Kind), m.Verifier.Reveal(), string(m.State)).Scan(&created); err != nil {
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
	return getLoginMethod(ctx, r.pool, userID, kind)
}

// getLoginMethod — ЕДИНСТВЕННЫЙ оператор чтения строки способа входа по человеку
// и виду. Исполняет его пул (глагол `Get`) либо транзакция вызывающего: писатель
// сессии (`humanSessionWriter.LoginMethod`) читает им заведённое тем же
// соединением, что пишет, — завершение восстановления спрашивает о способах
// входа только ПОСЛЕ применения кода (задача PRO-Robotech/kaname#305). Живёт в
// этом файле, потому что называет таблицу секрета.
func getLoginMethod(ctx context.Context, q loginMethodQuerier, userID domain.UserID, kind domain.LoginMethodKind) (domain.LoginMethod, error) {
	if userID == "" {
		return domain.LoginMethod{}, iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument login_method.user_id: required")
	}
	if err := kind.Validate(); err != nil {
		return domain.LoginMethod{}, iamerr.Wrapf(iamerr.ErrInvalidArg, "%s", err.Error())
	}
	sql := `SELECT verifier, state, last_accepted_step, created_at FROM ` + loginMethodsTable + ` WHERE user_id = $1 AND kind = $2`
	m, err := scanLoginMethod(q.QueryRow(ctx, sql, string(userID), string(kind)), userID, kind)
	if stderrors.Is(err, pgx.ErrNoRows) {
		return domain.LoginMethod{}, iamerr.Wrapf(iamerr.ErrNotFound, "Login method %s of user %s not found", kind, userID)
	}
	if err != nil {
		return domain.LoginMethod{}, mapErr(err, "LoginMethod.Get", loginMethodHint(userID, kind))
	}
	return m, nil
}

// scanLoginMethod — строка способа из ряда `verifier, state, last_accepted_step,
// created_at`. Отказ базы (в том числе `pgx.ErrNoRows`) уходит вызывающему как
// есть; строка, не проходящая тип, — НАШ дефект.
func scanLoginMethod(row pgx.Row, userID domain.UserID, kind domain.LoginMethodKind) (domain.LoginMethod, error) {
	var (
		material string
		state    string
		step     *int64
		created  time.Time
	)
	if err := row.Scan(&material, &state, &step, &created); err != nil {
		return domain.LoginMethod{}, err
	}
	verifier, verr := domain.NewLoginVerifier(material)
	if verr != nil {
		// Пустого материала ограничение таблицы не пропускает; прочитать его
		// значит найти строку, записанную мимо схемы, — НАШ дефект, а не «нет
		// способа».
		return domain.LoginMethod{}, iamerr.Wrapf(iamerr.ErrInternal, "stored login method is malformed")
	}
	m := domain.LoginMethod{UserID: userID, Kind: kind, Verifier: verifier, State: domain.LoginMethodState(state), CreatedAt: created}
	if step != nil {
		m.AcceptedStep, m.StepAccepted = *step, true
	}
	if err := m.Validate(); err != nil {
		return domain.LoginMethod{}, iamerr.Wrapf(iamerr.ErrInternal, "stored login method is malformed")
	}
	return m, nil
}

// PasswordCostClasses — перепись классов стоимости (порт
// `loginmethod.CostClassCensus`; решение kaname#188).
//
// Класс вычисляет БАЗА: наружу уходит значение без соли и тела — у
// наследуемого формата два сегмента (признак, стоимость), у объявленного три
// (признак, версия, параметры). Значение с признаком вне перечня отдаётся
// ПУСТЫМ префиксом: его сегменты могли бы нести что угодно, а перепись выносит
// из колонки только то, что читатель класса разберёт как числа. Читатель —
// `passwordverify.ParseCostClassPrefix`; сходимость производителя и читателя
// держит `TestLoginMethodRepo_CostClassPrefixRoundTripsThroughTheParser`.
//
// Один последовательный проход по таблице, без индекса по материалу (шапка
// миграции запрещает его намеренно); зовётся один раз при старте.
func (r *LoginMethodRepo) PasswordCostClasses(ctx context.Context) ([]loginmethod.CostClassCount, error) {
	q := `SELECT
	        CASE
	          WHEN verifier LIKE $2 THEN array_to_string((string_to_array(verifier, '$'))[1:3], '$')
	          WHEN verifier LIKE $3 THEN array_to_string((string_to_array(verifier, '$'))[1:4], '$')
	          ELSE ''
	        END AS prefix,
	        count(*)
	      FROM ` + loginMethodsTable + `
	      WHERE kind = $1
	      GROUP BY 1
	      ORDER BY 1`
	rows, err := r.pool.Query(ctx, q, string(domain.LoginMethodPassword),
		"$"+string(domain.PasswordHashFormatBcrypt)+"$%", "$"+string(domain.PasswordHashFormatArgon2id)+"$%")
	if err != nil {
		return nil, mapErr(err, "LoginMethod.CostClassCensus", "")
	}
	defer rows.Close()
	var out []loginmethod.CostClassCount
	for rows.Next() {
		var c loginmethod.CostClassCount
		if err := rows.Scan(&c.Prefix, &c.Rows); err != nil {
			return nil, mapErr(err, "LoginMethod.CostClassCensus", "")
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, mapErr(err, "LoginMethod.CostClassCensus", "")
	}
	return out, nil
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

// --- второй фактор (Ф12, kacho#1281): операторы над таблицей секрета ---

// upsertPendingTOTPTx — ОДИН оператор заведения (Ф12-05, приёмка Р4 матрица):
// вставка под ключом «человек, вид»; при конфликте — замена ТОЛЬКО не-`active`
// строки. Ноль затронутых строк означает «уже заведён»; проверки перед
// вставкой нет, и два одновременных заведения дают одну строку с секретом
// позднего — под замком строки конфликта.
func upsertPendingTOTPTx(ctx context.Context, tx pgx.Tx, m domain.LoginMethod) (bool, error) {
	if err := m.Validate(); err != nil {
		return false, iamerr.Wrapf(iamerr.ErrInvalidArg, "%s", err.Error())
	}
	if m.Kind != domain.LoginMethodTOTP || m.State != domain.LoginMethodStatePending || m.CreatedAt.IsZero() {
		return false, iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument login_method: enrollment row must be a pending totp row with its moment")
	}
	q := `INSERT INTO ` + loginMethodsTable + ` (user_id, kind, verifier, state, last_accepted_step, created_at)
	      VALUES ($1, $2, $3, $4, NULL, $5)
	      ON CONFLICT (user_id, kind) DO UPDATE
	         SET verifier = EXCLUDED.verifier, state = EXCLUDED.state, last_accepted_step = NULL, created_at = EXCLUDED.created_at
	       WHERE ` + loginMethodsTable + `.state <> 'active'`
	tag, err := tx.Exec(ctx, q, string(m.UserID), string(m.Kind), m.Verifier.Reveal(), string(m.State), m.CreatedAt)
	if err != nil {
		return false, mapErr(err, "LoginMethod.EnrollPending", loginMethodHint(m.UserID, m.Kind))
	}
	return tag.RowsAffected() == 1, nil
}

// activateTOTPTx — CAS подтверждения (Ф12-07): строка `pending` с ТЕМ ЖЕ
// моментом заведения становится `active`; момент подтверждения ложится в
// `created_at`, принятый шаг — в строку. Ноль строк — заведения того момента
// уже нет: активировано, заменено либо снято.
func activateTOTPTx(ctx context.Context, tx pgx.Tx, userID domain.UserID, pendingSince time.Time, step int64, at time.Time) (bool, error) {
	if userID == "" || pendingSince.IsZero() || at.IsZero() {
		return false, iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument login_method: user, enrollment moment and confirmation moment required")
	}
	q := `UPDATE ` + loginMethodsTable + `
	         SET state = 'active', last_accepted_step = $3, created_at = $4
	       WHERE user_id = $1 AND kind = $2 AND state = 'pending' AND created_at = $5`
	tag, err := tx.Exec(ctx, q, string(userID), string(domain.LoginMethodTOTP), step, at, pendingSince)
	if err != nil {
		return false, mapErr(err, "LoginMethod.Activate", loginMethodHint(userID, domain.LoginMethodTOTP))
	}
	return tag.RowsAffected() == 1, nil
}

// replaceLookupSetTx — набор запасных кодов целиком: вставка либо замена
// строки `lookup_secret` (Ф12 Р6). Материал уходит оператору аргументом.
func replaceLookupSetTx(ctx context.Context, tx pgx.Tx, m domain.LoginMethod) error {
	if err := m.Validate(); err != nil {
		return iamerr.Wrapf(iamerr.ErrInvalidArg, "%s", err.Error())
	}
	if m.Kind != domain.LoginMethodLookupSecret || m.CreatedAt.IsZero() {
		return iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument login_method: lookup set row must be a lookup_secret row with its moment")
	}
	q := `INSERT INTO ` + loginMethodsTable + ` (user_id, kind, verifier, state, created_at)
	      VALUES ($1, $2, $3, $4, $5)
	      ON CONFLICT (user_id, kind) DO UPDATE
	         SET verifier = EXCLUDED.verifier, state = EXCLUDED.state, created_at = EXCLUDED.created_at`
	if _, err := tx.Exec(ctx, q, string(m.UserID), string(m.Kind), m.Verifier.Reveal(), string(m.State), m.CreatedAt); err != nil {
		return mapErr(err, "LoginMethod.ReplaceLookupSet", loginMethodHint(m.UserID, m.Kind))
	}
	return nil
}

// lockLookupSetTx — строка набора под замком строки до конца транзакции
// (Ф12-24): сериализует чтение-изменение-запись набора между писателями.
func lockLookupSetTx(ctx context.Context, tx pgx.Tx, userID domain.UserID) (domain.LoginMethod, bool, error) {
	if userID == "" {
		return domain.LoginMethod{}, false, iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument login_method.user_id: required")
	}
	q := `SELECT verifier, state, last_accepted_step, created_at FROM ` + loginMethodsTable + `
	       WHERE user_id = $1 AND kind = $2 FOR UPDATE`
	m, err := scanLoginMethod(tx.QueryRow(ctx, q, string(userID), string(domain.LoginMethodLookupSecret)), userID, domain.LoginMethodLookupSecret)
	if stderrors.Is(err, pgx.ErrNoRows) {
		return domain.LoginMethod{}, false, nil
	}
	if err != nil {
		return domain.LoginMethod{}, false, mapErr(err, "LoginMethod.LockLookupSet", loginMethodHint(userID, domain.LoginMethodLookupSecret))
	}
	return m, true, nil
}

// consumeLookupElementTx — снятие одного элемента набора по значению
// (Ф12-23): форма набора — элементы между запятыми, запятая по краям, поэтому
// элемент узнаётся ровно с обеими запятыми и подстрока элемента элементом не
// является. Значение приходит от проверяющего, вычислившего его из
// предъявленного кода, — материала строки в аргументах нет.
func consumeLookupElementTx(ctx context.Context, tx pgx.Tx, userID domain.UserID, element string) (bool, error) {
	if userID == "" || element == "" || strings.ContainsRune(element, ',') {
		return false, iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument lookup element: required and without a separator")
	}
	q := `UPDATE ` + loginMethodsTable + `
	         SET verifier = replace(verifier, ',' || $3 || ',', ',')
	       WHERE user_id = $1 AND kind = $2 AND position(',' || $3 || ',' in verifier) > 0`
	tag, err := tx.Exec(ctx, q, string(userID), string(domain.LoginMethodLookupSecret), element)
	if err != nil {
		return false, mapErr(err, "LoginMethod.ConsumeLookupElement", loginMethodHint(userID, domain.LoginMethodLookupSecret))
	}
	return tag.RowsAffected() == 1, nil
}

// recordAcceptedStepTx — условная запись принятого шага (Ф12 Р5, Ф12-22):
// только `active` и только шаг старше последнего принятого. Условие — арбитр
// двух одновременных предъявлений одной ступени: второй ждёт замка строки и
// видит уже записанный шаг.
func recordAcceptedStepTx(ctx context.Context, tx pgx.Tx, userID domain.UserID, step int64) (bool, error) {
	if userID == "" {
		return false, iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument login_method.user_id: required")
	}
	q := `UPDATE ` + loginMethodsTable + `
	         SET last_accepted_step = $3
	       WHERE user_id = $1 AND kind = $2 AND state = 'active'
	         AND (last_accepted_step IS NULL OR last_accepted_step < $3)`
	tag, err := tx.Exec(ctx, q, string(userID), string(domain.LoginMethodTOTP), step)
	if err != nil {
		return false, mapErr(err, "LoginMethod.RecordAcceptedStep", loginMethodHint(userID, domain.LoginMethodTOTP))
	}
	return tag.RowsAffected() == 1, nil
}

// removeSecondFactorTx — строки `totp` (`active`) и `lookup_secret` одним
// оператором (Ф12-28, Ф12-30). Набор снимается только вместе с заведённым
// фактором; строка `pending` не трогается — её снимает срок либо новое
// заведение (матрица Р4).
func removeSecondFactorTx(ctx context.Context, tx pgx.Tx, userID domain.UserID) (bool, error) {
	if userID == "" {
		return false, iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument login_method.user_id: required")
	}
	q := `WITH factor AS (
	        DELETE FROM ` + loginMethodsTable + ` WHERE user_id = $1 AND kind = $2 AND state = 'active' RETURNING 1),
	      codes AS (
	        DELETE FROM ` + loginMethodsTable + ` WHERE user_id = $1 AND kind = $3 AND EXISTS (SELECT 1 FROM factor) RETURNING 1)
	      SELECT (SELECT count(*) FROM factor)`
	var removed int64
	if err := tx.QueryRow(ctx, q, string(userID), string(domain.LoginMethodTOTP), string(domain.LoginMethodLookupSecret)).Scan(&removed); err != nil {
		return false, mapErr(err, "LoginMethod.RemoveSecondFactor", loginMethodHint(userID, domain.LoginMethodTOTP))
	}
	return removed == 1, nil
}

// SweepExpiredEnrollments — уборка неподтверждённых заведений (Ф12-44, порт
// `humansession.EnrollmentSweeper`): строки `pending` старше окна — те, которые
// `confirm` уже не примет ни при каком коде. Партия ограничена `ctid`-подзапросом;
// full=true — партия заполнена, звать ещё.
func (r *LoginMethodRepo) SweepExpiredEnrollments(ctx context.Context, window time.Duration, batch int) (int64, bool, error) {
	if window <= 0 || batch <= 0 {
		return 0, false, iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument sweep: window and batch must be positive")
	}
	q := `DELETE FROM ` + loginMethodsTable + `
	       WHERE ctid IN (
	         SELECT ctid FROM ` + loginMethodsTable + `
	          WHERE kind = $1 AND state = 'pending' AND created_at < now() - $2::interval
	          LIMIT $3)`
	tag, err := r.pool.Exec(ctx, q, string(domain.LoginMethodTOTP), window, batch)
	if err != nil {
		return 0, false, mapErr(err, "LoginMethod.SweepExpiredEnrollments", "")
	}
	return tag.RowsAffected(), tag.RowsAffected() >= int64(batch), nil
}
