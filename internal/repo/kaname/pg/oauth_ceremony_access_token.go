// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

// oauth_ceremony_access_token.go — запись ВЫПУСКА токена доступа собственной
// церемонии: идентификатор выпуска → семейство (задача PRO-Robotech/kaname#319,
// решение К10 вариант А; миграция
// `20260923231545_access_token_belongs_to_its_family.sql`).
//
// # ЗАЧЕМ ЭТА ЗАПИСЬ
//
// Токен доступа сверяют по подписи, и поверхность, принимающая его, строки
// гранта не читает. Отзыв семейства доезжает до неё только так: поверхность
// спрашивает о выпуске по его идентификатору, а запись выпуска отвечает,
// жива ли его семья.
//
// # ЧТО ДЕРЖИТ БАЗА, А НЕ ЭТОТ ФАЙЛ
//
//   - единственность идентификатора — первичный ключ;
//   - выпуск только в ЖИВОЕ семейство и доезд отзыва до записи — ключ
//     `(family_id, family_live) → token_families (id, live)` с каскадом правки;
//   - «семейство снято» не превращается в «выпуск ничей» — действие ключа на
//     удаление `SET NULL (family_live)`.
//
// Поэтому ни писатель, ни читатель здесь не проверяют семейство ПЕРЕД
// записью: условие и запись исполняет сам движок под замком ключа (ban #10).

import (
	"context"
	stderrors "errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/corelib/db/pgfault"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
)

// issuanceFamilyFK — ограничение, которым база отвергает выпуск в
// неизвестное либо отозванное семейство.
const issuanceFamilyFK = "access_tokens_family_fk"

// recordIssuanceSQL — заведение записи выпуска. Живости семейства оператор
// НЕ пишет: её берёт умолчание, и ключ сверяет его с живым семейством.
const recordIssuanceSQL = `
INSERT INTO kaname.access_tokens (jti, family_id, issued_at, expires_at)
VALUES ($1, $2, $3, $4)`

// familyRevokedOfIssuanceSQL — ЕДИНСТВЕННЫЙ оператор, читающий решение «отозвано
// ли семейство выпуска». Второго написания в дереве нет и быть не должно: его
// держит гейт `internal/check`
// `TestFamilyVerdictHasOneReaderAndEverySurfaceAsksTheRule`.
//
// `IS NOT TRUE`, а не `= false` и не `NOT family_live`: пустая живость — снятое
// семейство — обязана давать «отозван». И сравнение на ложь, и отрицание дают
// на ней пустое значение (трёхзначная логика), а не ответ: драйвер пустое в
// признак не читает, и каждая поверхность закрылась бы ошибкой хранилища на
// законном вопросе о снятом семействе. Допуском снятие стало бы на форме
// `coalesce(…, false)` — её здесь нет по той же причине.
const familyRevokedOfIssuanceSQL = `SELECT family_live IS NOT TRUE FROM kaname.access_tokens WHERE jti = $1`

// sweepExpiredIssuancesSQL — уборка записей, чей токен уже не примет ни одна
// поверхность. Партией и по часам БАЗЫ, как у соседних уборщиков.
const sweepExpiredIssuancesSQL = `
DELETE FROM kaname.access_tokens
 WHERE ctid IN (
     SELECT ctid FROM kaname.access_tokens
      WHERE expires_at < now() - make_interval(secs => $1)
      ORDER BY expires_at
      LIMIT $2
      FOR UPDATE SKIP LOCKED
 )`

// issuanceTable — таблица записей выпуска так, как её называет сервер в
// отказе.
const issuanceTable = "access_tokens"

// issuanceBackstopMessage — запись журнала о сработавшем рубеже писателя
// выпуска.
const issuanceBackstopMessage = "access token issuance record refused a value the service produced"

// RecordAccessToken записывает выпуск токена доступа в его семейство.
//
// # КТО ЗОВЁТ
//
// Выпуск токена доступа церемонии — адаптер порта выпуска фундамента
// (`ceremonyport.AccessTokens.IssueAccessToken`, порт
// `oauthceremony.AccessTokenIssuer` пакета `corelib/oauthceremony`) через свой
// порт `ceremonyport.IssuanceRecorder`. Сама церемония в композиционном корне
// службы ещё не собрана (kaname#407): до сборки записей на пути запроса не
// пишет никто.
//
// Обязанность выпуска, а не пожелание:
//
//   - писать ПОСЛЕ подписи и ДО того, как токен уедет клиенту, с `expiresAt`,
//     равным подписанному `exp` (не более ранней границей: уборка сняла бы
//     строку, пока токен ещё принимается);
//   - отказ записи ОБЯЗАН ронять выдачу. Отсутствие записи правило отзыва
//     читает как «семейству не принадлежит», и токен без записи отзыв
//     семейства не снимает.
//
// Держит обязанность гейт `internal/check`
// `TestFamilyVerdictHasOneReaderAndEverySurfaceAsksTheRule`: реализация порта
// выпуска при нуле вызывающих писателя в дереве — находка.
//
// # УРОВЕНЬ ИЗОЛЯЦИИ — НАЗВАННЫЙ
//
// Оператор исполняется на уровне писателей церемонии (`ceremonyWriterTx()`
// через `execWriter`, kaname#316), а не на умолчании сессии. Заведение,
// стоявшее на строке семейства, которую отзыв меняет в ключе (`live`), после
// фиксации отзыва перепроверяет ключ по новой версии строки и получает отказ
// ключа — «семейство не живо». Под унаследованным `repeatable read` либо
// `serializable` тот же порядок дал бы отказ сериализации, то есть «повторите»
// вместо исхода заведения. Держит сцена `RecordAccessToken` пробы
// `oauth_ceremony_isolation_integration_test.go`.
//
// # ИСХОДОВ ДВА
//
// Семейства нет либо оно отозвано — `domain.ErrAccessTokenFamilyNotLive`: это
// решает ключ базы, а не проверка перед вставкой, и это исход ЗАВЕДЕНИЯ — выдача
// не состоится, но служба исправна.
//
// Любой другой отказ — ДЕФЕКТ СЛУЖБЫ: каждое значение записи производит она
// сама (подписант чеканит `jti`, `iat`, `exp`, церемония называет семейство), и
// вызывающий точки выдачи ни одного из них не присылает. Отказ ввода обвинял бы
// клиента в том, чего он не делал и не может исправить. Поэтому —
// фиксированный `iamerr.ErrInternal` и запись в журнале с координатами; ни
// идентификатор выпуска, ни строка отказа (`Detail`) в журнал не идут.
func (r *OAuthCeremonyRepo) RecordAccessToken(ctx context.Context, jti, familyID string, issuedAt, expiresAt time.Time) error {
	switch {
	case jti == "":
		return issuanceDefect(ctx, familyID, "jti", "required")
	case familyID == "":
		return issuanceDefect(ctx, familyID, "family_id", "required")
	case issuedAt.IsZero():
		return issuanceDefect(ctx, familyID, "issued_at", "required")
	case expiresAt.IsZero():
		return issuanceDefect(ctx, familyID, "expires_at", "required")
	case !expiresAt.After(issuedAt):
		return issuanceDefect(ctx, familyID, "expires_at", "must be after issued_at")
	}
	if _, err := r.execWriter(ctx, recordIssuanceSQL, jti, familyID, issuedAt, expiresAt); err != nil {
		return issuanceRefusal(ctx, err, jti, familyID)
	}
	return nil
}

// issuanceDefect — отказ проверки писателя до базы: полоса дефекта службы.
func issuanceDefect(ctx context.Context, familyID, field, rule string) error {
	slog.ErrorContext(ctx, issuanceBackstopMessage,
		slog.String("kind", "AccessToken"), slog.String("family", familyID),
		slog.String("field", field), slog.String("rule", rule))
	return iamerr.ErrInternal
}

// issuanceRefusal разбирает отказ базы на заведении записи выпуска.
//
// Полоса дефекта судится КЛАССОМ, а не перечнем имён: любой отказ целостности
// (SQLSTATE класса 23) нашей таблицы, кроме ключа семейства, — значение службы,
// которое схема не приняла. Ограничение, заведённое позже, попадает в ту же
// полосу без правки здесь; решение по каждому ограничению выписано в переписи
// integration-пробы `TestIntegration_AccessTokenRecordConstraintsAreAllAdjudicated`.
//
// Отказ без строки состояния (сервер не ответил) и прочие классы остаются общему
// переводчику: «не дозвонились» — не дефект значения.
func issuanceRefusal(ctx context.Context, err error, jti, familyID string) error {
	f := pgfault.Classify(err)
	if f.Class == pgfault.ForeignKey && f.Constraint == issuanceFamilyFK {
		return fmt.Errorf("%w: family %s", domain.ErrAccessTokenFamilyNotLive, familyID)
	}
	if f.FromDatabase() && f.Table == issuanceTable && strings.HasPrefix(f.SQLState, "23") {
		slog.ErrorContext(ctx, issuanceBackstopMessage,
			append([]any{slog.String("kind", "AccessToken"), slog.String("family", familyID)}, f.LogAttrs()...)...)
		return iamerr.ErrInternal
	}
	return wrapPgErr(err, "AccessToken", jti)
}

// SweepExpiredAccessTokens снимает записи выпуска, чей срок вышел раньше, чем
// `now() − grace` часами базы. Возвращает число снятых и признак «партия ушла
// полной».
//
// Порог — функция предиката читателя: каждая поверхность отвергает истёкший
// токен по его сроку с допуском `ClockSkew`, и после порога строка ни одного
// исхода не меняет. Величину слагаемых задаёт реестр уборки
// (`apps/kaname/retention`), не этот файл.
//
// Уровень — названный (`execWriter`), как у каждого писателя порта: строку,
// которую держит другой (каскад отзыва семейства), уборка пропускает и снимет
// следующим проходом, а правку строки, зафиксированную после её снимка, при
// названном уровне перечитывает, а не отказывает сериализацией.
func (r *OAuthCeremonyRepo) SweepExpiredAccessTokens(ctx context.Context, grace time.Duration, batch int) (int64, bool, error) {
	if batch <= 0 {
		return 0, false, fmt.Errorf("Illegal argument access_token sweep batch: must be positive")
	}
	tag, err := r.execWriter(ctx, sweepExpiredIssuancesSQL, grace.Seconds(), batch)
	if err != nil {
		return 0, false, wrapPgErr(err, "AccessToken", "")
	}
	n := tag.RowsAffected()
	return n, n == int64(batch), nil
}

// familyRevokedOf — ответ записи выпуска: отозвано ли семейство выпуска с этим
// идентификатором.
//
// Записи нет — выпуск семейству не принадлежит, и это ЗАКОННЫЙ ответ «нет», а не
// ошибка: токены вне церемонии (выдача по утверждению клиента и прочие) записи
// выпуска не имеют и судятся отсечками по ключам. Ошибка хранилища — третий
// исход, вызывающий закрывается сам.
func familyRevokedOf(ctx context.Context, q rowQuerier, jti string) (bool, error) {
	var revoked bool
	err := q.QueryRow(ctx, familyRevokedOfIssuanceSQL, jti).Scan(&revoked)
	if stderrors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, wrapPgErr(err, "AccessToken", "")
	}
	return revoked, nil
}

// FamilyRevoked — ответ о семействе выпуска для авторитета отзыва и читателя
// предъявленного (порт `tokenrevocation.Reader`). Оператор — ТОТ ЖЕ, что у
// `IsRevoked` службы отзыва: решение одно.
func (r *MintedTokenRevocationRepo) FamilyRevoked(ctx context.Context, jti string) (bool, error) {
	return familyRevokedOf(ctx, r.pool, jti)
}

// FamilyRevoked — ответ о семействе выпуска для `IsRevoked` службы отзыва.
// Оператор — ТОТ ЖЕ, что у поверхностей предъявления.
func (s *SessionRevocationsAdapter) FamilyRevoked(ctx context.Context, jti string) (bool, error) {
	return familyRevokedOf(ctx, s.pool, jti)
}
