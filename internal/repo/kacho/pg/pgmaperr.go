// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

// pgmaperr.go — SQLSTATE → sentinel bridge (the pgx-aware half of error
// mapping). This lives in the repo/pg ADAPTER layer, not in internal/errors,
// so the pgx dependency (github.com/jackc/pgx/v5/pgconn) stays out of the pure
// sentinel package that ~40 use-case/handler files import (architecture.md
// dependency-rule: use-case/domain must not pull pgx into their build closure).
//
// internal/errors keeps ONLY the pgx-free sentinel family + Wrapf/StripSentinel;
// the constraint-name-aware canonical Kachō text mapping (uniqueText/fkText/…)
// belongs to the adapter that owns the DB constraints and is applied here via
// mapErr (maperr.go).

import (
	stderrors "errors"
	"fmt"
	"log/slog"
	"net"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"

	iamerr "github.com/PRO-Robotech/kacho-iam/internal/errors"
	"github.com/PRO-Robotech/kacho/pkg/db/pgfault"
	"github.com/PRO-Robotech/kacho/pkg/quota/quotadetail"
)

// wrapPgErr — SQLSTATE → ErrXxx mapping point, constraint-name aware. The
// constraint-name aware text mapping yields the canonical Kachō messages:
//
//	accounts_name_unique        → ErrAlreadyExists "Account with name %s already exists"
//	accounts_owner_fk           → ErrFailedPrecondition "User %s not found"
//	<таблица>_name_check        → ErrInternal (защита последнего рубежа: форму
//	                              имени проверяет сам сервис, значит срабатывание
//	                              ограничения — НАШ дефект, а не ввод вызывающего)
//	projects_account_fk (FK→accounts on INSERT project)        → ErrFailedPrecondition
//	projects_account_fk (FK←projects on DELETE account, 23503) → ErrFailedPrecondition "Account %s contains projects and cannot be deleted"
//
// The `kindHint` / `idHint` parameters supply context known only to the
// caller (passed in for the canonical Kachō text). When hints are empty we fall back
// to generic text.
func wrapPgErr(err error, kindHint, idHint string) error {
	if err == nil {
		return nil
	}
	var pgErr *pgconn.PgError
	if !stderrors.As(err, &pgErr) {
		// Отказ БЕЗ строки состояния — сервер не ответил вовсе. Единственный его
		// осмысленный класс здесь — не дозвонились (#666); всё остальное
		// возвращается нетронутым, чтобы «непонятное» не выдавалось за
		// «временное»: обещание повтора там, где повторять нечего, хуже
		// молчания.
		if isConnectionFailure(err) {
			return iamerr.Wrapf(iamerr.ErrUnavailable, "database unavailable")
		}
		return err
	}
	switch pgErr.Code {
	// Отказ учёта числа ресурсов — ПЕРЕД общими классами. Его SQLSTATE'ы
	// поднимает единственный производитель платформы (`kacho_quota_refuse`,
	// миграция 484001, рендер `pkg/quota/refusal.sql.tmpl`), общий на всех шести
	// владельцев учёта. Классы за пределами зарезервированных Postgres'ом букв —
	// поэтому совпасть с кодом сервера или расширения они не могут.
	//
	// Текст двух первых исходов сохраняется ДОСЛОВНО: он и есть контракт
	// («<носитель> <id> has reached its limit of <N> <вид>»), а не диагностика
	// хранилища, поэтому пересказывать его здесь значило бы завести второе место
	// об одном предмете. Текст третьего НЕ сохраняется — он про нашу схему, и
	// арендатору о ней знать нечего.
	case "KQ001": // место кончилось: строка учёта есть, used >= limit
		// Величины производителя приклеиваются ЗДЕСЬ — дальше по пути
		// `*pgconn.PgError` уже нет, и прочитать `DETAIL` негде (задача #1605).
		return quotadetail.Attach(
			iamerr.Wrapf(iamerr.ErrQuotaExceeded, "%s", pgErr.Message), pgErr.Detail)
	case "KQ002": // потолок не назван ни на одной области видимости
		return quotadetail.Attach(
			iamerr.Wrapf(iamerr.ErrQuotaNotProvisioned, "%s", pgErr.Message), pgErr.Detail)
	case "KQ003": // строка ресурса не несёт носителя — дефект схемы, не арендатора
		return iamerr.Wrapf(iamerr.ErrInternal, "quota accounting")
	// Полоса ТЕМПА (`kacho_rate_refuse`, миграция задачи #618). Её производитель
	// отдельный: тот, что выше, рендерится из общего шаблона шести владельцев и
	// говорит о строке учёта ОБЪЁМА, а этой полосы нет больше ни у кого.
	case "KQ004": // окно полно: за текущее окно принято столько, сколько названо
		return iamerr.Wrapf(iamerr.ErrQuotaRateExceeded, "%s", pgErr.Message)
	case "KQ005": // величина темпа не названа — администратору требуется ЗАВЕСТИ её
		// Тот же sentinel, что у не названного предела объёма, и это не небрежность:
		// действие администратора одно и то же — назначить величину, — а какую
		// именно, говорит текст производителя, который доезжает дословно.
		return iamerr.Wrapf(iamerr.ErrQuotaNotProvisioned, "%s", pgErr.Message)
	}

	// Классы целостности — через дом `pkg/db/pgfault`: одно правило корпуса, одно
	// место решения. Тексты остаются ЗДЕСЬ: тон отказа — часть контракта этого
	// сервиса («Account %s contains projects and cannot be deleted»), а не общего
	// правила, и дом, взявший на себя текст, потребовал бы менять контракт ради
	// централизации.
	//
	// Полоса учёта величин разобрана ВЫШЕ и по коду как есть: её коды производит
	// триггер схемы этого сервиса, а не сервер на ограничении таблицы, и общего
	// правила о них корпус не формулирует. Дом молчит о том, чего не знает.
	f := pgfault.Classify(err)
	switch f.Class {
	case pgfault.IntegrityConstraint: // integrity_constraint_violation — поднято ЯВНО триггером схемы
		// Класс отображается в FAILED_PRECONDITION целиком, а не одной связью:
		// `integrity_constraint_violation` по определению есть «состояние
		// ресурса не позволяет», а не поломка сервиса. Текст при этом берётся НЕ
		// из сообщения сервера — оно диагностика хранилища, — а из таблицы связей
		// ниже, и незнакомая связь получает общий текст без утечки.
		//
		// Признак ВЫБИРАЕТСЯ вместе с текстом, а не ставится общим на весь класс:
		// у отказа «членство несёт права» есть потребитель, дочитывающий перечень
		// мешающих выдач, и отличить эту полосу от прочих предусловий он обязан
		// машинно (см. `iamerr.ErrMembershipCarriesRights`).
		//
		// ОТСЮДА ТРЕБОВАНИЕ К ПРОИЗВОДИТЕЛЮ, и его держит гейт, а не эта строка:
		// `RAISE`, поднявший класс без клаузы `CONSTRAINT`, попадает в общую
		// полосу — код тот же, различимость потеряна. Держатель —
		// `internal/repohygiene` `TestLiveIntegrityRaiseNamesItsConstraint`: он
		// разбирает миграции всех сервисов, отличает живое определение функции от
		// замещённого поздним и от ветви отката, печатает перепись и падает, если
		// живых производителей не осталось вовсе.
		//
		// ЧТО ИМЕННО ТЕРЯЕТ БЕЗЫМЯННЫЙ ОТКАЗ — сказано здесь, потому что решает
		// это ЭТА ветвь, и сказано наблюдаемым, а не предположением:
		// `integritySentinel` отдаёт ему `ErrFailedPrecondition`, а
		// `integrityText` — фиксированный «resource state does not permit this
		// operation». То есть код отказа и его смысл сохраняются; теряется
		// РАЗЛИЧИМОСТЬ полосы и перечень мешающих выдач в тексте. Шапка миграции
		// `20260824010000_membership_mirror_does_not_invent_a_membership.sql`
		// обосновывала клаузу тем, что безымянный отказ «уехал бы в INTERNAL» и
		// арендатор прочитал бы «сервис сломан», — прогоном это не
		// подтверждается, цена мягче объявленной. Миграция применена и не
		// правится (ban #5), поэтому исправление стоит здесь: правило,
		// преувеличивающее цену, снимают первым.
		//
		// ЗДЕСЬ СТОЯЛО «единственный производитель в дереве» с предикатом
		// `git grep -n integrity_constraint_violation -- '*.sql'` → «одно
		// попадание». Предикат давал ЧЕТЫРЕ, и одно из четырёх было ЕГО ЖЕ
		// объяснением в шапке соседней миграции: счёт шёл по слову, а не по
		// производителю. Числа здесь больше нет намеренно — у выписанного числа
		// нет владельца, и переживает свой замер оно молча; сегодняшнее печатает
		// перепись гейта (задача #2018).
		return iamerr.Wrapf(integritySentinel(pgErr, kindHint), "%s", integrityText(pgErr, kindHint, idHint))
	case pgfault.Unique: // unique_violation
		return iamerr.Wrapf(iamerr.ErrAlreadyExists, "%s", uniqueText(pgErr, kindHint, idHint))
	case pgfault.ForeignKey: // foreign_key_violation
		// Признак берётся от `fkText`: он и только он знает, какая из двух
		// сторон ссылки нарушена. Обе вложены в ErrFailedPrecondition, поэтому
		// код отказа не меняется — меняется различимость.
		text, lane := fkText(pgErr, kindHint, idHint)
		return iamerr.Wrapf(lane, "%s", text)
	case pgfault.Check: // check_violation
		// Полоса ФОРМЫ ИМЕНИ отделена от прочих проверок, и отделена по вопросу
		// «чьё это значение» (задача #718, здесь — #1279).
		//
		// Форму имени iam проверяет САМ, до вставки: доменный newtype на каждом
		// из шести именуемых типов плюс подстановка умолчания на пути создания.
		//
		// Предикатов ЗДЕСЬ ДВА, и второй не украшение (задача #1903). Общий
		// (`pgfault.CheckLaneOf` → `nameform.IsConstraint`) опознаёт ограничение
		// ТОЧНЫМ сравнением `<таблица>_name_check`. У роли ограничений формы два,
		// по одному на ярус, и названы они иначе — конструкции они не отвечают и
		// потому не опознавались НИКОГДА.
		// Значит ограничение таблицы есть защита ПОСЛЕДНЕГО РУБЕЖА, и его
		// срабатывание означает не «вызывающий прислал негодное имя», а «сервис
		// пропустил негодное значение» — НАШ дефект. `INVALID_ARGUMENT` здесь
		// обвинял бы вызывающего в чужой ошибке и не давал бы ему ничего, что
		// можно исправить.
		if pgfault.CheckLaneOf(f) == pgfault.LaneServiceDefect || isRoleNameFormConstraint(f.Table, f.Constraint) {
			slog.Error("name form backstop fired: service admitted a name it validates itself",
				append([]any{"kind", kindHint, "id", idHint}, f.LogAttrs()...)...)
			return iamerr.ErrInternal
		}
		return iamerr.Wrapf(iamerr.ErrInvalidArg, "%s", checkText(pgErr))
	case pgfault.NotNull: // not_null_violation
		return iamerr.Wrapf(iamerr.ErrInvalidArg, "%s", notNullText(pgErr))
	case pgfault.Exclusion: // exclusion_violation
		// No EXCLUDE constraints in kacho_iam today; map generically WITHOUT
		// pgErr.Message (which would leak the constraint/range to the client).
		return iamerr.Wrapf(iamerr.ErrFailedPrecondition, "resource conflicts with an existing reservation")
	case pgfault.SerializationConflict: // serialization_failure
		// A transient write-write serialization conflict — the transaction can
		// succeed on retry. gRPC ABORTED is the idiomatic "retry the transaction"
		// code (FAILED_PRECONDITION would tell a well-behaved client NOT to retry,
		// contradicting the retryable nature). Unreachable under the current
		// READ COMMITTED regime (within-service invariants use single-statement
		// CAS / advisory locks / triggers, none of which raise 40001); mapped
		// correctly so a future SERIALIZABLE path surfaces a retryable code.
		// Текст называет ДЕЙСТВИЕ вызывающего, а не уровень изоляции СУБД:
		// «serialization» — термин нашего хранилища, и арендатор по нему сделать
		// не может ничего. Код (ABORTED) и смысл «повтори» сохранены дословно.
		return iamerr.Wrapf(iamerr.ErrAborted, "conflicting concurrent change, retry the request")
	}
	// connection family 08xxx
	if strings.HasPrefix(pgErr.Code, "08") {
		return iamerr.Wrapf(iamerr.ErrUnavailable, "database unavailable")
	}
	// Отказ ПРИНЯТЬ соединение, поднятый самим сервером (#666). Оба класса лежат
	// вне восьмого семейства, поэтому проверка выше их не ловила, и они уезжали в
	// `Internal` — то есть «сервис сломан» на состояние, которое проходит само за
	// секунды и повторяется успешно.
	//
	// Это не редкость и не край: пул строится без нижней границы, соединения
	// открываются лениво на первом обращении, готовности базы служебный бинарь не
	// ждёт — значит быстрый транзиторный отказ открытия в загрузочной буре
	// ожидаем ПО ПОСТРОЕНИЮ.
	switch pgErr.Code {
	case "53300": // too_many_connections — слоты сервера исчерпаны
		return iamerr.Wrapf(iamerr.ErrUnavailable, "database unavailable")
	case "57P03": // cannot_connect_now — сервер ещё поднимается
		return iamerr.Wrapf(iamerr.ErrUnavailable, "database unavailable")
	}
	// Unmapped SQLSTATE — never return the raw *pgconn.PgError: its Error()
	// carries table/constraint/column/SQLSTATE and would surface verbatim as the
	// gRPC INTERNAL message (data-integrity.md: no pgx leak, fixed INTERNAL text).
	// A new constraint that should produce a tenant-facing message must be added
	// to the constraint-aware switches above.
	//
	// КОД СОСТОЯНИЯ ОСТАЁТСЯ В ЦЕПОЧКЕ, и это не послабление утечки (#666).
	// Клиенту достаётся фиксированный текст: перевод sentinel'а в статус
	// заменяет сообщение `Internal` целиком. А журналу сервера без кода назвать
	// причину нечем вовсе — комментарии на этом пути обещают журналу деталь, и
	// обещание держится, только если деталь в цепочке ЕСТЬ. Пять символов кода
	// состояния разведки схемы не дают: ни имени таблицы, ни ограничения, ни
	// столбца, ни текста сервера здесь нет.
	return iamerr.Wrapf(iamerr.ErrInternal, "database error: sqlstate %s", pgErr.Code)
}

// isConnectionFailure — отказ, случившийся ДО того, как сервер что-либо сказал.
//
// Три формы, и каждая встречается в этом дереве: собственный тип драйвера
// (`ConnectError`), сетевая операция (`net.OpError` — так приходит «в
// соединении отказано») и закрытое драйвером соединение. Все три означают одно:
// повтор осмыслен, потому что состояние временное.
//
// Списком форм, а не «всё непонятное — недоступность»: корзина «прочее»
// обещала бы повтор там, где повторять нечего, и прятала бы настоящие поломки
// под кодом, который вызывающий обязан игнорировать.
func isConnectionFailure(err error) bool {
	var connErr *pgconn.ConnectError
	if stderrors.As(err, &connErr) {
		return true
	}
	var opErr *net.OpError
	if stderrors.As(err, &opErr) {
		return true
	}
	return stderrors.Is(err, pgconn.ErrConnClosed)
}

func uniqueText(pgErr *pgconn.PgError, kindHint, idHint string) string {
	switch pgErr.ConstraintName {
	case "accounts_name_unique":
		return fmt.Sprintf("Account with name %s already exists", idHint)
	// Имени `users_external_id_unique` в этом перечне НЕТ и заводить его не
	// надо: ни одна миграция такого ключа не создаёт. Оно стояло здесь и
	// молчало — ветвь, которую сервер не выберет никогда, выглядит покрытием и
	// им не является (гейт `TestRefusalTextNeverNamesARetiredConstraint`).
	//
	// users_active_external_id_uniq — глобальный частичный ключ 0011 по
	// (external_id) WHERE invite_status='ACTIVE'. Проигранная гонка
	// конкурентного первого входа (два входа одного внешнего субъекта)
	// приходит этим 23505.
	case "users_active_external_id_uniq",
		// users_identity_external_id_uniq — тот же предмет, но строго шире
		// (миграция 20260823050000): ключ накрывает и запрещённую строку, у
		// которой внешний субъект непуст по тому же CHECK. Отображается в ТОТ ЖЕ
		// текст намеренно: тон сообщения есть часть контракта, и вызывающему
		// безразлично, каким из двух ключей платформа держит одно и то же
		// свойство. Не добавив имя сюда, мы сменили бы контракт-тон на generic
		// МОЛЧА — отказ остался бы верным по коду и перестал бы называть предмет.
		"users_identity_external_id_uniq":
		return "User with external_id already exists"
	case "users_account_email_unique",
		// users_identity_email_uniq — глобальный ключ почты (миграция
		// 20260823050000). Пер-аккаунтный лежит рядом и остаётся законным
		// производителем этого же отказа, пока экспанд не свёрнут, поэтому
		// названы оба: перечень обязан покрывать КАЖДОГО производителя, иначе
		// непокрытый молча отвечает своей, отличимой формой.
		"users_identity_email_uniq":
		return "User with email already exists"
	case "projects_account_name_unique":
		return fmt.Sprintf("Project with name %s already exists", idHint)
	case "service_accounts_account_name_unique":
		return fmt.Sprintf("ServiceAccount with name %s already exists", idHint)
	case "groups_account_name_unique":
		return fmt.Sprintf("Group with name %s already exists", idHint)
	// `roles_custom_unique` здесь не стоит по той же причине: схема заводит
	// только системный ключ, а имя пользовательского не создаёт ни одна
	// миграция.
	case "roles_system_unique":
		return fmt.Sprintf("Role with name %s already exists", idHint)
	// Прежний частичный ключ `access_bindings_unique` (0001) снят миграцией
	// 0003 в пользу более сильного `access_bindings_active_grant_uniq`;
	// сервер его имени больше не назовёт.
	case "access_bindings_active_grant_uniq":
		// Подсказка от access_binding.Insert — единственного места, где под рукой
		// сразу субъект, область и роль. Разбирается общим splitBindingHint,
		// потому что ЭТУ ЖЕ строку читает ветвь FK по роли ниже и берёт из неё
		// СВОЁ поле: одна подсказка, три потребителя, каждый со своим слотом.
		if idHint != "" {
			if subj, scope, _ := splitBindingHint(idHint); scope != "" {
				return fmt.Sprintf("these permissions are already granted to %s on %s", subj, scope)
			}
			return fmt.Sprintf("these permissions are already granted to %s", idHint)
		}
		return "AccessBinding already exists"
	}
	if kindHint != "" && idHint != "" {
		return fmt.Sprintf("%s %s already exists", kindHint, idHint)
	}
	// Unmapped UNIQUE constraint — generic text; never leak pgErr.Message
	// (it embeds the constraint name → schema reconnaissance).
	return "resource with these attributes already exists"
}

// fkText — текст И ПРИЗНАК ПОЛОСЫ нарушения внешнего ключа.
//
// Возвращаются оба, потому что у одного ограничения ДВЕ противоположные
// стороны: ссылаемого ресурса нет (лечится созданием) — и ресурс ещё
// используется (лечится освобождением). Сторону знает вызывающий репозиторий и
// сообщает её подсказкой `<Ресурс>.<Глагол>`; на ней же построены все
// разобранные ветви ниже. Отдавать один текст на обе стороны, как было прежде,
// значит не восстанавливать следующий шаг ни в одном из двух случаев.
func fkText(pgErr *pgconn.PgError, kindHint, idHint string) (string, error) {
	switch pgErr.ConstraintName {
	case "accounts_owner_fk":
		// Direction-sensitive, как у четырёх соседей ниже. Ограничение объявлено
		// `ON DELETE RESTRICT`, поэтому оно срабатывает С ДВУХ сторон:
		//   INSERT account с несуществующим owner_user_id → «User <id> not found»
		//   DELETE user, ВЛАДЕЮЩЕГО аккаунтом              → «… owns accounts …»
		// Второе — состояние «ещё ссылаются», противоположное «ссылки нет». До
		// #2048 ветви не было вовсе: человек, которого только что вернул
		// `ListUsers`, получал утверждение о собственном отсутствии, а клиент,
		// ведущий состояние, снимал его строку у себя. Тон обеих сторон — часть
		// контракта (api-conventions.md §Error-format); код у них ОДИН
		// (`ErrFailedPrecondition`), различает их только сообщение.
		//
		// Полоса сужена до снятия ИМЕННО человека: это единственный глагол,
		// нарушающий `accounts_owner_fk` со стороны ссылающихся. Широкое «всякая
		// подсказка снятия» было бы неверно — снятие соседнего ресурса этого
		// ключа не касается.
		if kindHint == "User.Delete" {
			return fmt.Sprintf("User %s owns accounts and cannot be deleted", idHint), iamerr.ErrReferenceInUse
		}
		return fmt.Sprintf("User %s not found", idHint), iamerr.ErrReferenceMissing
	case "projects_account_fk":
		// Direction-sensitive:
		//   INSERT project with non-existent account_id → "Account <id> not found"
		//   DELETE account with dangling projects       → "Account <id> contains projects and cannot be deleted"
		// kindHint decides: "Account.Delete" → reverse direction; otherwise INSERT-side.
		if kindHint == "Account.Delete" {
			return fmt.Sprintf("Account %s contains projects and cannot be deleted", idHint), iamerr.ErrReferenceInUse
		}
		return fmt.Sprintf("Account %s not found", idHint), iamerr.ErrReferenceMissing
	case "service_accounts_account_fk":
		if kindHint == "Account.Delete" {
			return fmt.Sprintf("Account %s contains service accounts and cannot be deleted", idHint), iamerr.ErrReferenceInUse
		}
		return fmt.Sprintf("Account %s not found", idHint), iamerr.ErrReferenceMissing
	case "groups_account_fk":
		if kindHint == "Account.Delete" {
			return fmt.Sprintf("Account %s contains groups and cannot be deleted", idHint), iamerr.ErrReferenceInUse
		}
		return fmt.Sprintf("Account %s not found", idHint), iamerr.ErrReferenceMissing
	case "roles_account_fk":
		if kindHint == "Account.Delete" {
			return fmt.Sprintf("Account %s contains custom roles and cannot be deleted", idHint), iamerr.ErrReferenceInUse
		}
		return fmt.Sprintf("Account %s not found", idHint), iamerr.ErrReferenceMissing
	case "group_members_group_fk":
		return fmt.Sprintf("Group %s not found", idHint), iamerr.ErrReferenceMissing
	case "access_bindings_role_fk":
		// Direction-sensitive:
		//   INSERT binding with a non-existent role_id → "Role <id> not found"
		//   DELETE role still referenced by ANY binding row (23503) → A-16 text.
		// The FK RESTRICT fires on ANY child row regardless of its status (ACTIVE
		// or a soft-revoked-but-not-purged row from TransitionStatus), so the text
		// is deliberately NOT qualified with "active" — AccessBindingService.Delete
		// is a HARD delete (purges the row) which is what clears the precondition.
		if kindHint == "Role.Delete" {
			return "role is in use by access bindings", iamerr.ErrReferenceInUse
		}
		// Подсказка на INSERT-стороне приходит от access_binding.Insert и несёт
		// ТРИ поля. Прежде эта ветвь печатала её целиком, поэтому вызывающий
		// получал «Role <субъект>|project:<область> not found» — сообщение,
		// называющее сущности, о которых он не спрашивал, и НЕ называющее ту,
		// из-за которой отказ. Клиент уходил искать причину в субъекте и проекте.
		// Тексты отказов — часть контракта (api-conventions.md §Error-format),
		// поэтому берётся именно роль (issue #105).
		if _, _, role := splitBindingHint(idHint); role != "" {
			return fmt.Sprintf("Role %s not found", role), iamerr.ErrReferenceMissing
		}
		return fmt.Sprintf("Role %s not found", idHint), iamerr.ErrReferenceMissing
	// Здесь стояла ветвь `access_binding_conditions_condition_fk` — два текста,
	// называвших арендатору ресурс `Condition`. Его тенантская поверхность снята
	// ЦЕЛИКОМ (приёмка «ретайр тенантской поверхности условного доступа»), а
	// вместе с нею миграцией `0075` снесены обе таблицы и внешний ключ,
	// заведённый `0048`. Ветвь пережила свой предмет и стала неотличима от
	// исправной: сервер этого имени не назовёт никогда, поэтому ни один прогон
	// не мог покраснеть, а обещанный ею текст посылал клиента искать настройку
	// того, чего в продукте нет. Держит класс гейт
	// `TestRefusalTextNeverNamesARetiredConstraint`.

	// ТРИ ВЕТВИ НИЖЕ ПРИШЛИ ИЗ ЛИНИИ КАТАЛОГА (#1855) и переведены на форму с
	// признаком полосы. Полоса у всех трёх — сторона ССЫЛКИ
	// (`ErrReferenceMissing`), потому что ровно это говорит их текст: правило
	// назвало сегмент, которого в каталоге нет. Обе полосы вложены в
	// ErrFailedPrecondition, поэтому код отказа не изменился — изменилась
	// различимость.
	//
	// Обратная сторона (`ON DELETE/UPDATE NO ACTION` в миграции
	// 20260901113757: снятие или отзыв строки каталога, на которую ещё ссылается
	// правило) этими ветвями НЕ различается. Сегодня у неё нет производителя —
	// каталог заполняет только посев миграции, а глагол применения и отзыва
	// заведён задачей #1034, — поэтому ветвь без такого различения не
	// молчит о живом случае. Предмет назван, чтобы различение завели ВМЕСТЕ с
	// глаголом, а не после первого отказа не с той стороны.
	case "role_rule_ref_res_fk":
		// Сегмент называет ИМЯ ОГРАНИЧЕНИЯ, токен — подсказка писателя,
		// поставленная на его собственном операторе вставки (role_repo.go,
		// ReplaceRuleRefs). Ни то, ни другое НЕ берётся из pgErr.Detail: его этот
		// файл не читает намеренно (см. хвост функции — защита от разведки схемы).
		//
		// Поле названо во МНОЖЕСТВЕННОМ числе — `resources`, — потому что так оно
		// называется в теле запроса, которое прислал вызывающий, а не так, как
		// называется колонка таблицы.
		//
		// ТОН — предусловия, а не валидации: «Illegal argument …» принадлежит
		// INVALID_ARGUMENT, а эта полоса отвечает FAILED_PRECONDITION, и различие
		// кодов и есть доказательство, что отвечал ключ, а не грамматика.
		res, _ := splitRuleRefHint(idHint)
		if res != "" {
			return fmt.Sprintf("resources: %s is not a live platform resource", res), iamerr.ErrReferenceMissing
		}
		return "resources: rule names a resource that is not live in the platform catalog", iamerr.ErrReferenceMissing
	case "role_rule_ref_verb_fk":
		res, verb := splitRuleRefHint(idHint)
		if res != "" && verb != "" {
			return fmt.Sprintf("verbs: %s is not a live verb of resource %s", verb, res), iamerr.ErrReferenceMissing
		}
		return "verbs: rule names a verb that is not live for its resource", iamerr.ErrReferenceMissing
	case "role_verb_type_fk":
		// Проекция ГЛАГОЛОВ (role_verb) ссылается на живую строку каталога тем же
		// точечным написанием, каким её пишет `ReplaceRoleVerbs`. Подсказка там —
		// идентификатор роли, а не сегмент, поэтому текст называет предмет, а не
		// токен: иначе он назвал бы роль виновницей чужого отказа.
		return "resources: rule names a resource that is not live in the platform catalog", iamerr.ErrReferenceMissing
	case "access_binding_subjects_subject_ref":
		// Migration 0050 BEFORE DELETE trigger on users/service_accounts/groups: a
		// principal still referenced as a subjects[0..N] grantee
		// (access_binding_subjects) cannot be hard-deleted (SEC r8, hard-rule #10).
		// The trigger is the race backstop for the concurrent add-subject-vs-delete
		// window the software NOT EXISTS guard (a stale snapshot) cannot close; the
		// common case is already rejected with the same text by the guard's probe.
		// kindHint = "<Resource>.Delete" (set by the repo Delete) → canonical text.
		res := strings.TrimSuffix(kindHint, ".Delete")
		if res == "" {
			res = "Principal"
		}
		return fmt.Sprintf("%s %s has active access bindings and cannot be deleted", res, idHint), iamerr.ErrReferenceInUse
	}
	// Неразобранная связь. Текст общий — имя таблицы, колонки и значение из
	// `pgErr.Detail`/`Message` наружу НЕ идут (разведка схемы), — но состояние
	// называется ОДНО, а не два взаимоисключающих.
	//
	// Сторону выбирает глагол подсказки. Снятие строки — единственный способ
	// получить нарушение со стороны ссылающихся, и репозиторий его знает;
	// исполнимость этого различения держит гейт
	// `TestDeletingRepoMethodNamesItsKindHint`: метод, снимающий строку, обязан
	// подсказку передать. Всё прочее (вставка, правка) даёт сторону ссылки.
	//
	// Умолчание при пустой подсказке — сторона ССЫЛКИ, и выбрано оно не на глаз:
	// нарушение при вставке даёт любое создание с негодной ссылкой, тогда как
	// сторона снятия закрыта гейтом выше.
	if isDeletingHint(kindHint) {
		return "resource is still referenced by other resources; release those references before deleting it",
			iamerr.ErrReferenceInUse
	}
	return "referenced resource does not exist; create it or correct the reference before retrying",
		iamerr.ErrReferenceMissing
}

// isDeletingHint — глагол подсказки `<Ресурс>.<Глагол>` означает снятие строки.
// Перечень глаголов закрыт и совпадает с тем, что требует гейт подсказок:
// два места об одном предмете разошлись бы молча, поэтому оба читают ЭТУ
// функцию — гейт сверяет имена методов с нею же.
func isDeletingHint(kindHint string) bool {
	_, verb, ok := strings.Cut(kindHint, ".")
	if !ok {
		return false
	}
	return IsDeletingVerb(verb)
}

// IsDeletingVerb — глагол, снимающий строку. Экспортирован ради гейта подсказок
// (`TestDeletingRepoMethodNamesItsKindHint`), который обязан судить ТЕМ ЖЕ
// предикатом, каким судит рантайм: собственная копия перечня разошлась бы с
// этой молча и ровно там, где расхождение не видно.
func IsDeletingVerb(verb string) bool {
	// Сравнение по НАЧАЛУ, а не на равенство: глаголы уточняются («DeleteExpired»,
	// «DeleteOwnedByID», «RemoveMember»), и точное равенство объявляло бы
	// уточнённый глагол не снимающим — то есть отдавало бы клиенту текст чужой
	// стороны ровно там, где подсказка передана верно.
	for _, v := range []string{"Delete", "Remove", "Purge", "Drop"} {
		if strings.HasPrefix(verb, v) {
			return true
		}
	}
	return false
}

// integrityText — client-facing текст для 23000 (integrity_constraint_violation),
// поднятого явным RAISE триггера схемы.
//
// Подсказка приходит из `writeTx.Commit`: отложенный триггер срабатывает НА
// КОММИТЕ, и назвать человека с аккаунтом можно только тем, что писатель оставил
// в подсказке (`userWriter.RemoveMembership`).
// isMembershipCarriesRights — распознаватель ОДНОЙ полосы 23000, общий для
// текста и для признака.
//
// Один распознаватель, а не два похожих условия рядом: разъехавшись, они дали бы
// худший из исходов — отказ с текстом про выдачи и признаком другой полосы, то
// есть ответ, машинно заявляющий одно, а прозой другое.
func isMembershipCarriesRights(pgErr *pgconn.PgError, kindHint string) bool {
	return pgErr.ConstraintName == "membership_carrying_rights_is_kept" || kindHint == "Membership.Remove"
}

// integritySentinel — какой полосе принадлежит отказ 23000.
//
// Незнакомая связь остаётся общим предусловием: у неё нет потребителя, который
// умел бы что-то дочитать, и объявить её особой полосой значило бы обещать
// клиенту различение, за которым ничего не стоит.
func integritySentinel(pgErr *pgconn.PgError, kindHint string) error {
	if isMembershipCarriesRights(pgErr, kindHint) {
		return iamerr.ErrMembershipCarriesRights
	}
	return iamerr.ErrFailedPrecondition
}

// isGrantOnARetiredRole — распознаватель ВТОРОЙ полосы 23000: новая ссылка на
// снятую роль (#1913).
//
// Один распознаватель на текст и на признак, по тому же доводу, что у соседа
// выше: разъехавшись, они дали бы отказ, машинно заявляющий одно, а прозой
// другое.
//
// Подсказки вызывающего здесь НЕТ намеренно: имя связи ставит сам страж
// (`access_bindings_role_is_live_trg`, миграция 20260903223304), и оно приходит
// с сервера. Полоса, опирающаяся на подсказку, молчала бы у всякого писателя,
// который её не передал, — а писателей у выдачи больше одного.
func isGrantOnARetiredRole(pgErr *pgconn.PgError) bool {
	return pgErr.ConstraintName == "access_bindings_role_is_live"
}

func integrityText(pgErr *pgconn.PgError, kindHint, idHint string) string {
	if isGrantOnARetiredRole(pgErr) {
		// Роль называется, состояние называется, текст сервера НЕ эхается: в нём
		// имя ограничения и значения, то есть разведка схемы.
		return "Role is retired and cannot receive a new access binding"
	}
	if isMembershipCarriesRights(pgErr, kindHint) {
		user, account, _ := splitBindingHint(idHint)
		if user != "" && account != "" {
			return fmt.Sprintf("User %s still has active access bindings in Account %s and cannot be removed from it", user, account)
		}
		return "user still has active access bindings in this account and cannot be removed from it"
	}
	// Незнакомая связь — общий текст; сообщение сервера НИКОГДА не эхается
	// (в нём имя ограничения и значения → разведка схемы).
	return "resource state does not permit this operation"
}

// isRoleNameFormConstraint — ограничение ФОРМЫ ИМЕНИ РОЛИ, полоса дефекта
// сервиса (задача #1903).
//
// # Почему предикат ЗДЕСЬ, а не расширением общего
//
// Общий перечень (`pkg/validate/nameform`) описывает форму имени РЕСУРСА — DNS
// label по RFC 1123, одну на шесть схем, принявших канон. Имя роли ей не
// подчиняется: у него ДВЕ собственные формы по ярусу, и держат их два
// ограничения вместо одного. Расширение чужого пакета свело бы два разных
// предмета в один словарь, и следующая смена канона имени ресурса потянула бы
// за собой роль, которая к нему не относится.
//
// # Почему это НАШ дефект, а не ввод вызывающего
//
// Обе формы iam проверяет сам, до вставки: `RoleName.ValidateAtTier` — их
// зеркало, и зовётся оно из `Role.Validate`. Значит ограничение таблицы есть
// защита ПОСЛЕДНЕГО РУБЕЖА, и его срабатывание означает «сервис пропустил
// негодное значение». `INVALID_ARGUMENT` здесь обвинял бы вызывающего в чужой
// ошибке, а прежний текст вдобавок ВЫПИСЫВАЛ форму — то есть пережил бы её
// смену молча.
//
// Имя таблицы проверяется наравне с именем ограничения: имена ограничений
// уникальны в схеме, но сверка обеих координат не даёт полосе сработать на
// одноимённом ограничении чужой таблицы, если такое однажды заведут.
func isRoleNameFormConstraint(table, constraint string) bool {
	if table != "roles" {
		return false
	}
	return constraint == "roles_custom_name_check" || constraint == "roles_system_name_check"
}

func checkText(pgErr *pgconn.PgError) string {
	// Связей формы имени в этой таблице НЕТ намеренно: они отводятся раньше, в
	// ветке 23514, и отвечают фиксированным INTERNAL. Прежде здесь стояли две
	// записи, называвшие форму `^[a-z][-a-z0-9]{2,62}$`, — они пережили бы её
	// смену молча и посылали бы арендатора чинить имя по правилу, которого в
	// дереве нет (#1279).
	//
	// Ещё две записи стояли здесь до #1903 — обе формы имени РОЛИ, и обе
	// выписывали регулярку в текст арендатору. Утверждение выше было при них
	// ложным: комментарий говорил «связей формы имени НЕТ», а они лежали семью
	// строками ниже. Два места об одном предмете, из которых верно одно;
	// теперь верно оба — роль отводится в ветке 23514 вместе с остальными.
	switch pgErr.ConstraintName {
	case "accounts_description_check", "projects_description_check", "groups_description_check",
		"service_accounts_description_check", "roles_description_check":
		return "Illegal argument description: length must be <=256"
	case "accounts_labels_valid", "projects_labels_valid", "groups_labels_valid":
		return "Illegal argument labels: invalid key/value format or cardinality"
	case "users_email_check":
		return "Illegal argument email: invalid format"
	case "users_display_name_check":
		return "Illegal argument display_name: length must be <=128"
	case "users_external_id_check":
		return "Illegal argument external_id: length must be 1..256"
	case "access_bindings_target_resources_card_ck":
		// DB backstop for domain.MaxTargetResourcesPerBinding — the API rejects the
		// same input sync, so this text only surfaces for a writer that bypassed the
		// use-case. Kept byte-identical to the sync reject (contract tone).
		return "Illegal argument target.resources (must be 1..256)"
	case "role_rule_selectors_types_live":
		// ЕДИНСТВЕННАЯ ветвь этой функции, ОТДАЮЩАЯ ТЕКСТ ПРОИЗВОДИТЕЛЯ ДОСЛОВНО, —
		// и это решение, а не отступление от правила «сообщение сервера не эхается»
		// (задача продукта #2011).
		//
		// # Почему запрет сюда не распространяется
		//
		// Запрет ниже назван своей причиной: сообщение, СОСТАВЛЕННОЕ СЕРВЕРОМ, несёт
		// выражение ограничения, имя таблицы и значения строки — то есть разведку
		// схемы. Это сообщение сервер не составляет: его целиком пишет НАШ триггер
		// (`kacho_iam.role_rule_selector_types_live`, миграции 20260902174500 →
		// 20260903181000), и в нём ровно две величины, обе присланы самим
		// вызывающим:
		//
		//	object_types: <элемент массива> is not a live platform resource (role <роль>)
		//
		// Ничего о схеме там нет. Дискриминатор — ИМЯ ОГРАНИЧЕНИЯ, а его на `23514`
		// проставляет только `RAISE … USING CONSTRAINT`, то есть наш же триггер:
		// подделать эту ветвь чужим отказом нечем by construction.
		//
		// Прецедент того же вида — полоса учёта числа ресурсов выше (`KQ001`/`KQ002`):
		// её текст тоже сохраняется дословно и по тому же доводу — он и есть
		// контракт, а пересказ завёл бы второе место об одном предмете.
		//
		// # Почему текст не СОБИРАЕТСЯ здесь, как у соседних ветвей ключа
		//
		// Ветви `role_rule_ref_*_fk` собирают текст из подсказки писателя, потому что
		// писатель знает нарушенный сегмент. Здесь он его НЕ знает: страж судит
		// КАЖДЫЙ элемент массива и отвергает на первом негодном, а писатель подаёт
		// набор целиком. Собрать имя элемента на этой стороне можно было бы только
		// вторым запросом живости — то есть вторым словарём живости и
		// check-then-act (запрет #10) ради текста отказа.
		//
		// # Расхождение с соседом названо, а не сглажено
		//
		// Сосед по ключу отвечает `FAILED_PRECONDITION` (полоса ссылки), эта ветвь —
		// `INVALID_ARGUMENT`: страж стоит на ВХОДЕ записи, отвергает присланный
		// массив, и повтор того же входа годным его не сделает. Код здесь не
		// меняется — он контракт, и его смена была бы отдельным решением.
		//
		// Пустой текст производителя — вырожденный вход (его не бывает у `RAISE` с
		// форматом), но отдать пустую строку значило бы отказать БЕЗ СООБЩЕНИЯ:
		// `Wrapf(sentinel, "%s", "")` схлопывается в один sentinel, и вызывающий
		// получает код без единого слова о том, что править.
		if pgErr.Message == "" {
			return "Illegal argument object_types: rule names a resource that is not live in the platform catalog"
		}
		return pgErr.Message
	}
	// Unmapped CHECK — generic InvalidArgument text; never leak pgErr.Message
	// (it embeds the constraint expression/name → schema reconnaissance).
	return "Illegal argument: value violates a constraint"
}

// notNullText — client-facing text for 23502 (not_null_violation). The raw
// pgErr.ColumnName is deliberately NOT echoed: it is an internal schema
// identifier that differs from the public proto field name and aids schema
// reconnaissance (data-integrity.md: no pgx leak). A 23502 reaching the DB is
// normally caught earlier by domain validation, so a generic message suffices.
func notNullText(_ *pgconn.PgError) string {
	return "a required field is missing"
}

// splitBindingHint разбирает подсказку, которую составляет access_binding.Insert:
//
//	"<subject_id>|<resource_type>:<resource_id>|<role_id>"
//
// Одна строка — три потребителя, и каждый берёт СВОЙ слот: текст UNIQUE называет
// субъекта и область, ветвь FK по роли — роль. Прежде поля роли не было вовсе, и
// ветвь FK печатала всю строку в слот роли: вызывающий получал сообщение о
// сущностях, которых не называл, без той, из-за которой отказ (issue #105).
//
// Разбор устойчив к КОРОТКОЙ форме: подсказка без роли (двухполевая, как её писали
// раньше) и подсказка без разделителей вовсе не ломают ни одного потребителя —
// отсутствующие слоты возвращаются пустыми, а вызывающий сам решает, что делать
// с пустым. Это не запас на будущее, а требование совместимости: mapErr зовут из
// 190 мест, и не все они про выдачу.
func splitBindingHint(idHint string) (subject, scope, role string) {
	if idHint == "" {
		return "", "", ""
	}
	subject, rest, ok := strings.Cut(idHint, "|")
	if !ok {
		return idHint, "", ""
	}
	scope, role, _ = strings.Cut(rest, "|")
	return subject, scope, role
}
