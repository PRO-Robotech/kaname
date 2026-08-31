// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

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

	"github.com/PRO-Robotech/kacho/pkg/db/pgfault"
	"github.com/PRO-Robotech/kacho/pkg/quota/quotadetail"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
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
		// Единственный производитель в дереве — отложенный триггер
		// `membership_carrying_rights_is_kept` (миграция 472002): членство,
		// несущее живую выдачу в своём аккаунте, снять нельзя. Предикат:
		// `git grep -n integrity_constraint_violation -- '*.sql'` → одно попадание.
		//
		// Класс отображается в FAILED_PRECONDITION целиком, а не одной этой
		// связью: `integrity_constraint_violation` по определению есть
		// «состояние ресурса не позволяет», а не поломка сервиса. Текст при этом
		// берётся НЕ из сообщения сервера — оно диагностика хранилища, — а из
		// таблицы связей ниже, и незнакомая связь получает общий текст без утечки.
		//
		// Признак ВЫБИРАЕТСЯ вместе с текстом, а не ставится общим на весь класс:
		// у отказа «членство несёт права» есть потребитель, дочитывающий перечень
		// мешающих выдач, и отличить эту полосу от прочих предусловий он обязан
		// машинно (см. `iamerr.ErrMembershipCarriesRights`).
		return iamerr.Wrapf(integritySentinel(pgErr, kindHint), "%s", integrityText(pgErr, kindHint, idHint))
	case pgfault.Unique: // unique_violation
		return iamerr.Wrapf(iamerr.ErrAlreadyExists, "%s", uniqueText(pgErr, kindHint, idHint))
	case pgfault.ForeignKey: // foreign_key_violation
		return iamerr.Wrapf(iamerr.ErrFailedPrecondition, "%s", fkText(pgErr, kindHint, idHint))
	case pgfault.Check: // check_violation
		// Полоса ФОРМЫ ИМЕНИ отделена от прочих проверок, и отделена по вопросу
		// «чьё это значение» (задача #718, здесь — #1279).
		//
		// Форму имени iam проверяет САМ, до вставки: доменный newtype на каждом
		// из шести именуемых типов плюс подстановка умолчания на пути создания.
		// Значит ограничение таблицы есть защита ПОСЛЕДНЕГО РУБЕЖА, и его
		// срабатывание означает не «вызывающий прислал негодное имя», а «сервис
		// пропустил негодное значение» — НАШ дефект. `INVALID_ARGUMENT` здесь
		// обвинял бы вызывающего в чужой ошибке и не давал бы ему ничего, что
		// можно исправить.
		if pgfault.CheckLaneOf(f) == pgfault.LaneServiceDefect {
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
		return iamerr.Wrapf(iamerr.ErrAborted, "serialization conflict, retry")
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
	case "users_external_id_unique",
		// users_active_external_id_uniq — глобальный частичный ключ 0011 по
		// (external_id) WHERE invite_status='ACTIVE'. Проигранная гонка
		// конкурентного первого входа (два входа одного внешнего субъекта)
		// приходит этим 23505.
		"users_active_external_id_uniq",
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
	case "roles_custom_unique", "roles_system_unique":
		return fmt.Sprintf("Role with name %s already exists", idHint)
	case "access_bindings_unique",
		"access_bindings_active_grant_uniq":
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

func fkText(pgErr *pgconn.PgError, kindHint, idHint string) string {
	switch pgErr.ConstraintName {
	case "accounts_owner_fk":
		return fmt.Sprintf("User %s not found", idHint)
	case "projects_account_fk":
		// Direction-sensitive:
		//   INSERT project with non-existent account_id → "Account <id> not found"
		//   DELETE account with dangling projects       → "Account <id> contains projects and cannot be deleted"
		// kindHint decides: "Account.Delete" → reverse direction; otherwise INSERT-side.
		if kindHint == "Account.Delete" {
			return fmt.Sprintf("Account %s contains projects and cannot be deleted", idHint)
		}
		return fmt.Sprintf("Account %s not found", idHint)
	case "service_accounts_account_fk":
		if kindHint == "Account.Delete" {
			return fmt.Sprintf("Account %s contains service accounts and cannot be deleted", idHint)
		}
		return fmt.Sprintf("Account %s not found", idHint)
	case "groups_account_fk":
		if kindHint == "Account.Delete" {
			return fmt.Sprintf("Account %s contains groups and cannot be deleted", idHint)
		}
		return fmt.Sprintf("Account %s not found", idHint)
	case "roles_account_fk":
		if kindHint == "Account.Delete" {
			return fmt.Sprintf("Account %s contains custom roles and cannot be deleted", idHint)
		}
		return fmt.Sprintf("Account %s not found", idHint)
	case "group_members_group_fk":
		return fmt.Sprintf("Group %s not found", idHint)
	case "access_bindings_role_fk":
		// Direction-sensitive:
		//   INSERT binding with a non-existent role_id → "Role <id> not found"
		//   DELETE role still referenced by ANY binding row (23503) → A-16 text.
		// The FK RESTRICT fires on ANY child row regardless of its status (ACTIVE
		// or a soft-revoked-but-not-purged row from TransitionStatus), so the text
		// is deliberately NOT qualified with "active" — AccessBindingService.Delete
		// is a HARD delete (purges the row) which is what clears the precondition.
		if kindHint == "Role.Delete" {
			return "role is in use by access bindings"
		}
		// Подсказка на INSERT-стороне приходит от access_binding.Insert и несёт
		// ТРИ поля. Прежде эта ветвь печатала её целиком, поэтому вызывающий
		// получал «Role <субъект>|project:<область> not found» — сообщение,
		// называющее сущности, о которых он не спрашивал, и НЕ называющее ту,
		// из-за которой отказ. Клиент уходил искать причину в субъекте и проекте.
		// Тексты отказов — часть контракта (api-conventions.md §Error-format),
		// поэтому берётся именно роль (issue #105).
		if _, _, role := splitBindingHint(idHint); role != "" {
			return fmt.Sprintf("Role %s not found", role)
		}
		return fmt.Sprintf("Role %s not found", idHint)
	case "access_binding_conditions_condition_fk":
		// Direction-sensitive (migration 0048 — DB-level Condition reference):
		//   INSERT attach row with a non-existent condition_id → "Condition <id> not found"
		//   DELETE Condition still referenced by ANY attach row (23503 RESTRICT) → in-use text.
		// ConditionsCRUDService.Delete passes kindHint "Condition.Delete"; this
		// FK is what closes the delete-vs-attach TOCTOU (the software refcheck is
		// only a best-effort early message).
		if kindHint == "Condition.Delete" {
			return "condition is in use by access bindings"
		}
		return fmt.Sprintf("Condition %s not found", idHint)
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
		return fmt.Sprintf("%s %s has active access bindings and cannot be deleted", res, idHint)
	}
	// Unmapped FK — generic text; never leak pgErr.Detail/Message (they embed
	// the referenced table/column/value → schema reconnaissance).
	return "referenced resource not found or still in use"
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

func integrityText(pgErr *pgconn.PgError, kindHint, idHint string) string {
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

func checkText(pgErr *pgconn.PgError) string {
	// Связей формы имени в этой таблице НЕТ намеренно: они отводятся раньше, в
	// ветке 23514, и отвечают фиксированным INTERNAL. Прежде здесь стояли две
	// записи, называвшие форму `^[a-z][-a-z0-9]{2,62}$`, — они пережили бы её
	// смену молча и посылали бы арендатора чинить имя по правилу, которого в
	// дереве нет (#1279).
	switch pgErr.ConstraintName {
	case "accounts_description_check", "projects_description_check", "groups_description_check",
		"service_accounts_description_check", "roles_description_check":
		return "Illegal argument description: length must be <=256"
	case "accounts_labels_valid", "projects_labels_valid", "groups_labels_valid":
		return "Illegal argument labels: invalid key/value format or cardinality"
	case "roles_custom_name_check":
		return "Illegal argument name: must match ^[a-z][a-z0-9_]{0,40}$ (custom role)"
	case "roles_system_name_check":
		return "Illegal argument name: must match ^roles/[a-z]+\\.[a-z]+$ (system role)"
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
