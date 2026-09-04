// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg

// role_withdrawal_repo.go — ПРОИЗВОДИТЕЛЬ ОТЗЫВА роли модуля: переселение,
// снятие проекций и пометка.
//
// Приёмка `services/iam/docs/engineering/acceptance/role-withdrawal-has-a-producer.md`
// (APPROVED круга 4), §2.3, §2.5, §2.7, §2.9; задача продукта #1913.
//
// # Отзыв есть ОДНА транзакция из трёх шагов, и порядок держит КЛЮЧ
//
//  1. переселение строк `role_verb` и `role_rule_ref` в `role_grant_orphan` —
//     тем же оператором, каким их снимают. Ведомость и есть объяснение для
//     арендатора: без неё отобранное право неотличимо от никогда не выданного;
//  2. снятие проекций — все четыре названы ЯВНО, а не оставлены каскаду:
//     каскада здесь нет вовсе, строка роли остаётся;
//  3. пометка строки роли.
//
// Порядок между (2) и (3) держат ключи живости
// (`20260903220358_role_withdrawal_needs_liveness_keys.sql`): пометка роли, у
// которой осталась хоть одна живая проекция, отвергается `23503`. То есть шаг 3
// НЕВОЗМОЖЕН раньше шага 2 — это свойство схемы, а не памяти применителя
// (ban #10).
//
// # Ключ НЕ ПОВТОРЯЕТСЯ между отбором снимаемого и предикатом снятия
//
// Требование §2.7 выведено из ПРИЧИНЫ выигрыша, измеренной прибором стоимости
// (#1959): дорог был повтор ключа между отбором и снятием. Здесь снятие само
// стало отбором — `DELETE … RETURNING`, — и второй раз ключ не называется.
//
// # Сужение по ВЛАДЕЛЬЦУ, а не по системности
//
// Оператор пометки сужен `owner_module = $module`, а не только `is_system`.
// Разница не педантская: `is_system` истинно у ВСЕХ ролей манифеста и у всех
// платформенных сразу, поэтому сужение по нему одному допустило бы снятие
// платформенной роли манифестом, назвавшим её имя.
//
// # ВЕДОМОСТЬ отвечает ПОСЛЕДНЕЙ причиной
//
// Полоса снятия роли пишется `ON CONFLICT … DO UPDATE`: цикл «снять → вернуть →
// снять» обязан оставлять арендатору причину, автора и момент ПОСЛЕДНЕГО
// снятия, а не первого. Полоса КАТАЛОГА при этом не трогается — там `DO NOTHING`
// остаётся, и вопрос о ней вынесен остатком §9 Р10 приёмки.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
)

// roleRetirementCause — причина переселения, которой помечает свои строки полоса
// снятия РОЛИ. Значение объявлено ОДНИМ местом: разойдясь с оператором очистки,
// оно оставило бы оживлённой роли её же ведомость.
const roleRetirementCause = "role_retired"

// retireRoleVerbsSQL — ПЕРВАЯ популяция: снятие проекции глаголов и переселение
// снятого в ведомость ОДНИМ оператором.
//
// Литерал не разрезается ссылкой НАМЕРЕННО: гейт дерева
// `internal/repohygiene` `TestIAMRV112_RoleVerbProjectionHasASoleWriter`
// требует, чтобы строковый литерал, содержащий `DELETE FROM` проекции роли,
// содержал и `INSERT INTO kacho_iam.role_grant_orphan`. Снятие и переселение
// неделимы ровно тогда, когда стоят в одном операторе.
const retireRoleVerbsSQL = `
		WITH dropped AS (
		  DELETE FROM kacho_iam.role_verb rv
		   WHERE rv.role_id = $1
		  RETURNING rv.object_type, rv.verb
		), moved AS (
		  INSERT INTO kacho_iam.role_grant_orphan
		         (role_id, object_type, verb, source, cause, reason, applied_by)
		  SELECT $1, d.object_type, d.verb, 'role_verb', 'role_retired', $2, $3 FROM dropped d
		  ON CONFLICT (role_id, object_type, verb, source, cause) DO UPDATE
		     SET reason      = EXCLUDED.reason,
		         applied_by  = EXCLUDED.applied_by,
		         orphaned_at = now()
		)
		SELECT (SELECT count(*) FROM dropped)`

// retireRuleRefsSQL — ВТОРАЯ популяция: снятие проекции объявленных сегментов и
// переселение снятого ОДНИМ оператором.
//
// `verb` у якорной строки пуст (`NULL`), и в ведомости он записывается пустой
// строкой: там ключа нет, и пустая строка оставляет первичный ключ простым — та
// же семантика, что у полосы каталога.
const retireRuleRefsSQL = `
		WITH dropped AS (
		  DELETE FROM kacho_iam.role_rule_ref rr
		   WHERE rr.role_id = $1
		  RETURNING rr.module, rr.resource, rr.verb
		), moved AS (
		  INSERT INTO kacho_iam.role_grant_orphan
		         (role_id, object_type, verb, source, cause, reason, applied_by)
		  SELECT $1, d.module || '.' || d.resource, COALESCE(d.verb, ''), 'rule_ref',
		         'role_retired', $2, $3
		    FROM dropped d
		  ON CONFLICT (role_id, object_type, verb, source, cause) DO UPDATE
		     SET reason      = EXCLUDED.reason,
		         applied_by  = EXCLUDED.applied_by,
		         orphaned_at = now()
		)
		SELECT (SELECT count(*) FROM dropped)`

// LiveSystemRoles — живые системные роли, какими их видит ЭТА транзакция.
//
// Читается ВСЯ популяция, а не роли одного модуля: классификацию по владельцу
// делает сверка (`moduleroles.Reconcile`), и её перепись обязана называть чужие
// модули и роли без владельца отдельными числами. Сузив чтение здесь, мы отдали
// бы сверке множество, на котором эти числа тождественно нулевые, — то есть
// перепись стала бы всегда-зелёной.
//
// Снятые строки НЕ возвращаются: сверка отвечает на вопрос «что живёт, не
// будучи объявленным», и снятая роль на него отвечает «ничего».
func (w *roleWriter) LiveSystemRoles(ctx context.Context) ([]domain.Role, error) {
	q := fmt.Sprintf(`SELECT %s FROM roles WHERE is_system AND live ORDER BY id`, roleCols)
	rows, err := w.tx.Query(ctx, q)
	if err != nil {
		return nil, mapErr(err, "", "")
	}
	defer rows.Close()
	var out []domain.Role
	for rows.Next() {
		r, serr := scanRole(rows)
		if serr != nil {
			return nil, mapErr(serr, "", "")
		}
		out = append(out, r)
	}
	if rows.Err() != nil {
		return nil, mapErr(rows.Err(), "", "")
	}
	return out, nil
}

// RetireRole снимает роль модуля: переселяет её проекции в ведомость, снимает их
// и помечает строку — в транзакции ВЫЗЫВАЮЩЕГО.
//
// `ownerModule` сужает оператор пометки; `reason` и `actor` уезжают и в пометку,
// и в ведомость — арендатор читает их у отобранного права.
//
// Возвращает перепись. `Marked=false` означает, что оператор пометки не нашёл
// своей строки: роль уже снята либо владелец не тот, — и это НЕ отказ: повторное
// применение того же манифеста есть штатный режим.
func (w *roleWriter) RetireRole(ctx context.Context, id domain.RoleID, ownerModule, reason, actor string) (
	domain.RoleRetirement, error,
) {
	var out domain.RoleRetirement

	// ВЛАДЕНИЕ РЕШАЕТСЯ ОДИН РАЗ И ДО ПЕРВОЙ ЗАПИСИ — под замком строки.
	//
	// Различителей владения в этом дереве ДВА: сверка классифицирует роль по
	// приставке ИМЕНИ, оператор — по колонке `owner_module`. Связывает их только
	// `roles_owner_module_name_prefix`, и только в одну сторону («владелец непуст
	// ⇒ имя составлено из него»), поэтому строка с именем `vpc.*` и ПУСТЫМ
	// владельцем законна — и все строки, заведённые до `20260902190500`, такие.
	//
	// Пока сужение стояло только на пометке, расхождение давало худший исход из
	// возможных: проекции снимались, пометка не находила строки, применение
	// возвращало УСПЕХ. Роль оставалась ЖИВОЙ и не давала ничего — от исправной
	// не отличить, — а ведомость несла причину «роль снята» у живой роли, и
	// оживление её не вычистило бы никогда.
	//
	// Это НЕ check-then-act (ban #10): `FOR NO KEY UPDATE` держит строку до конца
	// транзакции, поэтому между этим вопросом и пометкой ни владение, ни живость
	// измениться не могут. Замок именно `FOR NO KEY UPDATE`, а не `FOR UPDATE`:
	// он ровно тот, который возьмёт сама пометка, и брать сильнее значило бы
	// сериализовать чужие чтения без предмета.
	//
	// ПУСТОЙ ВЛАДЕЛЕЦ ЧИТАЕТСЯ ПО ИМЕНИ — и это не послабление, а единственная
	// форма, при которой отзыв вообще возможен. Замер на свежем дереве: системных
	// ролей 48, с непустым `owner_module` — НОЛЬ, точечных без владельца — 44.
	// Колонка заведена `20260902190500` и обратного заполнения не несёт, а
	// проставляет её применитель ровно тем, что роль ОБЪЯВЛЕНА, — то есть у той
	// популяции, которую отзыв и снимает, она пуста by construction.
	//
	// Признак берётся ТОТ ЖЕ, которым классифицирует сверка (первый сегмент
	// имени): второй различитель владения и есть предмет находки. Платформенные
	// роли им не задеваются — `admin`, `edit`, `view`, `owner` точки не несут
	// вовсе, а первый сегмент `kacho-system.*` членом набора модулей не является,
	// поэтому равенству с именем модуля они не удовлетворяют ни при каком входе.
	var owned string
	err := w.tx.QueryRow(ctx, `
		SELECT id FROM kacho_iam.roles
		 WHERE id = $1
		   AND live
		   AND (owner_module = $2
		     OR (owner_module IS NULL AND split_part(name, '.', 1) = $2))
		 FOR NO KEY UPDATE`, string(id), ownerModule).Scan(&owned)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		// ОТКАЗ, а не тихий пропуск. «Роль уже снята» сюда не доходит: перечень
		// живых прочитан этой же транзакцией под этим же замком. Значит
		// единственная достижимая причина — роль принадлежит ДРУГОМУ модулю
		// (колонка называет чужого), и молчать о ней нельзя: молчание оставляет
		// роль без прав и с виду исправной.
		return out, iamerr.Wrapf(iamerr.ErrFailedPrecondition,
			"Role %s is not owned by module %s and cannot be retired by its manifest",
			id, ownerModule)
	case err != nil:
		return out, mapErr(err, "", string(id))
	}

	if err := w.tx.QueryRow(ctx, retireRoleVerbsSQL, string(id), reason, actor).
		Scan(&out.ResettledVerbs); err != nil {
		return out, mapErr(err, "", string(id))
	}
	if err := w.tx.QueryRow(ctx, retireRuleRefsSQL, string(id), reason, actor).
		Scan(&out.ResettledRuleRefs); err != nil {
		return out, mapErr(err, "", string(id))
	}

	// Третья и четвёртая проекции переселению не подлежат: у строки отбора нет
	// пары «тип + глагол», которой адресуются сироты, а состав цели —
	// материализация чужой выдачи. Снимаются они ЯВНО, потому что каскада здесь
	// нет: строка роли остаётся.
	tag, err := w.tx.Exec(ctx, `DELETE FROM kacho_iam.role_rule_selectors WHERE role_id = $1`,
		string(id))
	if err != nil {
		return out, mapErr(err, "", string(id))
	}
	out.RemovedSelectors = int(tag.RowsAffected())

	tag, err = w.tx.Exec(ctx,
		`DELETE FROM kacho_iam.access_binding_target_members WHERE role_id = $1`, string(id))
	if err != nil {
		return out, mapErr(err, "", string(id))
	}
	out.RemovedTargetMembers = int(tag.RowsAffected())

	// Пометка. Сужение по владельцу повторяется в предикате НАМЕРЕННО, хотя
	// замок выше уже его проверил: оператор обязан быть верным сам по себе, а не
	// по памяти о том, что кто-то спросил раньше. Ноль строк здесь означал бы,
	// что замок не удержал строку, — и это отказ, а не штатный исход.
	var marked string
	err = w.tx.QueryRow(ctx, `
		UPDATE kacho_iam.roles
		   SET live = false, retired_at = now(), retired_reason = $2, retired_by = $3
		 WHERE id = $1
		   AND live
		   AND (owner_module = $4
		     OR (owner_module IS NULL AND split_part(name, '.', 1) = $4))
		RETURNING id`, string(id), reason, actor, ownerModule).Scan(&marked)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return out, iamerr.Wrapf(iamerr.ErrFailedPrecondition,
			"Role %s changed under the retirement lock and was not marked", id)
	case err != nil:
		return out, mapErr(err, "", string(id))
	}
	out.Marked = true
	return out, nil
}

// ReviveRole оживляет снятую роль и снимает из ведомости строки СВОЕЙ причины —
// одним оператором.
//
// Оба действия неделимы намеренно: `withdrawn_grants` говорит настоящим временем
// «что у роли ОТОБРАНО», поэтому здоровая оживлённая роль с непустым списком
// утверждала бы о себе неправду. Строки причины «снят каталог» НЕ трогаются: они
// по-прежнему описывают действительность, и роль после оживления законно
// остаётся деградированной, если её сегменты не резолвятся.
//
// Возвращает `true`, когда строка ДЕЙСТВИТЕЛЬНО была снята и оживлена. Живая
// роль даёт `false` — это не отказ, а «оживлять нечего».
func (w *roleWriter) ReviveRole(ctx context.Context, id domain.RoleID) (bool, error) {
	var revived int
	err := w.tx.QueryRow(ctx, `
		WITH revived AS (
		  UPDATE kacho_iam.roles
		     SET live = true, retired_at = NULL, retired_reason = NULL, retired_by = NULL
		   WHERE id = $1 AND NOT live
		  RETURNING id
		), cleared AS (
		  DELETE FROM kacho_iam.role_grant_orphan o
		   WHERE o.role_id IN (SELECT id FROM revived)
		     AND o.cause = $2
		)
		SELECT (SELECT count(*) FROM revived)`, string(id), roleRetirementCause).Scan(&revived)
	if err != nil {
		return false, mapErr(err, "", string(id))
	}
	return revived > 0, nil
}

// Lifecycles — жизненное состояние каждой названной роли: объявлена она сегодня
// либо снята, и при каких обстоятельствах.
//
// Вопрос задаётся ОДИН на страницу, как у трёх соседей по этому пути чтения:
// стоимость обязана следовать СТРАНИЦЕ, величина которой ограничена контрактом,
// а не популяции ролей, не ограниченной ничем.
//
// Роль в ответе присутствует ВСЕГДА, если её строка существует, — и это отличие
// от соседей, где отсутствие ключа означает «пусто». Здесь пустого состояния не
// бывает: строка либо жива, либо снята, третьего не даёт `CHECK`. Отсутствие
// ключа означает «строки нет», и вызывающий, встретив его, оставляет нулевое
// состояние — «этим ответом не вычислено».
func (r *roleReader) Lifecycles(ctx context.Context, roleIDs []domain.RoleID) (
	map[domain.RoleID]domain.RoleLifecycle, error,
) {
	out := make(map[domain.RoleID]domain.RoleLifecycle, len(roleIDs))
	if len(roleIDs) == 0 {
		return out, nil
	}
	ids := make([]string, 0, len(roleIDs))
	for _, id := range roleIDs {
		ids = append(ids, string(id))
	}
	rows, err := r.tx.Query(ctx, `
		SELECT id, live, retired_at, retired_reason, retired_by
		  FROM kacho_iam.roles
		 WHERE id = ANY($1::text[])`, ids)
	if err != nil {
		return nil, mapErr(err, "", "")
	}
	defer rows.Close()
	for rows.Next() {
		var (
			id             string
			live           bool
			retiredAt      *time.Time
			reason, byWhom *string
		)
		if serr := rows.Scan(&id, &live, &retiredAt, &reason, &byWhom); serr != nil {
			return nil, mapErr(serr, "", "")
		}
		l := domain.RoleLifecycle{State: domain.RoleLifecycleDeclared}
		if !live {
			l.State = domain.RoleLifecycleWithdrawn
		}
		if retiredAt != nil {
			// Усечение до секунд — та же дисциплина, что у всех отметок времени в
			// ответах: микросекунды базы на провод не текут.
			l.RetiredAt = retiredAt.Truncate(time.Second)
		}
		if reason != nil {
			l.RetiredReason = *reason
		}
		if byWhom != nil {
			l.RetiredBy = *byWhom
		}
		out[domain.RoleID(id)] = l
	}
	if rerr := rows.Err(); rerr != nil {
		return nil, mapErr(rerr, "", "")
	}
	return out, nil
}
