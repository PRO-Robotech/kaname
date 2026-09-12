// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

// module_seed_writer.go — ЕДИНСТВЕННЫЙ писатель строк посева модуля в прод-коде
// (задача продукта #2452).
//
// # Почему писатель живёт РЯДОМ С КАТАЛОГОМ, а не на `kaname.Writer`
//
// Посев модуля — данные ПЛАТФОРМЫ, приезжающие доставкой манифестов, а
// `kaname.Writer` — писательская транзакция арендаторских ресурсов. Глагол
// «завести личность модуля» там был бы методом, который ни один арендаторский
// use-case не вправе позвать, — и он был бы у всех. Тот же довод записан у
// писателя каталога, и следовать ему здесь дешевле, чем заводить второе
// устройство об одном предмете.
//
// # Идентификаторы ВЫВОДЯТСЯ выражением базы, а не чеканятся заново
//
// Живая служебная запись модуля несёт `'sva' || substr(md5(<имя>), 1, 17)` — так
// её завела применённая миграция, и так её адресует сверка посева
// (`internal/moduleseedparity`). Применитель повторяет ТО ЖЕ выражение, поэтому
// установка, поднявшаяся заново, получает ТЕ ЖЕ идентификаторы, а не вторую
// личность рядом с первой.
//
// У группы такой производной нет: живые группы несут случайные идентификаторы.
// Поэтому её идемпотентность держит ограничение уникальности `(account_id,
// name)`, а не совпадение идентификатора, — и это сказано здесь, чтобы
// расхождение двух подразделов не читалось как недосмотр.
//
// # Отказы приходят СЫРЫМИ, и это решение
//
// Приведение к статусу (`mapErr`) здесь НЕ делается: оно сворачивает
// `*pgconn.PgError` в sentinel и теряет ИМЯ НАРУШЕННОГО ОГРАНИЧЕНИЯ, а именно
// оно и есть предмет разбора для оператора установки. Тот же довод — у писателя
// каталога.
//
// # Прямой факт отношения пишется ЖУРНАЛОМ, а не напрямую
//
// `kaname.relation_fact` складывает триггер `relation_fact_follows_journal` из
// строки `kaname.fga_outbox`. Писать факт в обход журнала значило бы завести
// второго производителя одной строки — и он разошёлся бы с первым молча, потому
// что оба кладут одно и то же на исправном входе.

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/PRO-Robotech/corelib/ids"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/moduleseed"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// ModuleSeedWriteRepo — исполнитель транзакций применителя посева над пулом.
type ModuleSeedWriteRepo struct {
	tx *coredb.Transactor
}

// NewModuleSeedWriteRepo собирает исполнителя транзакций поверх пула.
func NewModuleSeedWriteRepo(pool *pgxpool.Pool) *ModuleSeedWriteRepo {
	return &ModuleSeedWriteRepo{tx: coredb.NewTransactor(pool)}
}

// RunInWriteTx исполняет fn под ОДНОЙ писательской транзакцией: посев модуля
// ложится целиком либо не ложится вовсе.
func (r *ModuleSeedWriteRepo) RunInWriteTx(
	ctx context.Context,
	fn func(context.Context, moduleseed.Writer) error,
) error {
	return r.tx.InTx(ctx, func(tx pgx.Tx) error { return fn(ctx, moduleSeedWriter{tx: tx}) })
}

// moduleSeedWriter — `moduleseed.Writer` над одной транзакцией.
type moduleSeedWriter struct{ tx pgx.Tx }

// accountID резолвит аккаунт по имени и ОТКАЗЫВАЕТ, когда его нет.
//
// Отказ, а не пустой результат: вставка, чей `SELECT` не дал строк, прошла бы
// нулём затронутых строк и выглядела бы применённой. Это ровно тот класс, из-за
// которого заведена эта задача, — данные, объявленные и не доехавшие молча.
func (w moduleSeedWriter) accountID(ctx context.Context, name string) (string, error) {
	var id string
	err := w.tx.QueryRow(ctx, `SELECT id FROM kaname.accounts WHERE name = $1`, name).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("аккаунт %q не резолвится: %w", name, err)
	}
	return id, nil
}

// UpsertServiceAccount заводит личность модуля либо приводит её назначение.
func (w moduleSeedWriter) UpsertServiceAccount(
	ctx context.Context, account, name, description string,
) (bool, error) {
	accountID, err := w.accountID(ctx, account)
	if err != nil {
		return false, err
	}
	tag, err := w.tx.Exec(ctx, `
		INSERT INTO kaname.service_accounts (id, account_id, name, description, created_at, enabled, labels)
		VALUES ('`+domain.PrefixServiceAccount+`' || substr(md5($2), 1, 17), $1, $2, $3, now(), true, '{}')
		   ON CONFLICT (id) DO UPDATE
		      SET description = EXCLUDED.description
		    WHERE kaname.service_accounts.description IS DISTINCT FROM EXCLUDED.description`,
		accountID, name, description)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// UpsertGroup заводит группу модуля.
//
// Идентификатор чеканится продуктовым генератором, а не выводится из имени:
// живые группы несут случайные идентификаторы, и производная здесь завела бы
// ВТОРУЮ форму адресации той же сущности. Идемпотентность держит ограничение
// уникальности `(account_id, name)`.
func (w moduleSeedWriter) UpsertGroup(
	ctx context.Context, account, name, description string,
) (bool, error) {
	accountID, err := w.accountID(ctx, account)
	if err != nil {
		return false, err
	}
	tag, err := w.tx.Exec(ctx, `
		INSERT INTO kaname.groups (id, account_id, name, description, labels, created_at)
		VALUES ($1, $2, $3, $4, '{}', now())
		   ON CONFLICT ON CONSTRAINT groups_account_name_unique DO UPDATE
		      SET description = EXCLUDED.description
		    WHERE kaname.groups.description IS DISTINCT FROM EXCLUDED.description`,
		ids.NewID(domain.PrefixGroup), accountID, name, description)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// JoinGroup вводит служебную запись в группу и объявляет членство журналом.
func (w moduleSeedWriter) JoinGroup(
	ctx context.Context, saAccount, saName, groupAccount, groupName string,
) (bool, error) {
	saID, err := w.serviceAccountID(ctx, saAccount, saName)
	if err != nil {
		return false, err
	}
	groupID, err := w.groupID(ctx, groupAccount, groupName)
	if err != nil {
		return false, err
	}

	tag, err := w.tx.Exec(ctx, `
		INSERT INTO kaname.group_members (group_id, member_type, member_id, added_at)
		VALUES ($1, 'service_account', $2, now())
		   ON CONFLICT DO NOTHING`, groupID, saID)
	if err != nil {
		return false, err
	}
	if tag.RowsAffected() == 0 {
		// Членство уже стоит — журнал не пишется. Повторная строка журнала
		// заводила бы прямой факт заново на каждом старте: перепись росла бы, а
		// состояние — нет.
		return false, nil
	}
	if err := w.journal(ctx, "service_account:"+saID, "group:"+groupID, "member"); err != nil {
		return false, err
	}
	return true, nil
}

// GrantRelation выдаёт субъекту ИМЕНОВАННОЕ ОТНОШЕНИЕ на якоре области.
func (w moduleSeedWriter) GrantRelation(
	ctx context.Context, subject moduleseed.Subject, relation, scopeKind, scopeID string,
) (bool, error) {
	return w.grant(ctx, subject, grantForm{relation: relation}, scopeKind, scopeID)
}

// GrantRole выдаёт субъекту РОЛЬ на якоре области.
func (w moduleSeedWriter) GrantRole(
	ctx context.Context, subject moduleseed.Subject, roleID, scopeKind, scopeID string,
) (bool, error) {
	return w.grant(ctx, subject, grantForm{roleID: roleID}, scopeKind, scopeID)
}

// grantForm — какая из двух форм выдачи применяется. Взаимоисключающи: непусто
// ровно одно поле, и это требование формы, проверенное валидатором до
// применителя (`access_bindings_grant_form_ck` держит его же в схеме).
type grantForm struct {
	relation string
	roleID   string
}

// grant кладёт строку выдачи вместе с её дочерним субъектом, эмитированным
// кортежем и строкой журнала.
//
// # Идентификатор выдачи ВЫВОДИТСЯ тем же выражением, каким его вывела платформа
//
// `'acb' || substr(md5('system-grant:' || <субъект> || ':' || <форма> || ':' ||
// <вид> || ':' || <якорь>), 1, 17)` — ровно то выражение, которым системные
// выдачи заведены применённой миграцией. Повторять его здесь значит получать те
// же идентификаторы на той же паре (субъект, якорь), а не вторую выдачу рядом с
// первой.
//
// Названо и то, чего это НЕ обещает: якорь входит в выражение своим ЖИВЫМ
// написанием. Установка, пережившая переименование якоря, получит на этой выдаче
// другой идентификатор — выдача системная, защищена от удаления и по
// идентификатору снаружи не адресуется, поэтому цена названа и принята.
func (w moduleSeedWriter) grant(
	ctx context.Context, subject moduleseed.Subject, form grantForm, scopeKind, scopeID string,
) (bool, error) {
	subjectType, subjectID, err := w.subjectRef(ctx, subject)
	if err != nil {
		return false, err
	}

	formKey := form.relation
	if formKey == "" {
		formKey = "role:" + form.roleID
	}
	fgaUser := subjectType + ":" + subjectID

	var bindingID string
	err = w.tx.QueryRow(ctx, `
		SELECT 'acb' || substr(md5('system-grant:' || $1::text || ':' || $2::text
		                           || ':' || $3::text || ':' || $4::text), 1, 17)`,
		fgaUser, formKey, scopeKind, scopeID).Scan(&bindingID)
	if err != nil {
		return false, err
	}

	var roleID *string
	relation := form.relation
	if form.roleID != "" {
		roleID = &form.roleID
	}

	tag, err := w.tx.Exec(ctx, `
		INSERT INTO kaname.access_bindings (
		    id, subject_type, subject_id, role_id, granted_relation, is_system,
		    resource_type, resource_id, status, deletion_protection, granted_by_user_id)
		VALUES ($1, $2, $3, $4, $5, true, $6, $7, 'ACTIVE', true, '')
		   ON CONFLICT (id) DO NOTHING`,
		bindingID, subjectType, subjectID, roleID, relation, scopeKind, scopeID)
	if err != nil {
		return false, err
	}
	if tag.RowsAffected() == 0 {
		return false, nil
	}

	if _, err := w.tx.Exec(ctx, `
		INSERT INTO kaname.access_binding_subjects (binding_id, subject_type, subject_id, ordinal)
		VALUES ($1, $2, $3, 0)
		   ON CONFLICT DO NOTHING`, bindingID, subjectType, subjectID); err != nil {
		return false, err
	}

	// Эмитированный кортеж пишется только у формы ОТНОШЕНИЯ: у формы роли
	// кортежи производит проекция правил роли, и вписать здесь один значило бы
	// объявить за неё то, чего она ещё не решала.
	if relation != "" {
		if _, err := w.tx.Exec(ctx, `
			INSERT INTO kaname.access_binding_emitted_tuples (binding_id, fga_user, relation, object, source)
			VALUES ($1, $2, $3, $4, 'binding')
			   ON CONFLICT DO NOTHING`,
			bindingID, fgaUser, relation, scopeKind+":"+scopeID); err != nil {
			return false, err
		}
		if err := w.journal(ctx, fgaUser, scopeKind+":"+scopeID, relation); err != nil {
			return false, err
		}
	}
	return true, nil
}

// subjectRef переводит получателя выдачи в пару, которой его адресует хранилище.
func (w moduleSeedWriter) subjectRef(
	ctx context.Context, subject moduleseed.Subject,
) (subjectType, subjectID string, err error) {
	switch subject.Kind {
	case "serviceAccount":
		id, err := w.serviceAccountID(ctx, subject.Account, subject.Name)
		return "service_account", id, err
	case "group":
		id, err := w.groupID(ctx, subject.Account, subject.Name)
		return "group", id, err
	default:
		return "", "", fmt.Errorf("%w: %q", moduleseed.ErrUnknownSubjectType, subject.Kind)
	}
}

// serviceAccountID резолвит служебную запись ПАРОЙ (аккаунт, имя) и отказывает,
// когда её нет.
func (w moduleSeedWriter) serviceAccountID(ctx context.Context, account, name string) (string, error) {
	var id string
	err := w.tx.QueryRow(ctx, `
		SELECT sa.id FROM kaname.service_accounts sa
		  JOIN kaname.accounts a ON a.id = sa.account_id
		 WHERE a.name = $1 AND sa.name = $2`, account, name).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("служебная запись %s/%s не резолвится: %w", account, name, err)
	}
	return id, nil
}

// groupID резолвит группу ПАРОЙ (аккаунт, имя) и отказывает, когда её нет.
//
// Отказ здесь несёт свой предмет: группа, в которую вступает модуль, ему НЕ
// принадлежит — её заводит служба, а модуль лишь заявляет членство. Значит
// «группы нет» есть состояние установки, а не ошибка манифеста, и текст обязан
// назвать пару, чтобы оператор искал не в манифесте.
func (w moduleSeedWriter) groupID(ctx context.Context, account, name string) (string, error) {
	var id string
	err := w.tx.QueryRow(ctx, `
		SELECT g.id FROM kaname.groups g
		  JOIN kaname.accounts a ON a.id = g.account_id
		 WHERE a.name = $1 AND g.name = $2`, account, name).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("группа %s/%s не резолвится: %w", account, name, err)
	}
	return id, nil
}

// journal кладёт строку журнала прав. Прямой факт отношения складывает из неё
// триггер `relation_fact_follows_journal`.
//
// Приведения `::text` у параметров ОБЯЗАТЕЛЬНЫ и сняты быть не могут:
// `jsonb_build_object` объявляет свои доводы как `"any"`, поэтому тип параметра
// вывести неоткуда, и без приведения вставка отказывает `42P18` — а отказ
// приходит из подготовки оператора, то есть раньше любого условия внутри.
func (w moduleSeedWriter) journal(ctx context.Context, user, object, relation string) error {
	_, err := w.tx.Exec(ctx, `
		INSERT INTO kaname.fga_outbox (event_type, payload, created_at)
		VALUES ('fga.tuple.write',
		        jsonb_build_object('user', $1::text, 'object', $2::text, 'relation', $3::text),
		        now())`, user, object, relation)
	return err
}
