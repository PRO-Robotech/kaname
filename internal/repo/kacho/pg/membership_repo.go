// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

// membership_repo.go — чтение принадлежности человека аккаунту.
//
// # НЕСУЩЕЕ СВОЙСТВО: аккаунт стоит в УСЛОВИИ ОТБОРА, а не в проверке после
//
// Оба запроса несут `m.account_id = $1` первым условием. Значит строк других
// аккаунтов они не читают ВОВСЕ — и различию неоткуда взяться ни в теле ответа,
// ни во времени его получения. Это сильнее проверки после чтения: проверку можно
// забыть в следующей ветке, а условие отбора забыть нельзя — без него запрос не
// соберётся.
//
// Отсюда же следует полоса ответа одиночного чтения: well-formed идентификатор
// членства ЧУЖОГО аккаунта даёт `ErrNotFound` не потому, что вызывающий проверен
// и отвергнут, а потому, что запрос эту строку не выбирает. Идентификатор
// членства вычислим посторонним из пары «человек × аккаунт», поэтому различимый
// ответ здесь был бы полным межаккаунтным оракулом — перебирать нечего, адрес
// строится арифметикой.
//
// # Имя аккаунта — зеркало, и оно читается СОЕДИНЕНИЕМ, а не вторым запросом
//
// Аккаунт живёт в той же БД, и ссылка на него — настоящий внешний ключ. Второй
// запрос за именем дал бы окно, в котором имя относится к другому моменту, чем
// строка членства, и заплатил бы за это обращением на каждую строку страницы.

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho-iam/internal/errors"
	"github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/membership"
)

// MembershipReader открывает чтение членств.
//
// Отдельный корень, а не метод общего `kacho.Reader`: см. `membership.Repo` —
// там названы и довод, и его цена.
func (r *Repository) MembershipReader(ctx context.Context) (membership.Session, error) {
	tx, err := r.readPool().BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	return &membershipSession{tx: tx}, nil
}

type membershipSession struct{ tx pgx.Tx }

func (s *membershipSession) Memberships() membership.ReaderIface { return &membershipReader{tx: s.tx} }
func (s *membershipSession) Close(ctx context.Context)           { _ = s.tx.Rollback(ctx) }

type membershipReader struct{ tx pgx.Tx }

// membershipCols — проекция ОДНА на оба чтения.
//
// Одиночное чтение и список отдают одно сообщение с одинаково заполненными
// полями, и держится это тем, что колонки объявлены один раз: расхождение
// проекций законно только там, где контракт назвал их разными, а он их разными
// не называет.
const membershipCols = `m.id, m.account_id, COALESCE(a.name, ''), m.user_id, m.state,
	COALESCE(m.invited_by, ''), m.created_at, m.updated_at`

// membershipFrom — источник строк обоих чтений.
const membershipFrom = `FROM memberships m JOIN accounts a ON a.id = m.account_id`

func scanMembership(row pgx.Row) (domain.Membership, error) {
	var m domain.Membership
	err := row.Scan(&m.ID, &m.AccountID, &m.AccountName, &m.UserID, &m.State,
		&m.InvitedBy, &m.CreatedAt, &m.UpdatedAt)
	return m, err
}

func (r *membershipReader) Get(
	ctx context.Context, accountID domain.AccountID, id domain.MembershipID,
) (domain.Membership, error) {
	if accountID == "" {
		// Пустой аккаунт означал бы «любой», то есть ровно межаккаунтное чтение.
		// Отказ здесь — не перестраховка: сигнатура требует аккаунт, и пустое
		// значение до запроса доходить не должно.
		return domain.Membership{}, iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument account_id")
	}
	q := fmt.Sprintf(`SELECT %s %s WHERE m.account_id = $1 AND m.id = $2`,
		membershipCols, membershipFrom)
	m, err := scanMembership(r.tx.QueryRow(ctx, q, string(accountID), string(id)))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// ОДИН И ТОТ ЖЕ текст для двух положений — «членство чужого аккаунта»
			// и «членства нет нигде», — и он подставляет ЗАПРОШЕННЫЙ
			// идентификатор, а не вырезанный и не внутреннее имя таблицы.
			// Различимый ответ выдал бы ровно то, что сужение отбора и
			// закрывает.
			return domain.Membership{}, iamerr.Wrapf(iamerr.ErrNotFound, "Membership %s not found", id)
		}
		return domain.Membership{}, mapErr(err, "", string(id))
	}
	return m, nil
}

func (r *membershipReader) List(
	ctx context.Context, f membership.ListFilter,
) ([]domain.Membership, string, error) {
	if f.AccountID == "" {
		return nil, "", iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument account_id")
	}
	// page_size вне [0..1000] ОТВЕРГАЕТСЯ, а не подрезается: молчаливое зажатие
	// отдаёт не ту страницу, о которой просили.
	pageSize, err := effectivePageSize(f.PageSize)
	if err != nil {
		return nil, "", err
	}

	conditions := []string{"m.account_id = $1"}
	args := []any{string(f.AccountID)}
	argIdx := 2

	// Белый список терма и объявленный оператор живут В ОДНОМ месте
	// (`membership.ParseListFilter`) и зовутся отсюда же: адаптер остаётся
	// авторитетным, а разбор не удваивается.
	ast, ferr := membership.ParseListFilter(f.Filter)
	if ferr != nil {
		return nil, "", ferr
	}
	if ast != nil {
		// Оператор уже проверен разбором; здесь применяется РАЗОБРАННЫЙ узел
		// целиком, а не одно его значение, — иначе оператор потерялся бы вместе
		// со значением.
		frag, fargs := ast.ToSQLOn(membership.FilterColumnUserID, argIdx)
		conditions = append(conditions, frag)
		args = append(args, fargs...)
		argIdx += len(fargs)
	}

	// Курсор. Разобранный имеет приоритет: путь, который его задаёт, токена не
	// передаёт вовсе — но порядок назван явно, чтобы это было свойством кода.
	switch {
	case f.After != nil:
		conditions = append(conditions,
			fmt.Sprintf("(m.created_at, m.id) > ($%d, $%d)", argIdx, argIdx+1))
		args = append(args, f.After.CreatedAt, f.After.ID)
		argIdx += 2
	case f.PageToken != "":
		ts, id, derr := decodePageToken(f.PageToken)
		if derr != nil {
			return nil, "", iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument page_token")
		}
		conditions = append(conditions,
			fmt.Sprintf("(m.created_at, m.id) > ($%d, $%d)", argIdx, argIdx+1))
		args = append(args, ts, id)
		argIdx += 2
	}

	// Порядок обхода — тот же, что у объявленного индекса
	// `memberships_account_cursor_idx (account_id, created_at, id)`: ведущее
	// равенство по аккаунту, за ним ключи курсора подряд и в согласованном
	// направлении.
	q := fmt.Sprintf(`SELECT %s %s WHERE %s ORDER BY m.created_at ASC, m.id ASC LIMIT $%d`,
		membershipCols, membershipFrom, strings.Join(conditions, " AND "), argIdx)
	args = append(args, pageSize+1)

	rows, err := r.tx.Query(ctx, q, args...)
	if err != nil {
		return nil, "", mapErr(err, "", "")
	}
	defer rows.Close()

	out := []domain.Membership{}
	for rows.Next() {
		m, serr := scanMembership(rows)
		if serr != nil {
			return nil, "", mapErr(serr, "", "")
		}
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, "", mapErr(err, "", "")
	}

	var nextToken string
	if int64(len(out)) > pageSize {
		last := out[pageSize-1]
		nextToken = encodePageToken(last.CreatedAt, string(last.ID))
		out = out[:pageSize]
	}
	return out, nextToken, nil
}
