// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// AssertionClientRepo — реестр клиентов, СПОСОБНЫХ доказать владение ключом
// (задача #898, приёмка F2 §2.9).
//
// # Почему таблицы две, а не три
//
// Клиентских таблиц в схеме три, но ключевой материал лежит только у двух.
// Третий вид — тот, через который человек входит интерактивно, — не располагает
// им BY CONSTRUCTION: колонок открытого ключа и алгоритма у него нет вовсе.
//
// Отсюда решение: разрешение идёт ТОЛЬКО по таблицам с ключевым материалом, и
// идентификатор третьего вида не резолвится ни во что. Формулировка «нашли
// строку, ключ пуст, отказ» потребовала бы, чтобы третья таблица участвовала в
// разрешении, — а значит, чтобы кто-то поддерживал в ней инвариант «ключа быть
// не должно». Инвариант, который надо поддерживать, ломается; инвариант,
// выраженный ОТСУТСТВИЕМ ТАБЛИЦЫ НА ПУТИ, — нет.
//
// Вторая причина весомее первой: различимость исходов «нашли, но без ключа» и
// «не нашли» есть ОРАКУЛ. Он сообщает предъявителю, существует ли клиент, а по
// нему устанавливают и то, каким видом он заведён.
//
// # Почему зеркальной колонки здесь нет
//
// В обеих таблицах есть колонка идентификатора клиента во внешнем сервере. На
// этом пути она НЕ УЧАСТВУЕТ — ни как второй ключ поиска, ни как запасной.
// Субъект, у которого два имени, даёт две записи журнала об одном действии и ДВА
// КЛЮЧА ОДНОКРАТНОСТИ на одно утверждение, то есть отменяет однократность,
// сохранив её форму. Колонка остаётся путём к прежнему эндпоинту и снимается
// вместе с ним.
type AssertionClientRepo struct {
	pool *pgxpool.Pool
}

// NewAssertionClientRepo — построитель.
func NewAssertionClientRepo(pool *pgxpool.Pool) *AssertionClientRepo {
	return &AssertionClientRepo{pool: pool}
}

// resolveAssertionClientQuery — ОДИН оператор на обе таблицы.
//
// Объединение, а не два последовательных чтения: два чтения дали бы два
// обращения к базе на пути аутентификации и — что важнее — РАЗНУЮ длительность
// у найденного в первой таблице и найденного во второй. Разница во времени
// ответа сама по себе есть оракул: по ней устанавливают вид клиента, ничего не
// зная о его существовании.
//
// Состояние владельца читается ТЕМ ЖЕ оператором. Внешнее соединение, а не
// внутреннее: строка клиента, чей владелец снят, обязана дать «владелец не
// активен», а не исчезнуть — исчезновение было бы неотличимо от «клиента нет»,
// и оба состояния получили бы один счётчик.
// Сужение адресатов читается ЗДЕСЬ, тем же оператором, что и всё остальное:
// выпуск принимает решение по строке реестра, и величина, приезжающая вторым
// обращением, разошлась бы с ней ровно в окне между двумя чтениями.
//
// У ветки пользовательского токена на её месте стоит ПУСТОЙ МАССИВ, и это не
// заглушка. Адресата такого токена проставляет сам сервис из своей настройки, а
// заказчик не вправе назвать его вовсе (решение Р2, `interactive_client.proto`);
// колонки нет, потому что нет автора значения. Пусто здесь означает «сужать
// нечем», а внешняя граница — перечень посадки — действует на обеих ветках
// одинаково. Появится у того ресурса поле адресатов — появится и колонка, и эта
// строка станет её чтением.
const resolveAssertionClientQuery = `
SELECT c.id, 'user', c.user_id, c.public_key_pem, c.key_algorithm, c.expires_at,
       COALESCE(u.invite_status = 'ACTIVE', FALSE), ARRAY[]::text[]
  FROM kaname.user_oauth_clients c
  LEFT JOIN kaname.users u ON u.id = c.user_id
 WHERE c.id = $1
UNION ALL
SELECT c.id, 'service_account', c.sva_id, c.public_key_pem, c.key_algorithm, c.expires_at,
       COALESCE(s.enabled, FALSE), c.declared_audiences
  FROM kaname.service_account_oauth_clients c
  LEFT JOIN kaname.service_accounts s ON s.id = c.sva_id
 WHERE c.id = $1
LIMIT 1`

// ResolveAssertionClient разрешает идентификатор в строку реестра.
//
// Нерезолвящийся идентификатор — `domain.ErrAssertionClientUnknown`, и он один
// на два состояния: строки нет вовсе, либо она принадлежит виду клиента, не
// способному к утверждению. Различать их наружу нельзя (оракул), а внутрь —
// незачем: исход один.
func (r *AssertionClientRepo) ResolveAssertionClient(ctx context.Context, clientID string) (domain.AssertionClient, error) {
	if clientID == "" {
		return domain.AssertionClient{}, domain.ErrAssertionClientUnknown
	}
	var (
		out       domain.AssertionClient
		kind      string
		expiresAt *time.Time
		audiences []string
	)
	err := r.pool.QueryRow(ctx, resolveAssertionClientQuery, clientID).Scan(
		&out.ID, &kind, &out.OwnerID, &out.PublicKeyPEM, &out.Algorithm, &expiresAt, &out.OwnerActive,
		&audiences,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.AssertionClient{}, domain.ErrAssertionClientUnknown
	}
	if err != nil {
		// Недоступность реестра — НЕ «клиента нет». Вызывающий обязан различать
		// эти два, иначе отказ базы читался бы как отсутствие клиента и
		// счётчик двигался бы не тот.
		return domain.AssertionClient{}, wrapPgErr(err, "AssertionClient", clientID)
	}
	out.Kind = domain.AssertionClientKind(kind)
	// Пустой массив читается как «сужения не объявлено» — состояние законное и
	// для ключа служебной учётки, выданного без перечня, и для клиента
	// пользовательского токена, у которого автора перечня нет вовсе.
	if len(audiences) > 0 {
		out.DeclaredAudiences = audiences
	}
	if expiresAt != nil {
		// Незаданный срок означает «бессрочно», и это законное состояние схемы:
		// колонка допускает NULL. Ноль здесь читается вызывающим именно так.
		out.ExpiresAt = expiresAt.Unix()
	}
	return out, nil
}
