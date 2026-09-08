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
	"github.com/PRO-Robotech/kaname/internal/service"
)

// TrustedIssuerRepo — НАШ перечень доверенных издателей утверждения (#1124).
//
// # Почему разрешение идёт ОДНИМ оператором
//
// Тот же довод, что у реестра клиентов: два чтения дали бы разную длительность
// ответа у пары, дошедшей до второго, и у пары, отвергнутой на первом. Разница
// во времени ответа сама по себе есть оракул — по ней устанавливают, доверен ли
// издатель, ничего не отвечая по существу.
//
// # Почему состояние владельца читается ЭТИМ ЖЕ оператором
//
// Внешнее соединение, а не внутреннее: запись доверия, чья служебная учётная
// запись снята, обязана дать «владелец не активен», а не исчезнуть.
// Исчезновение было бы неотличимо от «доверия нет», и оба состояния получили бы
// один счётчик.
type TrustedIssuerRepo struct {
	pool *pgxpool.Pool
}

// NewTrustedIssuerRepo — построитель.
func NewTrustedIssuerRepo(pool *pgxpool.Pool) *TrustedIssuerRepo {
	return &TrustedIssuerRepo{pool: pool}
}

// resolveTrustedIssuerQuery — разрешение пары в запись доверия и в строку,
// которую она уполномочивает.
//
// Отбора по сроку доверия здесь НЕТ намеренно: истечение решает проверяющий, и
// у него на это свой исход со своим счётчиком. Отсеки мы истёкшее оператором —
// «доверия не было» и «доверие кончилось» стали бы неразличимы, и снятие
// доверия сроком перестало бы быть наблюдаемым событием эксплуатации.
const resolveTrustedIssuerQuery = `
SELECT t.sa_oauth_client_id, t.issuer, t.subject, t.public_key_pem, t.key_algorithm, t.expires_at,
       c.sva_id, c.expires_at,
       COALESCE(s.enabled, FALSE)
  FROM kaname.federated_trusted_issuers t
  JOIN kaname.service_account_oauth_clients c ON c.id = t.sa_oauth_client_id
  LEFT JOIN kaname.service_accounts s ON s.id = c.sva_id
 WHERE t.issuer = $1 AND t.subject = $2`

// ResolveTrustedIssuer разрешает пару (издатель, субъект) в запись перечня и в
// нашу строку федеративного ключа.
//
// Пары нет → domain.ErrTrustedIssuerUnknown. ОДИН признак на все состояния «мы
// за это не ручаемся»: записи нет · доверие выдано другому субъекту · строка,
// которую доверие уполномочивало, снята каскадом. Различимые исходы дали бы
// предъявителю оракул состава перечня.
func (r *TrustedIssuerRepo) ResolveTrustedIssuer(ctx context.Context, issuer, subject string) (
	domain.TrustedIssuer, domain.AssertionClient, error,
) {
	var (
		trust            domain.TrustedIssuer
		ownerID          string
		trustExpires     *time.Time
		clientExpires    *time.Time
		ownerActiveState bool
	)
	err := r.pool.QueryRow(ctx, resolveTrustedIssuerQuery, issuer, subject).Scan(
		&trust.ClientID, &trust.Issuer, &trust.Subject,
		&trust.PublicKeyPEM, &trust.Algorithm, &trustExpires,
		&ownerID, &clientExpires,
		&ownerActiveState,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.TrustedIssuer{}, domain.AssertionClient{}, domain.ErrTrustedIssuerUnknown
	}
	if err != nil {
		// Недоступность перечня НЕ маскируется под «не доверен»: у неё свой
		// исход и своё поведение — отказ, который вызывающий вправе повторить.
		return domain.TrustedIssuer{}, domain.AssertionClient{}, mapErr(err, "TrustedIssuer.Resolve", issuer)
	}
	if trustExpires != nil {
		trust.ExpiresAt = trustExpires.Unix()
	}
	client := domain.AssertionClient{
		ID:      trust.ClientID,
		Kind:    domain.AssertionClientServiceAccount,
		OwnerID: ownerID,
		// Ключевого материала у федеративной строки нет by construction:
		// подпись проверяется ключом ИЗДАТЕЛЯ, взятым из записи доверия.
		OwnerActive: ownerActiveState,
	}
	if clientExpires != nil {
		client.ExpiresAt = clientExpires.Unix()
	}
	return trust, client, nil
}

// InsertTrustedIssuers записывает перечень доверенных издателей выдаваемого
// ключа в транзакции ВЫЗЫВАЮЩЕГО.
//
// # Почему в его транзакции, а не своим обращением
//
// Строка ключа и её перечень — один предмет: ключ без перечня не примет никого,
// перечень без ключа доверяет постороннему от имени того, кого нет. Записанные
// двумя обращениями, они разъезжаются на отказе между ними, и разъезжаются в
// сторону, которую никто не увидит: выдача ответит успехом.
//
// Пустой перечень сюда не доходит: федеративной полосу делает именно непустой
// перечень, и вызывающий разводит полосы по нему. Отдельная проверка здесь была
// бы вторым местом об одном предмете — но и молча принять пустой ввод нельзя,
// поэтому он отвергается явно.
func (r *TrustedIssuerRepo) InsertTrustedIssuers(
	ctx context.Context,
	txh service.Tx,
	clientID domain.SAOAuthClientID,
	subjects []domain.TrustedSubject,
	expiresAt *time.Time,
) error {
	if len(subjects) == 0 {
		return errors.New("trusted issuers: an empty list means 'trust nobody' and is never written as one")
	}
	tx := txAsPgx(txh)
	const q = `
		INSERT INTO kaname.federated_trusted_issuers (
		    issuer, subject, sa_oauth_client_id, public_key_pem, key_algorithm, expires_at
		) VALUES ($1, $2, $3, $4, $5, $6)`
	for _, ts := range subjects {
		literal, ok := ts.LiteralSubject()
		if !ok {
			// Защитно: форма проверена доменом. Молчаливый пропуск дал бы
			// строку ключа, чей перечень короче названного, — то есть тихо
			// иной предмет доверия.
			return errors.New("trusted issuers: subject pattern is not a literal anchored subject")
		}
		if _, err := tx.Exec(ctx, q,
			ts.Issuer, literal, string(clientID), ts.PublicKeyPEM, ts.KeyAlgorithm,
			nullableTimePtr(expiresAt),
		); err != nil {
			// Занятая пара — не наша неисправность, а состояние: доверие этой
			// паре уже выдано другой строкой. Отображение SQLSTATE делает
			// общий mapErr, и вызывающий получает ALREADY_EXISTS вместо
			// INTERNAL.
			return mapErr(err, "TrustedIssuer.Insert", ts.Issuer)
		}
	}
	return nil
}
