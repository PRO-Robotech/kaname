// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package revocationpolicy — ОДНО правило «отсечка отзыва-всех человека
// запрещает полномочие, возникшее не позже неё», общее для всех полос
// удостоверений человека: чеканящих ему токен и принимающих его базовый секрет
// (задача kaname#379).
//
// # Почему общий источник, а не одинаковая проверка в каждой полосе
//
// Токен человеку выдают несколько полос: обратный вызов прежнего провайдера на
// выпуске, он же на обновлении и наш собственный токен-эндпоинт. Правило
// судит ЛЮБУЮ записанную отсечку владельца — каким бы действием, выводящим
// человека отовсюду, она ни была записана: строка на человека одна, и кто её
// пишет, правилу не важно и перечнем здесь не закрывается (перепись путей
// записи держит проба `client_token_revoke_all_integration_test.go`). Вопрос
// «вышел ли этот человек отовсюду после того, как возникло предъявленное
// полномочие» у всех полос ОДИН. Копия правила в каждой полосе разошлась бы
// молча: каждая полоса по отдельности выглядела бы исправной, неверной была бы
// их РАЗНИЦА. Здесь копия одна, и расхождение невозможно by construction — тот
// же приём, что у `audiencepolicy`.
// Одна здесь и обёртка предела времени на чтение отсечки отдельным запросом
// ([WithDeadline]): предел — тоже часть того, как полоса отвечает.
//
// Базовый секрет человека принимает полоса предъявления — резолв и вопрос о
// живости открытого соединения. Отсечку она читает тем же оператором, что
// строку удостоверения, а судит её тем же сравнением ([Forbids]) с якорем в
// момент выдачи строки — тем, что [Anchor] называет для долговременного
// удостоверения. Отдельного запроса отсечки у неё нет, поэтому и обёртки нет:
// предел у неё — предел самого оператора, поданный авторитету при построении
// той же величиной, которую корень подаёт обёртке.
//
// # Что здесь решается, а что — у вызывающего
//
// Решается ВЕРДИКТ: по принципалу, моменту его полномочия и отсечке. Что
// вызывающий делает с вердиктом — его дело и его словарь: хук отвечает
// провайдеру своим кодом и пишет свою причину в аудит, эндпоинт считает свой
// исход закрытого словаря. Словари разные, вердикт один.
package revocationpolicy

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/PRO-Robotech/kaname/internal/admission"
	"github.com/PRO-Robotech/kaname/internal/service"
)

// Lookup — отсечка отзыва-всех человека.
//
// Форма совпадает с портами полос дословно, и это требование, а не
// совпадение: каждая полоса подаёт сюда читатель одной и той же строки —
// адаптер одного типа, обёрнутый [WithDeadline] с одним объявленным пределом.
type Lookup interface {
	// UserRevokedBefore возвращает отсечку человека и признак её наличия.
	// Ошибка не сворачивается в «отсечки нет»: недоступное хранилище — не
	// ответ «нет».
	UserRevokedBefore(ctx context.Context, userID string) (time.Time, bool, error)
	// PersonMarks — второй вопрос правила (kaname#456, Р5): строки людей среди
	// названных идентификаторов и подтверждён ли их текущий адрес. Тот же
	// предикат допуска, что у двери решения и рубежа слушателей
	// (`admission`); своего чтения отметки у правила нет.
	admission.Marks
}

// Verdict — исход сверки. Закрытый словарь из ЧЕТЫРЁХ значений.
//
// Не двух: «выдавать», «не выдавать — человек вышел отовсюду», «не выдавать —
// адрес владельца-человека не подтверждён» и «не выдавать — ответить на
// вопрос нечем» чинятся разными людьми и разными действиями (войти заново
// против подтвердить адрес против починить хранилище), и слитый счётчик не
// сказал бы оператору, что чинить. Нулевое значение типа НЕ является ни одним
// из четырёх: вызывающий, получивший его, обязан отказать — это закрытый
// словарь, а не корзина «прочее».
type Verdict string

const (
	// Allowed — отсечка выдаче не мешает.
	Allowed Verdict = "allowed"
	// Revoked — полномочие возникло не позже отсечки: это и есть то, что
	// отсечка называет.
	Revoked Verdict = "revoked"
	// Undecidable — вопрос задать нечем либо не у кого: хранилище не ответило,
	// читатель не подан, принципал-человек не назван идентификатором. Отказ,
	// а не разрешение: правило авторитетно и закрывается на неизвестном. Не
	// ответивший о любом из двух вопросов — этот вердикт.
	Undecidable Verdict = "undecidable"
	// Unverified — владелец-человек с неподтверждённым адресом (kaname#456,
	// Р5): удостоверение человеку не выдаётся, пока адрес не подтверждён.
	Unverified Verdict = "unverified"
)

// Verdicts — закрытый словарь вердиктов, копией.
func Verdicts() []Verdict { return []Verdict{Allowed, Revoked, Undecidable, Unverified} }

// ErrNoLookup — читатель отсечки не подан.
var ErrNoLookup = errors.New("revocationpolicy: revoke-all cutoff reader is not wired")

// ErrUnknownPrincipalKind — вид принципала вне словаря [service.PrincipalKind].
var ErrUnknownPrincipalKind = errors.New("revocationpolicy: principal kind is outside the closed dictionary")

// ErrLimitNotPositive — предел на вызов, поданный обёртке, не положителен.
var ErrLimitNotPositive = errors.New("revocationpolicy: per-call limit must be a positive duration")

// ErrPrincipalWithoutID — принципал назван человеком, но без идентификатора,
// по которому отсечка ключуется.
var ErrPrincipalWithoutID = errors.New("revocationpolicy: principal is a person but carries no user id")

// Forbids — само сравнение: запрещает ли отсечка полномочие, возникшее в
// момент anchor.
//
// Граница включительна: полномочие, возникшее РОВНО в момент отсечки,
// запрещено — «не позже отсечки» и есть то, что она называет. Нулевой момент —
// запрет: полномочие, не назвавшее своего момента, нельзя показать возникшим
// после отсечки.
func Forbids(cutoff, anchor time.Time) bool {
	return anchor.IsZero() || !anchor.After(cutoff)
}

// Anchor — момент, от которого считается полномочие этого обмена.
//
// У долговременного удостоверения (ключ, персональный токен) это момент его
// выдачи: оно не переаутентифицируется, и выданное до отсечки есть ровно то,
// что «выйти отовсюду» обязано прекратить. У интерактивной сессии — её
// собственный момент аутентификации: человек, вошедший заново после отсечки,
// доказал себя снова, и это то, что не даёт отсечке стать вечной блокировкой.
// Нулевой результат означает, что обмен не назвал ни того, ни другого.
func Anchor(p service.ResolvedPrincipal, sessionAuthTime time.Time) time.Time {
	if p.StandingCredentialIssuedAt != nil {
		return *p.StandingCredentialIssuedAt
	}
	return sessionAuthTime
}

// AtIssuance — вердикт отсечки для выдачи токена этому принципалу.
//
// Вид принципала судится ЗАКРЫТЫМ словарём. Ключ служебной учётки — не сессия
// человека, а неразрешённый субъект не назван никем в этой службе: отсечка
// человека о них ничего не говорит, и читать её для них нечего. Для человека
// отсечка читается по его идентификатору в таблицах этой службы, а момент
// полномочия — по [Anchor]. Вид вне словаря — [Undecidable]: вид, заведённый
// позже рядом с тремя, иначе получал бы выдачу молча — тем же путём, что
// машина.
//
// Ошибка возвращается ровно при [Undecidable] и несёт причину для журнала;
// наружу она не выходит — это забота вызывающего.
func AtIssuance(ctx context.Context, cutoffs Lookup, p service.ResolvedPrincipal, sessionAuthTime time.Time) (Verdict, error) {
	switch p.Kind {
	case service.PrincipalServiceAccount, service.PrincipalUnresolved:
		return Allowed, nil
	case service.PrincipalUser:
	default:
		return Undecidable, fmt.Errorf("%w: %q", ErrUnknownPrincipalKind, p.Kind)
	}
	if cutoffs == nil {
		return Undecidable, ErrNoLookup
	}
	if p.UserID == "" {
		return Undecidable, ErrPrincipalWithoutID
	}
	cutoff, found, err := cutoffs.UserRevokedBefore(ctx, p.UserID)
	if err != nil {
		return Undecidable, fmt.Errorf("revocationpolicy: revoke-all cutoff lookup: %w", err)
	}
	if found && Forbids(cutoff, Anchor(p, sessionAuthTime)) {
		return Revoked, nil
	}
	return OwnerAdmission(ctx, cutoffs, p.UserID)
}

// OwnerAdmission — второй вопрос правила о владельце-человеке (kaname#456,
// Р5): подтверждён ли его текущий адрес. Allowed — подтверждён (либо
// идентификатор не называет строки человека); Unverified — не подтверждён;
// Undecidable — спросить не смогли. Полоса, судящая отсечку своим оператором
// (базовый секрет, хук обновления), спрашивает этот вопрос здесь же, а не
// копией.
func OwnerAdmission(ctx context.Context, marks admission.Marks, userID string) (Verdict, error) {
	if marks == nil {
		return Undecidable, ErrNoLookup
	}
	if userID == "" {
		return Undecidable, ErrPrincipalWithoutID
	}
	admitted, err := admission.ID(ctx, marks, userID)
	if err != nil {
		return Undecidable, fmt.Errorf("revocationpolicy: address mark lookup: %w", err)
	}
	if !admitted {
		return Unverified, nil
	}
	return Allowed, nil
}

// WithDeadline оборачивает читатель отсечки собственным пределом времени на
// КАЖДЫЙ вызов.
//
// Одна обёртка на все полосы, а не своя у каждой: чтение одной строки одним
// запросом, несущее разный предел в зависимости от полосы, — то же
// расхождение полос, которое этот пакет снимает для вердикта. Каждая сборка
// полос (токен-эндпоинт и хуки поставщика) оборачивает свой читатель ровно
// один раз этой функцией и объявленным пределом.
//
// Предел — у обёртки, а не у вызывающего: вызывающих у читателя больше одного,
// и предел, выставленный у каждого по отдельности, у одного из них рано или
// поздно не появится — молча. Истёкший предел — ошибка чтения, то есть
// [Undecidable], а не «отсечки нет».
//
// Неположительный предел — ОТКАЗ ПОСТРОЕНИЯ ([ErrLimitNotPositive]), а не
// обёртка: контекст с таким сроком истёк в момент вызова, каждое чтение
// кончалось бы ошибкой, и полоса отказывала бы в выдаче всем — на первом
// запросе, а не на старте. Предел судится раньше читателя: величина неверна
// независимо от того, что оборачивается.
//
// Неподанный читатель остаётся неподанным: обёртка над nil вернула бы
// непустое значение, и «читатель не провязан» перестал бы быть различимым.
func WithDeadline(inner Lookup, timeout time.Duration) (Lookup, error) {
	if timeout <= 0 {
		return nil, fmt.Errorf("%w, got %s", ErrLimitNotPositive, timeout)
	}
	if inner == nil {
		return nil, nil
	}
	return deadlineLookup{inner: inner, timeout: timeout}, nil
}

// deadlineLookup — чтение отсечки со СВОИМ пределом времени.
type deadlineLookup struct {
	inner   Lookup
	timeout time.Duration
}

func (d deadlineLookup) UserRevokedBefore(ctx context.Context, userID string) (time.Time, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()
	return d.inner.UserRevokedBefore(ctx, userID)
}

// PersonMarks — второй вопрос тем же пределом на вызов: чтение одной строки
// одним запросом, как и отсечка.
func (d deadlineLookup) PersonMarks(ctx context.Context, ids []string) (map[string]bool, error) {
	ctx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()
	return d.inner.PersonMarks(ctx, ids)
}
