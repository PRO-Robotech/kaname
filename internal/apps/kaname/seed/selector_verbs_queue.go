// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package seed

// selector_verbs_queue.go — пересчёт ОЧЕРЕДИ глаголов правил (kaname#878).
//
// # Окно, которое очередь закрывает
//
// Роль в очереди `kaname.role_selector_verbs_pending` несёт на строках
// селекторов ВЕРХНЮЮ ГРАНИЦУ глаголов правил — объединение по роли (заполнение
// миграцией 20261018030000) либо живые глаголы типа (досев селекторов
// системной роли, переходный страж схемы для писателя прежней версии). Решение о
// доступе по такой роли — прежнее, «по роли»: глагол одного правила сочетается с
// охватом другого. Окно закрыто ровно тогда, когда очередь пуста.
//
// # Почему разбор живёт, а не кончается на пустой очереди
//
// Один проход оставлял роль, чей пересчёт сорвался, с верхней границей до
// следующего рестарта, и длина очереди не была видна ниоткуда. Кончаться на
// первой пустой очереди тоже нельзя: очередь пополняется и после — писатель
// прежней версии во время перекатки (переходный страж схемы) и системная роль,
// чей пересчёт на старте сорвался. Поэтому разбор идёт, пока жив процесс:
// пауза `every` после прохода, оставившего очередь непустой, и десять таких
// пауз после пустого. Каждый проход сообщает перепись — сколько осмотрено,
// пересчитано, отказало и сколько осталось, — В ТОМ ЧИСЛЕ на пустой очереди:
// иначе «ноль» неотличим от «не мерили».
//
// # Зернистость — роль
//
// Каждая роль — своей транзакцией писателя: правила читаются под замком строки
// роли (`RulesForRegrain`), карты пишутся по отпечатку правила, роль снимается из
// очереди тем же оператором транзакции (`RegrainSelectorVerbs`). Отказ одной роли
// — в том числе неразбираемые правила — считается по этой роли и не прерывает
// проход: остальные пересчитываются.
//
// # Реплики
//
// Проход идемпотентен и коммутативен с правкой роли: карта строки — функция
// отпечатка правила и каталога, снятие из очереди — после чтения правил под
// замком. Две реплики, пересчитывающие одну роль, пишут одно и то же.
//
// # Предикат снятия
//
// Цикл — переходный механизм перекатки на эту версию: он нужен, пока на
// установке есть роли, заполненные миграцией, и писатели прежней версии.
// Снимается вместе с переходным стражем схемы
// (`role_rule_selectors_verbs_uncomputed`), когда
//
//	SELECT count(*) FROM kaname.role_selector_verbs_pending  →  0
//
// на всех установках после выкатки этой версии. Сама очередь остаётся: в неё
// кладёт «не вычисленные» строки досев селекторов системной роли, и снимает их
// пересчёт проекции системных ролей на старте (ReseedSystemRoleVerbs).

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamerepo "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

// SelectorVerbsCensus — перепись одного прохода пересчёта очереди.
type SelectorVerbsCensus struct {
	// Examined — ролей очереди прочитано в начале прохода.
	Examined int
	// Regrained — ролей, чья транзакция закоммичена (карты точные, роль снята).
	Regrained int
	// Failed — ролей, чья транзакция откачена; они остаются в очереди.
	Failed int
	// Pending — длина очереди ПОСЛЕ прохода, прочитанная заново: в неё входят и
	// роли, поставленные за время прохода.
	Pending int
}

// RegrainQueuedSelectorVerbs — один проход по очереди: каждая роль своей
// транзакцией писателя.
//
// Перечень очереди и её длина читаются пулом мимо реплики: прочитанная с
// отставанием пустая очередь дала бы «осмотрено 0, осталось 0» при роли, которая
// в ней стоит. Запись идёт только через порт.
//
// Ошибка — объединение отказов ролей; перепись возвращается всегда.
func RegrainQueuedSelectorVerbs(
	ctx context.Context,
	repo kanamerepo.Repository,
	pool *pgxpool.Pool,
	cat *catalog.Facts,
) (SelectorVerbsCensus, error) {
	var census SelectorVerbsCensus
	ids, err := queuedRoleIDs(ctx, pool)
	if err != nil {
		return census, err
	}
	census.Examined = len(ids)

	var failures []error
	for _, id := range ids {
		// Отмена контекста — один отказ прохода, а не отказ каждой оставшейся
		// роли: роли остаются в очереди до следующего процесса.
		if cerr := ctx.Err(); cerr != nil {
			failures = append(failures, fmt.Errorf("пересчёт очереди глаголов правил прерван: %w", cerr))
			break
		}
		if rerr := regrainOneRole(ctx, repo, cat, id); rerr != nil {
			census.Failed++
			failures = append(failures, rerr)
			continue
		}
		census.Regrained++
	}
	if ctx.Err() != nil {
		census.Pending = -1
	} else if perr := pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.role_selector_verbs_pending`).Scan(&census.Pending); perr != nil {
		failures = append(failures, fmt.Errorf("пересчёт очереди глаголов правил: длина очереди: %w", perr))
		census.Pending = -1
	}
	if len(failures) == 0 {
		return census, nil
	}
	return census, fmt.Errorf("пересчёт очереди глаголов правил: осмотрено %d, пересчитано %d, отказало %d: %w",
		census.Examined, census.Regrained, census.Failed, errors.Join(failures...))
}

// DrainSelectorVerbsQueue разбирает очередь, пока жив контекст: после прохода,
// оставившего очередь непустой, — пауза `every`, после пустого — десять таких
// пауз (`idleFactor`). Возвращается только отменой контекста: окно миграции
// закрывается пустой очередью, но пополнить её вправе и после — переходный
// страж схемы, досев системной роли, — и разобрать пополненное некому, если
// разбор кончился.
//
// `report` получает перепись и отказ КАЖДОГО прохода, включая пустые (nil — не
// сообщать): длина очереди видна на каждом шаге, и «ноль» — измеренный ноль.
//
// Каталожный факт берётся у источника на КАЖДОМ проходе: применение манифеста в
// работающем процессе меняет набор глаголов, и пересчёт по старому снимку
// записал бы карту, которой каталог уже не отвечает.
func DrainSelectorVerbsQueue(
	ctx context.Context,
	repo kanamerepo.Repository,
	pool *pgxpool.Pool,
	src catalog.Source,
	every time.Duration,
	report func(SelectorVerbsCensus, error),
) error {
	for {
		census, err := RegrainQueuedSelectorVerbs(ctx, repo, pool, src.Facts())
		if cerr := ctx.Err(); cerr != nil {
			return fmt.Errorf("разбор очереди глаголов правил остановлен: %w", cerr)
		}
		if report != nil {
			report(census, err)
		}
		pause := every
		if err == nil && census.Pending == 0 {
			pause = every * idleFactor
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("разбор очереди глаголов правил остановлен при длине очереди %d: %w",
				census.Pending, ctx.Err())
		case <-time.After(pause):
		}
	}
}

// idleFactor — во сколько раз пауза после пустого прохода длиннее паузы после
// непустого. Пустая очередь пополняется редко (перекатка, сорванный пересчёт
// на старте), и чтение её длины — одно обращение по пустому индексу.
const idleFactor = 10

// regrainOneRole — роль очереди: правила под замком, карты по правилу, снятие из
// очереди — одной транзакцией. Снятая либо удалённая роль строк селекторов не
// имеет: пересчитывать нечего, и транзакция лишь снимает её из очереди.
func regrainOneRole(ctx context.Context, repo kanamerepo.Repository, cat *catalog.Facts, id string) error {
	if err := shared.DoWithWriteTxVoid(ctx, repo,
		func(ctx context.Context, w kanamerepo.Writer) error {
			rules, policy, live, err := w.RolesW().RulesForRegrain(ctx, domain.RoleID(id))
			if err != nil {
				return err
			}
			var sels []domain.RuleSelector
			if live {
				sels = cat.GrantSelectors(rules.MaterializingSelectors(), policy)
			}
			return w.RolesW().RegrainSelectorVerbs(ctx, domain.RoleID(id), sels)
		}); err != nil {
		return fmt.Errorf("пересчёт глаголов правил роли %s: %w", id, err)
	}
	return nil
}

func queuedRoleIDs(ctx context.Context, pool *pgxpool.Pool) ([]string, error) {
	rows, err := pool.Query(ctx, `SELECT role_id FROM kaname.role_selector_verbs_pending ORDER BY enqueued_at, role_id`)
	if err != nil {
		return nil, fmt.Errorf("пересчёт очереди глаголов правил: перечень очереди: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if serr := rows.Scan(&id); serr != nil {
			return nil, fmt.Errorf("пересчёт очереди глаголов правил: строка очереди: %w", serr)
		}
		out = append(out, id)
	}
	if rerr := rows.Err(); rerr != nil {
		return nil, fmt.Errorf("пересчёт очереди глаголов правил: обход очереди: %w", rerr)
	}
	return out, nil
}
