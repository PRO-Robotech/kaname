// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package moduleseed — ПРИМЕНИТЕЛЬ раздела `seed` манифеста модуля
// (задача продукта #2452).
//
// # Чей это предмет и почему он появился
//
// Раздел `seed` объявляет то, что установка модуля заводит в службе доступа:
// личность модуля, его группы, выдачи и вступления в чужие группы. До этой
// задачи применителя у раздела не было НИ ОДНОГО: строки заводила применённая
// миграция службы, а раздел с ними лишь сверялся (`internal/moduleseedparity`).
//
// Цена того устройства измерена и названа в задаче #2452: миграция применяется
// ВЕЗДЕ, включая установку, где платформы нет вовсе, — и самостоятельная
// служба доступа заводила пять служебных ЛИЧНОСТЕЙ чужого продукта. Теперь
// строки заводит применитель, а условием служит ДОСТАВКА манифеста: каталог
// доставки кладёт зонтичный чарт платформы и не кладёт чарт самостоятельной
// службы. Условность выражена тем, что объявила установка, а не догадкой кода.
//
// # Что применитель НЕ делает
//
// Он не читает каталог доставки (это `loadDeliveredManifests`) и не судит форму
// манифеста (это валидатор связности `internal/manifest`). Ему приезжают уже
// разобранные и уже проверенные манифесты, и он приводит базу к тому, что в них
// написано.
//
// Он не СНИМАЕТ строк. Снятие модуля из доставки — отдельный предмет с
// отдельной ценой: снятая личность уносит с собой права, а её отсутствие
// снаружи неотличимо от «право не выдали». Применитель, снимающий молча, был бы
// отзывом без решения. Это ОСТАТОК, названный вслух, а не забытая половина.
//
// # Идемпотентность выражена ОПЕРАТОРОМ, а не сравнением в коде
//
// Каждая запись кладётся `ON CONFLICT … DO NOTHING` либо `DO UPDATE … WHERE
// <строка отличается>`. «Прочитать и сравнить» дало бы окно между чтением и
// записью (ban #10): под конкуренцией два применения увидели бы одну и ту же
// строку отсутствующей.
package moduleseed

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/PRO-Robotech/kaname/internal/manifest"
)

// Формы субъекта, которые манифест умеет называть. Перечень закрыт: субъект вне
// его — ОТКАЗ, а не пропуск. Пропущенный субъект дал бы выдачу ýже объявленной,
// и отличить её от исполненной можно было бы только вызовом.
const (
	subjectServiceAccount = "serviceAccount"
	subjectGroup          = "group"
)

// ErrUnknownSubjectType — субъект выдачи назван формой, которой применитель не
// знает. Отказ, а не пропуск: см. перечень выше.
var ErrUnknownSubjectType = errors.New("moduleseed: unknown access binding subject type")

// ErrGrantFormEmpty — выдача не назвала НИ РОЛИ, НИ ОТНОШЕНИЯ.
//
// Формы взаимоисключающи, и валидатор связности требует ровно одну ещё до
// применителя. Отказ здесь всё равно свой, а не оставленный базе: та отвергла бы
// строку ограничением `access_bindings_grant_form_ck`, и оператор прочёл бы имя
// ограничения вместо имени поля манифеста, которое надо править.
var ErrGrantFormEmpty = errors.New("moduleseed: access binding names neither roleId nor grantedRelation")

// Writer — то, что применителю нужно от хранилища, и ничего сверх.
//
// Каждый глагол отвечает ИЗМЕНИЛОСЬ ЛИ состояние: «применено шесть манифестов,
// изменений ноль» и «применено ноль манифестов» — разные утверждения о
// платформе, а молчание у них одно и то же.
type Writer interface {
	// UpsertServiceAccount заводит личность модуля либо приводит её назначение.
	UpsertServiceAccount(ctx context.Context, account, name, description string) (changed bool, err error)
	// UpsertGroup заводит группу модуля.
	UpsertGroup(ctx context.Context, account, name, description string) (changed bool, err error)
	// JoinGroup вводит служебную запись в группу.
	JoinGroup(ctx context.Context, saAccount, saName, groupAccount, groupName string) (changed bool, err error)
	// GrantRelation выдаёт субъекту ИМЕНОВАННОЕ ОТНОШЕНИЕ на якоре области.
	GrantRelation(ctx context.Context, subject Subject, relation, scopeKind, scopeID string) (changed bool, err error)
	// GrantRole выдаёт субъекту РОЛЬ на якоре области.
	GrantRole(ctx context.Context, subject Subject, roleID, scopeKind, scopeID string) (changed bool, err error)
}

// Subject — получатель выдачи, адресованный ПАРОЙ (аккаунт, имя): так он
// уникален в продукте. Идентификатор сюда не входит — его производит
// хранилище, и требовать от манифеста воспроизвести его значило бы требовать
// воспроизвести частность записи.
type Subject struct {
	// Kind — форма субъекта из закрытого перечня выше.
	Kind string
	// Account — аккаунт, в котором живёт субъект.
	Account string
	// Name — имя субъекта в этом аккаунте.
	Name string
}

func (s Subject) String() string { return s.Kind + " " + s.Account + "/" + s.Name }

// TxRunner — «исполни это под одной писательской транзакцией».
//
// Транзакция берётся НА МОДУЛЬ, а не на строку: личность модуля и её членства
// ложатся вместе либо не ложатся вовсе. Членство, доехавшее без личности,
// нарушило бы ссылочный триггер; личность без членства выглядела бы исправной и
// молча не давала бы модулю читать пределы.
type TxRunner interface {
	RunInWriteTx(ctx context.Context, fn func(context.Context, Writer) error) error
}

// Applier — применитель. Держит только исполнителя транзакций: решать ему
// нечего сверх того, что написано в манифесте.
type Applier struct {
	tx TxRunner
}

// NewApplier собирает применитель над исполнителем транзакций.
func NewApplier(tx TxRunner) *Applier { return &Applier{tx: tx} }

// Report — перепись применения одного модуля. Числами, потому что «применено»
// без чисел неотличимо от «прошло мимо»: применитель, не нашедший ни одной
// своей строки, молчит ровно так же уверенно, как записавший все.
type Report struct {
	// Module — модуль манифеста.
	Module string
	// Declared — объявлено разделом `seed` по каждому подразделу.
	DeclaredAccounts, DeclaredGroups, DeclaredJoins, DeclaredGrants int
	// Written — строк заведено либо приведено.
	WrittenAccounts, WrittenGroups, WrittenJoins, WrittenGrants int
}

func (r Report) String() string {
	return fmt.Sprintf("%s: личностей %d/%d · групп %d/%d · вступлений %d/%d · выдач %d/%d (записано/объявлено)",
		r.Module,
		r.WrittenAccounts, r.DeclaredAccounts,
		r.WrittenGroups, r.DeclaredGroups,
		r.WrittenJoins, r.DeclaredJoins,
		r.WrittenGrants, r.DeclaredGrants)
}

// Census — перепись всего применения.
type Census struct {
	// Manifests — доставленных манифестов прочитано.
	Manifests int
	// Seeding — из них объявили раздел `seed`. Ноль здесь законен и означает
	// «модули посева не объявили», а НЕ «применять не стали».
	Seeding int
	// Reports — по модулю на каждый объявивший.
	Reports []Report
}

// Totals — суммы по подразделам: объявлено и записано.
func (c Census) Totals() (declared, written int) {
	for _, r := range c.Reports {
		declared += r.DeclaredAccounts + r.DeclaredGroups + r.DeclaredJoins + r.DeclaredGrants
		written += r.WrittenAccounts + r.WrittenGroups + r.WrittenJoins + r.WrittenGrants
	}
	return declared, written
}

func (c Census) String() string {
	declared, written := c.Totals()
	lines := make([]string, 0, len(c.Reports))
	for _, r := range c.Reports {
		lines = append(lines, "  "+r.String())
	}
	head := fmt.Sprintf("манифестов %d · объявили посев %d · строк объявлено %d · записано %d",
		c.Manifests, c.Seeding, declared, written)
	if len(lines) == 0 {
		return head
	}
	return head + "\n" + strings.Join(lines, "\n")
}

// ApplyAll приводит базу к состоянию, объявленному разделами `seed` доставленных
// манифестов, и отдаёт перепись — ВСЕГДА, независимо от исхода.
//
// Отказ на любом модуле прекращает применение: половина применённого посева ýже
// объявленного, и отличить её от исполненного можно только вызовом. Отказ
// называет модуль — иначе оператор ищет причину во всей доставке сразу.
func (a *Applier) ApplyAll(ctx context.Context, manifests []*manifest.Manifest) (Census, error) {
	census := Census{Manifests: len(manifests)}

	for _, m := range manifests {
		if m == nil || m.Seed == nil {
			// «Посева нет» и «посев объявлен и пуст» — РАЗНЫЕ утверждения
			// (`seed: null` против `seed: {}`), и различает их указатель.
			// Первое здесь и остаётся первым: применять нечего.
			continue
		}
		census.Seeding++
		report, err := a.applyOne(ctx, m)
		census.Reports = append(census.Reports, report)
		if err != nil {
			return census, fmt.Errorf("посев модуля %q: %w", m.Module, err)
		}
	}
	sort.Slice(census.Reports, func(i, j int) bool {
		return census.Reports[i].Module < census.Reports[j].Module
	})
	return census, nil
}

// applyOne применяет посев одного модуля под ОДНОЙ транзакцией.
func (a *Applier) applyOne(ctx context.Context, m *manifest.Manifest) (Report, error) {
	seed := m.Seed
	report := Report{
		Module:           m.Module,
		DeclaredAccounts: len(seed.ServiceAccounts),
		DeclaredGroups:   len(seed.Groups),
		DeclaredJoins:    len(seed.Joins),
		DeclaredGrants:   len(seed.AccessBindings),
	}

	err := a.tx.RunInWriteTx(ctx, func(ctx context.Context, w Writer) error {
		// ПОРЯДОК НЕСУЩИЙ, и держится он ключами, а не памятью.
		//
		// Личности и группы — первыми: и вступление, и выдача ссылаются на них
		// ссылочным триггером (`subject_ref_exists`, `group_members_member_exists`),
		// и строка, положенная раньше своего референта, отказала бы отказом
		// ЧУЖОГО ограничения, называя не тот предмет.
		for _, sa := range seed.ServiceAccounts {
			changed, err := w.UpsertServiceAccount(ctx, sa.Account, sa.Name, sa.Description)
			if err != nil {
				return fmt.Errorf("личность %s/%s: %w", sa.Account, sa.Name, err)
			}
			if changed {
				report.WrittenAccounts++
			}
		}
		for _, g := range seed.Groups {
			changed, err := w.UpsertGroup(ctx, g.Account, g.Name, g.Description)
			if err != nil {
				return fmt.Errorf("группа %s/%s: %w", g.Account, g.Name, err)
			}
			if changed {
				report.WrittenGroups++
			}
		}
		for _, j := range seed.Joins {
			changed, err := w.JoinGroup(ctx,
				j.ServiceAccount.Account, j.ServiceAccount.Name,
				j.Group.Account, j.Group.Name)
			if err != nil {
				return fmt.Errorf("вступление %s/%s → %s/%s: %w",
					j.ServiceAccount.Account, j.ServiceAccount.Name,
					j.Group.Account, j.Group.Name, err)
			}
			if changed {
				report.WrittenJoins++
			}
		}
		for i, b := range seed.AccessBindings {
			written, err := applyBinding(ctx, w, seed, b)
			if err != nil {
				return fmt.Errorf("выдача seed.accessBindings[%d]: %w", i, err)
			}
			report.WrittenGrants += written
		}
		return nil
	})
	return report, err
}

// applyBinding кладёт одну выдачу — по одной строке на КАЖДОГО названного
// субъекта: выдача с двумя субъектами есть две строки хранилища, ровно как её
// кладёт публичный путь создания.
func applyBinding(ctx context.Context, w Writer, seed *manifest.Seed, b manifest.AccessBinding) (int, error) {
	kind, ok := scopeKindOf(b.ScopeType)
	if !ok {
		return 0, fmt.Errorf("якорь области %q не переводится в вид объекта", b.ScopeType)
	}

	written := 0
	for _, s := range b.Subjects {
		subject, err := subjectOf(s, seed)
		if err != nil {
			return written, err
		}
		var changed bool
		switch {
		case b.GrantedRelation != "":
			changed, err = w.GrantRelation(ctx, subject, b.GrantedRelation, kind, b.ScopeID)
		case b.RoleID != "":
			changed, err = w.GrantRole(ctx, subject, b.RoleID, kind, b.ScopeID)
		default:
			// Форм две, и они взаимоисключающи; НИ ОДНОЙ — состояние, которого
			// валидатор связности до применителя не пропускает. Отказ здесь —
			// не дублирование той проверки, а её последний рубеж: молча выбрать
			// одну из двух форм за автора манифеста применитель не вправе.
			return written, fmt.Errorf("%w (субъект %s)", ErrGrantFormEmpty, subject)
		}
		if err != nil {
			return written, fmt.Errorf("субъект %s: %w", subject, err)
		}
		if changed {
			written++
		}
	}
	return written, nil
}

// subjectOf переводит субъект манифеста в получателя выдачи.
//
// Аккаунт субъекта берётся у ТОЙ ЖЕ записи посева, которая его заводит: манифест
// называет субъект одним именем, потому что валидатор связности уже потребовал,
// чтобы этот субъект был заведён ЭТИМ ЖЕ посевом (`ErrSubjectNotSeeded`).
// Второго словаря аккаунтов здесь не заводится — он разошёлся бы с первым молча.
func subjectOf(s manifest.Subject, seed *manifest.Seed) (Subject, error) {
	switch s.Type {
	case subjectServiceAccount:
		for _, sa := range seed.ServiceAccounts {
			if sa.Name == s.Name {
				return Subject{Kind: subjectServiceAccount, Account: sa.Account, Name: sa.Name}, nil
			}
		}
		return Subject{}, fmt.Errorf("%w: служебная запись %q не заведена этим посевом",
			manifest.ErrSubjectNotSeeded, s.Name)
	case subjectGroup:
		for _, g := range seed.Groups {
			if g.Name == s.Name {
				return Subject{Kind: subjectGroup, Account: g.Account, Name: g.Name}, nil
			}
		}
		return Subject{}, fmt.Errorf("%w: группа %q не заведена этим посевом",
			manifest.ErrSubjectNotSeeded, s.Name)
	default:
		return Subject{}, fmt.Errorf("%w: %q (принимаются %q и %q)",
			ErrUnknownSubjectType, s.Type, subjectServiceAccount, subjectGroup)
	}
}
