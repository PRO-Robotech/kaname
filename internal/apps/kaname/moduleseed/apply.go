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
// строки заводит применитель, и разрядов манифестов у него ДВА (приёмка MRW-1,
// решение Р3; задача kaname#106):
//
//   - СВОЙ манифест службы — приезжает встроенным в образ
//     (`internal/servicemanifest`), применяется ВСЕГДА и ПЕРВЫМ, доставкой не
//     связан: группу пишущих кортежи и её выдачу заводит сама служба, и на
//     самостоятельной установке они нужны так же, как в посадке платформы;
//   - ДОСТАВЛЕННЫЕ манифесты модулей — применяются ПОСЛЕ своего, и условием
//     служит ДОСТАВКА: каталог доставки кладёт зонтичный чарт платформы и не
//     кладёт чарт самостоятельной службы. Условность выражена тем, что
//     объявила установка, а не догадкой кода.
//
// Порядок «своё раньше доставленного» — единственный порядок, который сегодня
// выводится из вступлений: группу объявляет ровно один манифест (свой), все
// вступления идут в неё. Порядок между доставленными не решён — там популяция
// ноль объявленных групп, и это состояние без предмета, а не отсрочка.
//
// # Строка `notifications` — тоже предмет посева
//
// Манифест модуля либо службы может нести строку уведомлений (приёмка NTF-1,
// Р3 и Р5). Применитель судит её тем же предикатом, что загрузчик
// (`manifest.JudgeNotifications`), — разряд называет ПОЗИЦИЯ манифеста в
// [Applier.Apply], — и кладёт кортеж `service:notify reader
// notification_feed:<лента>` в той же транзакции, что посев модуля. Кортеж
// собирается конструктором `service_tuple.go`, субъект — фундаментом.
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

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
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
	// WriteServiceTuple кладёт кортеж со служебным субъектом (строка
	// `notifications`). Кортеж приезжает собранным: см. [ServiceTuple].
	WriteServiceTuple(ctx context.Context, t ServiceTuple) (changed bool, err error)
	// EnsureNotificationGrant заводит запись выдачи пространства уведомлений,
	// если её нет, и не трогает существующую ни в одном поле (надгробие
	// уважается — приёмка NTF-1 Р5, NTF1-F08). inserted — запись заведена
	// этим вызовом: только тогда посев пишет проекцию `sender`.
	EnsureNotificationGrant(ctx context.Context, namespace string) (inserted bool, err error)
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
	// DeclaredServiceTuples, WrittenServiceTuples — служебные кортежи строки
	// `notifications`: объявлено и записано.
	DeclaredServiceTuples, WrittenServiceTuples int
}

func (r Report) String() string {
	return fmt.Sprintf("%s: личностей %d/%d · групп %d/%d · вступлений %d/%d · выдач %d/%d · "+
		"служебных кортежей %d/%d (записано/объявлено)",
		r.Module,
		r.WrittenAccounts, r.DeclaredAccounts,
		r.WrittenGroups, r.DeclaredGroups,
		r.WrittenJoins, r.DeclaredJoins,
		r.WrittenGrants, r.DeclaredGrants,
		r.WrittenServiceTuples, r.DeclaredServiceTuples)
}

// Census — перепись всего применения.
//
// Разряды различаются ЧИСЛОМ, а не складываются: «свой применён · доставлено
// N» — одно число на оба скрыло бы ровно тот случай, ради которого разделение
// и делается (Р3): самостоятельную установку, где своя группа заведена, а
// доставки нет.
type Census struct {
	// Own — перепись СВОЕГО манифеста службы; nil — свой не подан. «Не подан» и
	// «подан без посева» — разные утверждения, и различает их указатель: во
	// втором случае здесь стоит отчёт с нулями.
	Own *Report
	// Manifests — ДОСТАВЛЕННЫХ манифестов прочитано. Свой сюда не входит.
	Manifests int
	// Seeding — из доставленных объявили раздел `seed` либо строку
	// `notifications`. Ноль здесь законен и
	// означает «модули посева не объявили», а НЕ «применять не стали».
	Seeding int
	// Reports — по модулю на каждый объявивший ДОСТАВЛЕННЫЙ манифест.
	Reports []Report
}

// Totals — суммы по подразделам: объявлено и записано, оба разряда вместе.
func (c Census) Totals() (declared, written int) {
	for _, r := range c.allReports() {
		declared += r.DeclaredAccounts + r.DeclaredGroups + r.DeclaredJoins + r.DeclaredGrants +
			r.DeclaredServiceTuples
		written += r.WrittenAccounts + r.WrittenGroups + r.WrittenJoins + r.WrittenGrants +
			r.WrittenServiceTuples
	}
	return declared, written
}

// allReports — свой (если подан) и доставленные, своим первым: в том же
// порядке, в каком они применялись.
func (c Census) allReports() []Report {
	if c.Own == nil {
		return c.Reports
	}
	return append([]Report{*c.Own}, c.Reports...)
}

func (c Census) String() string {
	declared, written := c.Totals()
	own := "свой манифест не подан"
	if c.Own != nil {
		own = "свой манифест применён"
	}
	lines := make([]string, 0, len(c.Reports)+1)
	for _, r := range c.allReports() {
		lines = append(lines, "  "+r.String())
	}
	head := fmt.Sprintf("%s · доставлено %d · объявили посев %d · строк объявлено %d · записано %d",
		own, c.Manifests, c.Seeding, declared, written)
	if len(lines) == 0 {
		return head
	}
	return head + "\n" + strings.Join(lines, "\n")
}

// Apply приводит базу к состоянию, объявленному СВОИМ манифестом службы и затем
// ДОСТАВЛЕННЫМИ манифестами модулей, и отдаёт перепись — ВСЕГДА, независимо от
// исхода.
//
// Свой применяется ПЕРВЫМ и отдельным доводом, а не подмешанным в перечень
// (Р3): вступление модуля тогда всегда встречает группу заведённой — независимо
// от имени модуля и от порядка обхода каталога доставки. nil вместо своего —
// законный довод для вызывающего, у которого своего манифеста нет (пробы
// доставки); композиционный корень подаёт его всегда.
//
// Отказ на любом манифесте прекращает применение: половина применённого посева
// ýже объявленного, и отличить её от исполненного можно только вызовом. Отказ
// называет разряд и модуль — иначе оператор ищет причину во всей доставке
// сразу.
func (a *Applier) Apply(ctx context.Context, own *manifest.Manifest, delivered []*manifest.Manifest) (Census, error) {
	census := Census{Manifests: len(delivered)}

	// Личности, группы и привязки модулей — журналируемые таблицы, и строка
	// журнала без инициатора базой не принимается (NTF-3, Р2): транзакции
	// посева начинает компонент посева.
	ctx, err := shared.InitiatedOrJournalComponent(ctx, shared.JournalComponentSeed)
	if err != nil {
		return census, fmt.Errorf("посев модулей: инициатор журнала: %w", err)
	}

	if own != nil {
		report, err := a.applyOne(ctx, own, manifest.HolderAccessService)
		census.Own = &report
		if err != nil {
			return census, fmt.Errorf("посев своего манифеста %q (свой манифест службы): %w", own.Module, err)
		}
	}

	for _, m := range delivered {
		if m == nil || (m.Seed == nil && m.Notifications == nil) {
			// «Посева нет» и «посев объявлен и пуст» — РАЗНЫЕ утверждения
			// (`seed: null` против `seed: {}`), и различает их указатель.
			// Первое здесь и остаётся первым: применять нечего.
			continue
		}
		census.Seeding++
		report, err := a.applyOne(ctx, m, manifest.HolderModule)
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

// ApplyAll — применение ОДНИХ доставленных манифестов, без своего. Остаётся
// для вызывающих, у которых своего манифеста нет by construction (пробы
// доставки платформы); композиционный корень зовёт [Apply].
func (a *Applier) ApplyAll(ctx context.Context, manifests []*manifest.Manifest) (Census, error) {
	return a.Apply(ctx, nil, manifests)
}

// applyOne применяет посев одного манифеста под ОДНОЙ транзакцией.
//
// Манифест без раздела `seed` и без строки `notifications` даёт отчёт с нулями
// и транзакции не открывает: применять нечего, а «подан и пуст» обязано быть
// отличимо от «не подан» — это различает вызывающий по указателю в переписи.
//
// holder — разряд манифеста, названный ПОЗИЦИЕЙ в [Applier.Apply] (свой либо
// доставленный), а не документом: форма, по которой документ опознавал бы себя
// службой, была бы формой, которую может написать любой модуль.
func (a *Applier) applyOne(ctx context.Context, m *manifest.Manifest, holder manifest.NotificationsHolder) (Report, error) {
	report := Report{Module: m.Module}
	if m.Seed == nil && m.Notifications == nil {
		return report, nil
	}
	seed := m.Seed
	if seed == nil {
		seed = &manifest.Seed{}
	}
	report.DeclaredAccounts = len(seed.ServiceAccounts)
	report.DeclaredGroups = len(seed.Groups)
	report.DeclaredJoins = len(seed.Joins)
	report.DeclaredGrants = len(seed.AccessBindings)

	// Строка `notifications` судится ДО транзакции и тем же предикатом, что у
	// загрузчика: применитель — последний рубеж для документа, дошедшего сюда в
	// обход разбора. Отказ не открывает транзакции — половину строки (законный
	// notify рядом с чужим читателем) применитель не применяет.
	tuples, err := notificationTuples(m, holder)
	if err != nil {
		return report, err
	}
	grant, err := notificationGrant(m, holder)
	if err != nil {
		return report, err
	}
	report.DeclaredServiceTuples = len(tuples)
	if grant != nil {
		report.DeclaredServiceTuples++
	}

	err = a.tx.RunInWriteTx(ctx, func(ctx context.Context, w Writer) error {
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
		for _, t := range tuples {
			changed, err := w.WriteServiceTuple(ctx, t)
			if err != nil {
				return fmt.Errorf("служебный кортеж %s: %w", t, err)
			}
			if changed {
				report.WrittenServiceTuples++
			}
		}
		// Запись выдачи пространства и её проекция `sender` — той же
		// транзакцией. Проекция пишется ТОЛЬКО для записи, заведённой этим
		// посевом: существующую посев не трогает, и отозванная выдача
		// перезапуском не оживает (NTF1-F08).
		if grant != nil {
			inserted, err := w.EnsureNotificationGrant(ctx, grant.ObjectID())
			if err != nil {
				return fmt.Errorf("запись выдачи пространства %q: %w", grant.ObjectID(), err)
			}
			if inserted {
				changed, err := w.WriteServiceTuple(ctx, *grant)
				if err != nil {
					return fmt.Errorf("служебный кортеж %s: %w", grant, err)
				}
				if changed {
					report.WrittenServiceTuples++
				}
			}
		}
		return nil
	})
	return report, err
}

// notificationTuples — служебные кортежи строки `notifications` манифеста m.
// Строки нет — кортежей нет; строка негодна — отказ.
func notificationTuples(m *manifest.Manifest, holder manifest.NotificationsHolder) ([]ServiceTuple, error) {
	if m.Notifications == nil {
		return nil, nil
	}
	if err := manifest.JudgeNotifications(m, holder); err != nil {
		return nil, fmt.Errorf("строка notifications: %w", err)
	}
	feed := manifest.NotificationFeed(m, holder)
	tuples := make([]ServiceTuple, 0, len(m.Notifications.Readers))
	for _, reader := range m.Notifications.Readers {
		t, err := feedReaderTuple(reader, feed)
		if err != nil {
			return nil, fmt.Errorf("строка notifications: %w", err)
		}
		tuples = append(tuples, t)
	}
	return tuples, nil
}

// notificationGrant — проекция `sender` записи выдачи пространства строки
// `notifications` манифеста МОДУЛЯ. У службы доступа служебного принципала нет
// (MRW-1 Р1, NTF1-F21) — записи выдачи у неё тоже нет. Строку уже судил
// notificationTuples.
func notificationGrant(m *manifest.Manifest, holder manifest.NotificationsHolder) (*ServiceTuple, error) {
	if m.Notifications == nil || holder == manifest.HolderAccessService {
		return nil, nil
	}
	t, err := SenderTuple(manifest.NotificationFeed(m, holder))
	if err != nil {
		return nil, fmt.Errorf("строка notifications: %w", err)
	}
	return &t, nil
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
