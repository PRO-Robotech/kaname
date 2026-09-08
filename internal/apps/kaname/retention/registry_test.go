// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// registry_test.go — порог уборки есть ФУНКЦИЯ ПРЕДИКАТА ЧИТАТЕЛЯ
// (приёмка `retention-sweep-has-a-caller.md`, сценарий RET-SWP-04).
//
// # Что здесь утверждается и почему модульно
//
// Пороги первых трёх предметов объявлены в §2.2 приёмки:
//
//	уборка утверждений:  expires_at     <= now() − (ClockSkew + RemovalSlack)
//	уборка отзывов:      ttl_expires_at <= now()
//	уборка отсечек:      revoke_before  <  now() − (MaxTokenTTL + ClockSkew + RemovalSlack)
//
// Четвёртый предмет — окна темпа заведения (задача #1364) — объявлен здесь же:
//
//	уборка окон темпа:   window_started_at < now() − window_seconds − 0
//
// Пятый предмет — журнал смены субъекта (задача #1758) — объявлен здесь же:
//
//	уборка журнала:      created_at < now() − subjectchange.JournalRetention
//
// Величина берётся У ЧИТАТЕЛЯ (`pkg/subjectchange`), а не выписывается: порог
// удержания есть функция предиката читателя, и копия разошлась бы с ним молча —
// в опасную сторону, снимая строки, которые читатель ещё вправе получить.
//
// `window_seconds` в порог НЕ входит величиной: он читается уборщиком из
// действующей строки величин тем же оператором, что и читателем-триггером
// (`identity_admission_window_repo.go`). Реестр объявляет только СЛАГАЕМОЕ
// запаса, и оно ноль.
//
// Записи с НУЛЁМ слагаемых стоят здесь контролем: без них проба зеленела бы на
// реализации, прибавляющей запас всюду. У отзывов часы уборки и всех четырёх
// читателей уже одни (база), у окон темпа — часы уборки и единственного
// читателя, и слагаемому там взяться неоткуда.
//
// Слагаемое запаса в пороге УТВЕРЖДЕНИЙ держит только эта проба, и это сказано
// вслух: его предикат — отстающие часы ЧИТАЮЩЕЙ реплики, а интеграционная
// фикстура разводит источники у уборщика, не у читателя (§7.2, разбор
// RET-SWP-17).
package retention

import (
	"context"
	"testing"
	"time"

	"github.com/PRO-Robotech/kacho/pkg/outbox"
	"github.com/PRO-Robotech/kacho/pkg/subjectchange"
	"github.com/PRO-Robotech/kacho/pkg/tokenpolicy"

	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/reconcile_outbox"
)

// TestRegistryThresholdsAreTheReadersPredicate — RET-SWP-04.
func TestRegistryThresholdsAreTheReadersPredicate(t *testing.T) {
	subjects := Subjects(stubReaper{}, stubReaper{}, stubReaper{}, stubReaper{}, stubReaper{}, stubReaper{}, stubReaper{})

	want := map[string]time.Duration{
		SubjectClientAssertionReplay:    tokenpolicy.ClockSkew + tokenpolicy.RemovalSlack,
		SubjectSessionRevocations:       0,
		SubjectMintedTokenCutoffs:       tokenpolicy.MaxTokenTTL + tokenpolicy.ClockSkew + tokenpolicy.RemovalSlack,
		SubjectIdentityAdmissionWindows: 0,
		SubjectSubjectChangeJournal:     subjectchange.JournalRetention,
		SubjectReconcileOutbox:          reconcile_outbox.DrainedRetention,
		// Порог берётся у СЕМЬИ очередей дренажа, а не объявляется здесь седьмым
		// числом: [outbox.DeliveredRetention] выведен из читателя доставленной
		// строки — оператора, разбирающего «доехало ли снятие».
		SubjectProviderCompensationOutbox: outbox.DeliveredRetention,
	}

	if len(subjects) != len(want) {
		t.Fatalf("предметов уборки %d, объявлено порогов %d — реестр и §2.2 разошлись",
			len(subjects), len(want))
	}
	seen := map[string]bool{}
	for _, s := range subjects {
		w, ok := want[s.Name]
		if !ok {
			t.Fatalf("предмет %q порога в §2.2 не имеет: либо приёмка не полна, либо реестр называет чужое", s.Name)
		}
		if seen[s.Name] {
			t.Fatalf("предмет %q объявлен дважды — два места об одном пороге разойдутся молча", s.Name)
		}
		seen[s.Name] = true
		if s.Grace != w {
			t.Errorf("порог предмета %q: получено %v, §2.2 требует %v", s.Name, s.Grace, w)
		}
		if s.Sweep == nil {
			t.Errorf("предмет %q объявлен без уборщика — запись реестра без предмета", s.Name)
		}
	}
	t.Logf("перепись: предметов уборки %d, порогов сверено %d", len(subjects), len(want))
}

// TestRegistryThresholdsFollowPolicyRatherThanACopy — вторая половина RET-SWP-04:
// изменение величины в `pkg/tokenpolicy` меняет пороги БЕЗ правки уборщиков.
//
// Проверяется отношением, а не числом: копия, разошедшаяся с политикой, даёт
// величину, которая арифметике политики больше не отвечает. Проба на равенство
// конкретной длительности этого не различает — она зелена и на копии, пока
// копия совпадает.
func TestRegistryThresholdsFollowPolicyRatherThanACopy(t *testing.T) {
	byName := map[string]time.Duration{}
	for _, s := range Subjects(stubReaper{}, stubReaper{}, stubReaper{}, stubReaper{}, stubReaper{}, stubReaper{}, stubReaper{}) {
		byName[s.Name] = s.Grace
	}

	// Порог отсечек ровно на MaxTokenTTL больше порога утверждений: у отсечек
	// добавляется срок самого токена, остальные слагаемые общие.
	if got, want := byName[SubjectMintedTokenCutoffs]-byName[SubjectClientAssertionReplay],
		tokenpolicy.MaxTokenTTL; got != want {
		t.Errorf("разница порогов «отсечки − утверждения» = %v, а политика объявляет MaxTokenTTL = %v: "+
			"слагаемое взято копией, а не из политики", got, want)
	}
	// Порог утверждений ровно на ClockSkew больше запаса: допуск приёма —
	// отдельное слагаемое, и без него открывается окно законного повтора.
	if got, want := byName[SubjectClientAssertionReplay]-tokenpolicy.RemovalSlack,
		tokenpolicy.ClockSkew; got != want {
		t.Errorf("порог утверждений за вычетом запаса = %v, а ClockSkew = %v: "+
			"допуск приёма в пороге не учтён", got, want)
	}
}

// stubReaper — дублёр всех портов реестра сразу. Он ничего не снимает и ничего не
// утверждает о базе: предмет этой пробы — ПОРОГИ реестра, а не поведение уборки.
// Поведение держат интеграционные RET-SWP-01…03 на настоящей базе.
type stubReaper struct{}

func (stubReaper) Reap(_ context.Context, _ time.Duration, _ int) (int64, bool, error) {
	return 0, false, nil
}

func (stubReaper) DeleteExpired(_ context.Context, _ time.Duration, _ int) (int64, bool, error) {
	return 0, false, nil
}

func (stubReaper) SweepStaleCutoffs(_ context.Context, _ time.Duration, _ int) (int64, bool, error) {
	return 0, false, nil
}

func (stubReaper) SweepElapsedAdmissionWindows(_ context.Context, _ time.Duration, _ int) (int64, bool, error) {
	return 0, false, nil
}

func (stubReaper) SweepDrainedReconcileEvents(_ context.Context, _ time.Duration, _ int) (int64, bool, error) {
	return 0, false, nil
}

func (stubReaper) SweepDeliveredCompensations(_ context.Context, _ time.Duration, _ int) (int64, bool, error) {
	return 0, false, nil
}

func (stubReaper) SweepAgedRows(_ context.Context, _ time.Duration, _ int) (int64, bool, error) {
	return 0, false, nil
}
