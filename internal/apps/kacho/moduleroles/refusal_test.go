// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// refusal_test.go — ПОЛОСА отказа применителя различима МАШИННО (задача #1880).
//
// # Что здесь утверждается, и почему пара, а не два отдельных утверждения
//
// Вопрос задачи — не «называет ли отказ свою причину», а «РАЗЛИЧАЕТ ли
// вызывающий две полосы, не разбирая прозу». Утверждение о каждой полосе
// порознь на этот вопрос не отвечает: применитель, отвечающий одним и тем же
// токеном на всё, прошёл бы обе такие пробы. Поэтому у каждой пробы полосы
// стоит вторая половина — токен соседней полосы ОТЛИЧАЕТСЯ.
//
// Дублёр исполнителя (`fakeStore.RunInWriteTx`) приводит отказ к статусу тем же
// `shared.MapRepoErr`, что и продукт, — иначе он сохранял бы цепочку, которую
// продукт теряет, и полоса писателя оказалась бы различима только у дублёра.
// Границу транзакции он не изображает: её судит интеграционная проба
// (`module_roles_applier_integration_test.go`, MOD-RD-06).
package moduleroles_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/moduleroles"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
	"github.com/PRO-Robotech/kacho/services/iam/internal/manifest"
)

// refusingStore — дублёр, чей ПИСАТЕЛЬ отказывает так же, как база: сентинелом
// класса и текстом предмета. Свой текст поверх ответа базы здесь был бы прозой,
// скрывающей имя нарушенного ограничения.
type refusingStore struct {
	*fakeStore
	onRefs error
}

func (s *refusingStore) ReplaceRuleRefs(ctx context.Context, id domain.RoleID, refs []domain.RoleRuleRef) error {
	if s.onRefs != nil {
		return s.onRefs
	}
	return s.fakeStore.ReplaceRuleRefs(ctx, id, refs)
}

func (s *refusingStore) RunInWriteTx(ctx context.Context, fn func(context.Context, moduleroles.RoleWriter) error) error {
	return s.fakeStore.RunInWriteTx(ctx, func(ctx context.Context, _ moduleroles.RoleWriter) error {
		return fn(ctx, s)
	})
}

// clusterManifest — манифест модуля с одной ролью КЛАСТЕРНОГО яруса: иной ярус
// применитель пропускает молча, и проба на нём утверждала бы про пустое
// множество.
func clusterManifest(module, roleID string, rules []manifest.Rule) *manifest.Manifest {
	return &manifest.Manifest{
		Module: module,
		Roles: []manifest.Role{{
			ID:          roleID,
			Description: "Роль пробы полосы отказа.",
			Tier:        &manifest.Tier{TierType: domain.ScopeTypeClusterDotted, TierID: domain.ClusterSingletonID},
			Rules:       rules,
		}},
	}
}

// TestRefusalLaneOfTheWriterSurvivesTheTxExecutor — полоса ПИСАТЕЛЯ доезжает до
// вызывающего сквозь исполнителя транзакций.
//
// Именно здесь и терялся признак: исполнитель пересобирает статус, и `%w`-
// цепочка применителя до вызывающего не доходит. Проба утверждает то, что
// вызывающий получает на самом деле, — токен полосы и код, — а не то, что
// применитель написал у себя.
func TestRefusalLaneOfTheWriterSurvivesTheTxExecutor(t *testing.T) {
	store := &refusingStore{
		fakeStore: newStore(),
		onRefs: iamerr.Wrapf(iamerr.ErrFailedPrecondition,
			"resources: %s is not a live platform resource", "probeWithdrawn"),
	}
	_, err := moduleroles.NewApplier(store).Apply(context.Background(),
		clusterManifest("vpc", "vpc.network.admin",
			[]manifest.Rule{{Module: "vpc", Resources: []string{"network"}, Classes: []string{"get"}}}))
	if err == nil {
		t.Fatalf("писатель отказал — применение обязано отказать тоже")
	}

	if got := moduleroles.RefusalLane(err); got != moduleroles.LaneWriteFailed {
		t.Errorf("полоса писателя не доехала до вызывающего: RefusalLane=%q, хотел %q (%v)",
			got, moduleroles.LaneWriteFailed, err)
	}
	if got := status.Code(err); got != codes.FailedPrecondition {
		t.Errorf("класс отказа переопределён применителем: %v, хотел %v", got, codes.FailedPrecondition)
	}
	// Предмет отказа приезжает текстом базы: инвариант держит она, и её текст —
	// часть контракта. Признак полосы его не замещает, а дополняет.
	if !strings.Contains(err.Error(), "resources: probeWithdrawn is not a live platform resource") {
		t.Errorf("отказ не называет предмет: %v", err)
	}
	// Цепочка сентинела — вторым лицом того же отказа: вызывающий в процессе
	// спрашивает её привычным `errors.Is`, не зная про признак.
	if !errors.Is(err, moduleroles.ErrWriteFailed) {
		t.Errorf("сентинел писателя не доехал: %v", err)
	}
	if errors.Is(err, moduleroles.ErrRoleRejectedByDomain) {
		t.Errorf("отказ писателя отнесён к полосе домена: %v", err)
	}
}

// TestRefusalLaneOfTheDomainDiffersFromTheWriter — ОТЛИЧИЕ двух полос, а не
// наличие токена у каждой.
//
// Без этой пары обе пробы прошли бы на применителе, отвечающем одним токеном на
// любой отказ, — то есть на применителе, ничего не различающем.
func TestRefusalLaneOfTheDomainDiffersFromTheWriter(t *testing.T) {
	// Полоса домена: правило называет СНЯТЫЙ тип. До писателя такой вход не
	// доходит — проверка домена стоит раньше.
	domainStore := newStore()
	_, domainErr := moduleroles.NewApplier(domainStore).Apply(context.Background(),
		clusterManifest("vpc", "vpc.network.admin",
			[]manifest.Rule{{Module: "compute", Resources: []string{"disk"}, Classes: []string{"get"}}}))
	if domainErr == nil {
		t.Fatalf("правило называет снятый тип — применение обязано отказать")
	}
	if domainStore.calls != 0 {
		t.Errorf("негодная роль дошла до писателя: вызовов %d", domainStore.calls)
	}

	// Полоса писателя: то же применение, отказ на записи.
	writerStore := &refusingStore{
		fakeStore: newStore(),
		onRefs: iamerr.Wrapf(iamerr.ErrFailedPrecondition,
			"resources: %s is not a live platform resource", "probeWithdrawn"),
	}
	_, writeErr := moduleroles.NewApplier(writerStore).Apply(context.Background(),
		clusterManifest("vpc", "vpc.network.admin",
			[]manifest.Rule{{Module: "vpc", Resources: []string{"network"}, Classes: []string{"get"}}}))
	if writeErr == nil {
		t.Fatalf("писатель отказал — применение обязано отказать тоже")
	}

	domainLane, writeLane := moduleroles.RefusalLane(domainErr), moduleroles.RefusalLane(writeErr)
	if domainLane != moduleroles.LaneRejectedByDomain {
		t.Errorf("полоса домена названа неверно: %q (%v)", domainLane, domainErr)
	}
	if writeLane != moduleroles.LaneWriteFailed {
		t.Errorf("полоса писателя названа неверно: %q (%v)", writeLane, writeErr)
	}
	// Отличие утверждается ОТДЕЛЬНО и после того, как названа каждая: без имён
	// «различны» выполнялось бы и на паре «токен против пустой строки», то есть
	// на применителе, у которого одна из полос не названа вовсе.
	if domainLane == writeLane {
		t.Fatalf("полосы НЕ различимы: обе отвечают %q — вызывающему остаётся разбор прозы", domainLane)
	}
	// Код — вторая половина пары, и он различает полосы сам по себе: манифест
	// назвал негодное (ввод) против «база отвергла запись» (состояние).
	if got := status.Code(domainErr); got != codes.InvalidArgument {
		t.Errorf("полоса домена: класс %v, хотел %v", got, codes.InvalidArgument)
	}
	if got := status.Code(writeErr); got != codes.FailedPrecondition {
		t.Errorf("полоса писателя: класс %v, хотел %v", got, codes.FailedPrecondition)
	}
}

// TestRefusalLaneIsSilentOnAnythingElse — контроль в обратную сторону: полоса
// НЕ называется там, где её нет.
//
// Без него читатель, отвечающий токеном на всё, прошёл бы пробы выше: они
// спрашивают только про отказы применителя.
func TestRefusalLaneIsSilentOnAnythingElse(t *testing.T) {
	if got := moduleroles.RefusalLane(nil); got != "" {
		t.Errorf("у отсутствующего отказа названа полоса %q", got)
	}
	if got := moduleroles.RefusalLane(errors.New("чужой отказ")); got != "" {
		t.Errorf("у чужого отказа названа полоса %q", got)
	}
	if got := moduleroles.RefusalLane(status.Error(codes.FailedPrecondition, "чужой статус")); got != "" {
		t.Errorf("у чужого статуса названа полоса %q", got)
	}
}
