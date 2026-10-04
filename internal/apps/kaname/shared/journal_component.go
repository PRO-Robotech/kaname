// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package shared

// journal_component.go — личности компонентов службы как инициаторы ресурсного
// журнала (NTF-3, Р2; сценарий NTF3-63).
//
// Строка журнала без инициатора базой не принимается, а инициатора пишущей
// транзакции открывающий (`internal/journalwrite`) берёт только у принципала
// контекста. Пути, у которых удостоверенного субъекта нет, начинает компонент
// службы, и его личность — `auth.SystemPrincipalFor(kaname, <роль>)`,
// инициатор `system:kaname-<роль>`. Перечень ролей закрыт и объявлен здесь
// одним местом; инициатора из пары строит только фундамент
// (`journaltx.AsComponent` → `auth.InitiatorOf`).
//
//   - seed — посев старта: привязки владельцев, селекторы системных ролей,
//     роли и личности модулей из манифестов, досев выдач;
//   - reconciler — сверщик выдач: снятие выдачи по истечении срока;
//   - sweeper — уборщик выдач осиротевшей области;
//   - registration — полоса регистрации: человек ещё не удостоверен, и
//     приписать изменение ему значило бы утверждать непроверенное;
//   - provisioning — заведение человека по удостоверению поставщика без
//     предъявленного токена (`UpsertFromIdentity`).
//
// Межслужебных вызовов у службы нет (`TestIamIsALeafAndCallsNobodyByGRPC`),
// поэтому личность компонента пересылаемой личности не меняет.

import (
	"context"
	"fmt"

	"github.com/PRO-Robotech/corelib/auth"
	"github.com/PRO-Robotech/corelib/journaltx"
	"github.com/PRO-Robotech/corelib/operations"
)

// JournalComponentService — служба в паре личности компонента.
const JournalComponentService = "kaname"

// Роли компонентов службы, пишущих журнал без удостоверенного субъекта.
const (
	JournalComponentSeed         = "seed"
	JournalComponentReconciler   = "reconciler"
	JournalComponentSweeper      = "sweeper"
	JournalComponentRegistration = "registration"
	JournalComponentProvisioning = "provisioning"
)

// AsJournalComponent — контекст с личностью компонента службы. Контекст с
// иным принципалом — ошибка программы (`journaltx.ErrComponentOverPrincipal`).
func AsJournalComponent(ctx context.Context, role string) (context.Context, error) {
	return journaltx.AsComponent(ctx, JournalComponentService, role)
}

// InitiatedOrJournalComponent — контекст, чей принципал даёт инициатора,
// отдаётся как есть: изменение начинает удостоверенный субъект. Иначе —
// личность компонента: и без принципала, и с принципалом, у которого формы
// инициатора нет (`{system, bootstrap}`, анонимная форма). Последний — не
// личность начавшего, а отметка её отсутствия, и в контексте открытия
// транзакции его место занимает компонент; подмены субъекта здесь нет, потому
// что субъекта нет.
//
// Контекст, с которого принципал СНЯТ (`operations.WithoutPrincipal`), личности
// не принимает — отказ: снятие сильнее установки, и путь отказывает до записи.
func InitiatedOrJournalComponent(ctx context.Context, role string) (context.Context, error) {
	p, ok := operations.PrincipalFromContextOK(ctx)
	if !ok {
		return AsJournalComponent(ctx, role)
	}
	if _, err := auth.InitiatorOf(p); err == nil {
		return ctx, nil
	}
	out := operations.WithPrincipal(ctx, auth.SystemPrincipalFor(JournalComponentService, role))
	if _, set := operations.PrincipalFromContextOK(out); !set {
		return nil, fmt.Errorf("journal component %s-%s: %w",
			JournalComponentService, role, journaltx.ErrComponentOverPrincipal)
	}
	return out, nil
}
