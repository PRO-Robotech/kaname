// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package user

// account_less_delete_test.go — снятие БЕЗАККАУНТНОЙ строки личности решает
// МОДЕЛЬ, а не проверка внутри сервиса (#1174).
//
// # Предмет
//
// В `delete.go` стояло «не сам и без аккаунта → отказ». Довод, которым проверка
// обосновывалась, — «у безаккаунтного нет области, против которой можно написать
// выдачу» — потерял предмет после #1131: снятие строки личности гейтится
// `identity_remover`, и выдачей это отношение не резолвится вовсе НИ У КОГО.
//
// Что проверка делала на самом деле: отказывала НАДЗОРУ ОБЛАКА в снятии
// осиротевшей личности. То есть строка человека, потерявшего доступ, оставалась
// неудаляемой никем — сам он себя уже не удалит.
//
// Класс — `security.md` §«Авторизация живёт в МОДЕЛИ, а не в самодельных
// проверках»: хардкод не выдаётся, не ограничивается областью, не отзывается, не
// виден в аудите и не понимает машинных принципалов. #1102 снял такую же
// проверку с двенадцати мест; эта осталась и была названа «не сужающей» — что и
// опровергается здесь.
//
// # Почему пара, а не одно утверждение
//
// «Проходит» в одиночку зеленело бы и на use-case, который пускает кого угодно.
// Поэтому рядом — то, что сужение обязано СОХРАНИТЬ: анонимный отвергается, а
// самоудаление безаккаунтного по-прежнему проходит.
//
// Границу «никто, кроме облака, сюда не доходит» держит НЕ этот файл: она
// принадлежит модели и утверждается вердиктом по закоммиченным строкам —
// `services/iam/internal/service/removing_the_identity_integration_test.go`.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/operations"
)

// accountLessOversightCtxs — принципалы, которых край пропускает к этому RPC
// только через `identity_remover`, то есть надзор облака. Машинный — рядом
// намеренно: самодельная проверка «сам или никак» непроходима для него by
// construction, и именно это делает её решением о ДОСТУПЕ, а не валидацией.
func accountLessOversightCtxs() map[string]context.Context {
	return map[string]context.Context{
		"cloud_admin_user": operations.WithPrincipal(context.Background(),
			operations.Principal{Type: "user", ID: "usr0000000000000cadm"}),
		"service_account": operations.WithPrincipal(context.Background(),
			operations.Principal{Type: "service_account", ID: "sva0000000000000bot1"}),
	}
}

// TestDeleteUser_AccountLessTarget_DecidedByTheModel — предмет #1174.
func TestDeleteUser_AccountLessTarget_DecidedByTheModel(t *testing.T) {
	for name, ctx := range accountLessOversightCtxs() {
		t.Run(name, func(t *testing.T) {
			opsRepo := newFakeUsrOps()
			// Пустой аккаунт — та самая осиротевшая строка.
			uc := NewDeleteUserUseCase(newFakeUsrRepo(""), opsRepo)
			op, err := uc.Execute(ctx, delUserID)
			require.NoError(t, err,
				"снятие БЕЗАККАУНТНОЙ строки личности отвергнуто внутри сервиса. Гейт этого "+
					"RPC — `identity_remover@iam_user:<id>`, и край спрашивает его ДО того, как "+
					"наберёт iam: сюда доходит либо сам человек, либо надзор облака. Отказывая "+
					"здесь, сервис делает осиротевшую личность неудаляемой никем — а человек, "+
					"потерявший доступ, себя не удалит")
			require.NotNil(t, op)
			require.Empty(t, deleteUserMetaAccountID(t, opsRepo),
				"безаккаунтная строка обязана оставлять account_id пустым")
		})
	}
}

// TestDeleteUser_AccountLessTarget_SelfStillPasses — положительный контроль 1.
func TestDeleteUser_AccountLessTarget_SelfStillPasses(t *testing.T) {
	uc := NewDeleteUserUseCase(newFakeUsrRepo(""), newFakeUsrOps())
	op, err := uc.Execute(selfCtx(), delUserID)
	require.NoError(t, err,
		"самоудаление безаккаунтного человека было разрешено всегда — снятие проверки "+
			"не вправе его отнять")
	require.NotNil(t, op)
}

// TestDeleteUser_AccountLessTarget_AnonymousStillRejected — положительный
// контроль 2: пол аутентификации остаётся. Без него утверждение выше зеленело бы
// и на use-case, пускающем кого угодно.
func TestDeleteUser_AccountLessTarget_AnonymousStillRejected(t *testing.T) {
	uc := NewDeleteUserUseCase(newFakeUsrRepo(""), newFakeUsrOps())
	_, err := uc.Execute(context.Background(), delUserID)
	require.Error(t, err,
		"неаутентифицированный вызывающий снял безаккаунтную строку личности — снято "+
			"больше, чем предмет #1174")
}
