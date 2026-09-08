// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// invite_journal_cocommit_test.go — приглашение кладёт указатель на предка
// СТРОКОЙ ЖУРНАЛА в своей транзакции, а не записью в движок после коммита.
//
// ЧТО ЗАКРЕПЛЯЕТСЯ И ПОЧЕМУ ИМЕННО ЭТО. Состояние чужого хранилища отношений есть
// свёртка одного журнала `kaname.fga_outbox` — на этом стоит проекция
// `relation_fact` (миграция 0098), а на ней форма E. Прежде путь приглашения писал
// указатель ПРЯМО В ДВИЖОК после коммита, и кортеж не попадал в журнал НИКОГДА:
// движок отвечал «да», своя БД — «нет», и разбирали это в правах, а не в
// наполнении.
//
// Проба утверждает ИСХОД — что строка журнала легла и какой она формы, — а не что
// какая-то функция была позвана. Утверждение «эмиссия вызвана» осталось бы зелёным
// при пустом наборе кортежей.
package user

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/service"
)

// inviteEmitted прогоняет одно приглашение и возвращает строки журнала,
// со-коммиченные его транзакцией.
func inviteEmitted(t *testing.T) []service.RelationTuple {
	t.Helper()

	repo := &invPrincRepo{}
	uc := NewInviteUserUseCase(repo, newFakeUsrOps(), invPrincAllowAll{})

	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: "usr0000000000000invj"})
	op, err := uc.Execute(ctx, InviteUserInput{
		AccountID: domain.AccountID(invPrincAccount),
		Email:     domain.Email(invPrincEmail),
	})
	require.NoError(t, err, "приглашение обязано быть принято")
	require.NotNil(t, op)

	// ЖДЁМ ТО, О ЧЁМ УТВЕРЖДАЕМ. Здесь ждали ВСТАВКИ, а утверждали про
	// эмиссию строк журнала — а это два разных момента одной транзакции, и
	// идут они в известном порядке: вставка (`InsertPending`) раньше эмиссии
	// (`EmitFGARelationWrite`). Дождавшись первого, проба читала второе
	// незаполненным и падала с «Should NOT be empty, but was []».
	//
	// Локально это не воспроизводилось ни разу — включая `-count=5`,
	// `-shuffle=on` и весь пакет под `-race`: между двумя вызовами подряд
	// планировщику незачем переключаться. В конвейере, где пакеты идут
	// одновременно, окно открывается — и роняет ЧУЖОЙ PR в пакете, которого
	// он не касался.
	//
	// Ожидание обеих величин, а не одной поздней: вставка — предусловие, и её
	// отсутствие обязано называться своей причиной, иначе отказ по эмиссии
	// накроет и случай «приглашение вообще не дошло до писателя».
	require.Eventually(t, func() bool {
		repo.mu.Lock()
		defer repo.mu.Unlock()
		return repo.inserted && len(repo.emitted) > 0
	}, 5*time.Second, 10*time.Millisecond,
		"приглашение обязано дойти до писателя И со-коммитить строки журнала")

	repo.mu.Lock()
	defer repo.mu.Unlock()
	return append([]service.RelationTuple(nil), repo.emitted...)
}

// TestInvite_UserAccountPointerIsCoCommittedToTheJournal — указатель
// `iam_user:<id>#account@account:<acc>` ложится СТРОКОЙ ЖУРНАЛА.
//
// Без него per-resource UserService.Get на приглашённом — FGA `no path`; а если
// он попадает в движок мимо журнала, того же вопроса не может решить форма E.
func TestInvite_UserAccountPointerIsCoCommittedToTheJournal(t *testing.T) {
	emitted := inviteEmitted(t)

	require.NotEmpty(t, emitted,
		"транзакция приглашения не со-коммитила НИ ОДНОЙ строки журнала: указатель на "+
			"предка уходит мимо `kaname.fga_outbox`, и проекция relation_fact его не увидит никогда")

	want := service.RelationTuple{
		User:     "account:" + invPrincAccount,
		Relation: "account",
		Object:   "iam_user:",
	}
	found := false
	for _, got := range emitted {
		if got.User == want.User && got.Relation == want.Relation &&
			len(got.Object) > len(want.Object) && got.Object[:len(want.Object)] == want.Object {
			found = true
			break
		}
	}
	assert.True(t, found,
		"среди со-коммиченных строк журнала нет указателя `iam_user:<id>#account@account:%s`; "+
			"эмитировано: %+v", invPrincAccount, emitted)
}

// TestInvite_JournalRowCarriesTheContractShape — форма строки — часть предмета.
//
// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ к пробе выше: проверка «хоть что-то эмитировано»
// зеленела бы на строке любой формы, а проекция `relation_fact` разбирает объект
// как `<тип>:<идентификатор>` и ОТВЕРГАЕТ иную форму — то есть кортеж неверной
// формы не просто не спроецируется, он уронит вставку строки журнала.
func TestInvite_JournalRowCarriesTheContractShape(t *testing.T) {
	for _, got := range inviteEmitted(t) {
		assert.NotEmpty(t, got.User, "строка журнала без субъекта не проецируется")
		assert.NotEmpty(t, got.Relation, "строка журнала без отношения не проецируется")
		assert.Contains(t, got.Object, ":",
			"объект %q не имеет формы `<тип>:<идентификатор>` — триггер проекции такую строку "+
				"ОТВЕРГАЕТ, и вставка в журнал упала бы", got.Object)
		assert.NotContains(t, got.Object[:index(got.Object, ':')], ".",
			"тип объекта %q назван словарём каталога — вопрос о доступе приходит словарём "+
				"модели прав, и такая строка не совпала бы ни с одним вопросом", got.Object)
	}
}

func index(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return len(s)
}
