// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package toproto

import (
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/reflect/protoreflect"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	"github.com/PRO-Robotech/kacho/services/iam/internal/dto"
)

// role_computed_state_test.go — ПРОБА переводчика ответа операции.
//
// Держит обещание страницы ресурса: нулевые `health` и `lifecycle` в ответе
// операции означают «этим ответом не вычислено», а не «роль здорова и
// объявлена». До заведения проекции обещание не держалось НИЧЕМ — оно было
// верно by construction, потому что производителя вычисленного состояния никто
// не звал на пути мутации, и снималось одной строкой молча.
//
// Проба сверяет МНОЖЕСТВО полей контракта, которые проекция меняет, а не их
// число: расхождение бывает двусторонним — поле перестало обнуляться, и рядом
// завелось новое, — и по числу оно неотличимо от порядка.

// roleComputedStateFields — поля контракта, которые несут ВЫЧИСЛЕННОЕ состояние
// роли и потому в ответе операции приходят нулевыми.
//
// Их СЕМЬ, а доменных полей за ними ПЯТЬ: целость роли приезжает тремя полями
// контракта (состояние и два счётчика). Перечень выписан здесь ОДИН раз и
// сверяется с исходом перевода в обе стороны — лишнее имя роняет пробу так же,
// как недостающее.
var roleComputedStateFields = []string{
	"health",
	"declared_segments",
	"unresolved_segments",
	"withdrawn_grants",
	"pruned_selector_types",
	"rule_states",
	"lifecycle",
}

// roleWithComputedState — роль, какой её отдаёт ЧТЕНИЕ: со всеми пятью
// производными полями заполненными.
func roleWithComputedState() domain.Role {
	rules := domain.Rules{{
		Module: "vpc", Resources: []string{"networks"}, Verbs: []string{"get", "list"},
	}}
	return domain.Role{
		ID:        "rolkw55v2z363gpqath1",
		AccountID: "acc2bkd71802av7dywa8",
		Name:      "vpc-viewer",
		Rules:     rules,
		TypeVerbs: func(_, _ string) ([]string, bool) {
			return []string{"get", "list", "create", "update", "delete"}, true
		},
		Integrity: domain.HealthOf(2, 1),
		Lifecycle: domain.RoleLifecycle{
			State:         domain.RoleLifecycleWithdrawn,
			RetiredAt:     time.Date(2026, 9, 3, 13, 15, 44, 0, time.UTC),
			RetiredReason: "модуль перестал объявлять роль",
			RetiredBy:     "usrb3n8q1x7wzk52pfeq",
		},
		Withdrawn: []domain.WithdrawnGrant{{
			ObjectType: "vpc.networks", Verb: "list",
			Reason: "не объявлен манифестом модуля vpc",
		}},
		PrunedSelectorTypes: []domain.PrunedSelectorType{{
			ObjectType: "vpc.networks", Reason: "тип снят с обслуживания",
		}},
		RuleStates: domain.RuleStatesOf(rules, nil, nil),
	}
}

func roleToPb(t *testing.T, r domain.Role) *iamv1.Role {
	t.Helper()
	var dst *iamv1.Role
	require.NoError(t, dto.Transfer(dto.FromTo(r, &dst)), "перевод роли в контрактную форму")
	require.NotNil(t, dst)
	return dst
}

// setFields — имена полей контракта, которые сообщение несёт СОДЕРЖАТЕЛЬНО.
//
// Судится ЗНАЧЕНИЕ, а не занятость слота, и различие несущее: вложенное
// сообщение переводчик отдаёт непустым указателем ВСЕГДА, поэтому `lifecycle`
// присутствует и в ответе операции — но несёт `ROLE_LIFECYCLE_STATE_UNSPECIFIED`,
// то есть ровно «этим ответом не вычислено». Считать такой слот носителем
// состояния значило бы объявить нарушением контракт, который здесь и обещан:
// сигналом служит НУЛЕВОЕ состояние, а не отсутствие поля.
//
// Пустые скаляры, списки и карты `Range` не отдаёт сам.
func setFields(m protoreflect.Message) map[string]bool {
	out := map[string]bool{}
	m.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		if fd.Kind() == protoreflect.MessageKind && !fd.IsList() && !fd.IsMap() {
			if len(setFields(v.Message())) == 0 {
				return true // сообщение есть, содержания в нём нет
			}
		}
		out[string(fd.Name())] = true
		return true
	})
	return out
}

func sortedOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestOperationResponseOfRoleCarriesNoComputedState — ответ операции не несёт
// вычисленного состояния, а чтение — несёт.
//
// Положительный контроль стоит ПЕРВЫМ и он не украшение: без него утверждение
// «полей нет» зеленело бы на переводчике, который их не производит ВООБЩЕ, — то
// есть на сломанном переводе.
func TestOperationResponseOfRoleCarriesNoComputedState(t *testing.T) {
	read := roleToPb(t, roleWithComputedState())
	operation := roleToPb(t, roleWithComputedState().WithoutComputedState())

	// Контроль: чтение несёт КАЖДОЕ из семи. Иначе отрицание ниже вакуумно.
	readSet := setFields(read.ProtoReflect())
	for _, f := range roleComputedStateFields {
		require.Truef(t, readSet[f],
			"чтение не несёт поле %s — перевод производит не всё вычисленное состояние, "+
				"и утверждение об ответе операции ниже стало бы вакуумным", f)
	}

	// Отрицание: ответ операции не несёт НИ ОДНОГО.
	opSet := setFields(operation.ProtoReflect())
	for _, f := range roleComputedStateFields {
		require.Falsef(t, opSet[f],
			"ответ операции несёт поле %s: арендатору обещано, что нулевое значение "+
				"означает «этим ответом не вычислено», а не «роль здорова и объявлена». "+
				"Состояние, посчитанное на пути мутации, относится к ДРУГОМУ снимку "+
				"проекции", f)
	}

	// СВЕРКА ПО МНОЖЕСТВУ. Разность двух ответов обязана быть РОВНО перечнем
	// выше: меньше — поле перестало обнуляться, больше — обнулилось то, что
	// вычисленным состоянием не является (например превью глаголов, у которого
	// нулевое значение есть ОТКАЗ проекции, а не «не вычислено»).
	diff := map[string]bool{}
	for f := range readSet {
		if !opSet[f] {
			diff[f] = true
		}
	}
	for f := range opSet {
		if !readSet[f] {
			diff[f] = true
		}
	}
	want := map[string]bool{}
	for _, f := range roleComputedStateFields {
		want[f] = true
	}
	require.Equalf(t, sortedOf(want), sortedOf(diff),
		"проекция меняет НЕ ТО множество полей контракта. Заведено шестое производное "+
			"поле — снимите его в domain.Role.WithoutComputedState() и назовите здесь; "+
			"перестало обнуляться существующее — верните. Число здесь не помогает: "+
			"расхождение бывает двусторонним")

	// Не-производные поля ответ операции несёт по-прежнему: проекция обязана
	// быть УЗКОЙ, иначе она снимает у клиента и то, за чем он пришёл.
	require.Equal(t, read.GetId(), operation.GetId(), "проекция потеряла идентификатор")
	require.Equal(t, read.GetName(), operation.GetName(), "проекция потеряла имя")
	require.Equal(t, read.GetAuthoredVerbs(), operation.GetAuthoredVerbs(),
		"проекция потеряла превью глаголов: нулевое значение TypeVerbs означает ОТКАЗ "+
			"проекции, а не «не вычислено», и путь мутации его заполняет сам")
	require.Equal(t, read.GetRules(), operation.GetRules(), "проекция потеряла правила")
}

// TestWithoutComputedStateDoesNotMutateItsReceiver — проекция неразрушающая.
//
// Вызывающий переводит роль в ответ операции и продолжает пользоваться своей;
// разрушающая проекция унесла бы вычисленное состояние у ЧТЕНИЯ, случись оно
// в том же потоке.
func TestWithoutComputedStateDoesNotMutateItsReceiver(t *testing.T) {
	src := roleWithComputedState()
	_ = src.WithoutComputedState()

	require.Equal(t, domain.RoleHealthDegraded, src.Integrity.Health,
		"проекция изменила приёмник: целость снята у источника")
	require.Equal(t, domain.RoleLifecycleWithdrawn, src.Lifecycle.State,
		"проекция изменила приёмник: жизненное состояние снято у источника")
	require.Len(t, src.Withdrawn, 1, "проекция изменила приёмник: ведомость переселения снята")
	require.Len(t, src.PrunedSelectorTypes, 1, "проекция изменила приёмник: ведомость вырезания снята")
	require.Len(t, src.RuleStates, 1, "проекция изменила приёмник: состояния правил сняты")
}
