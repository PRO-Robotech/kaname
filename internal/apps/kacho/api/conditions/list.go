// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package conditions

// list.go — сужение страницы условий до объектов, которые вызывающему видны.
//
// Единая модель видимости, паритет с account/group/project/role/service_account/
// user List: страница читается курсором из СВОЕЙ БД первой, затем каждый её
// объект отдельно сверяется с моделью прав:
//
//	visible(id) = Check(subj,"viewer","iam_condition:"+id)
//	            ∨ Check(subj,"v_list","iam_condition:"+id)
//
// # Что здесь было и почему это дефект
//
// List спрашивал ОДИН вопрос про проект (`viewer @ project:<id>`) и отдавал всю
// его страницу целиком, тогда как Get/Update/Delete тех же условий гейтятся
// per-object по `iam_condition` (записи каталога прав). `iam_condition` — не
// вспомогательная строка, а полноценный объект прав: у него объявлен весь набор
// глаголов прямыми usersets, он входит в каскад и является допустимой целью
// привязки (`iam.condition` → `iam_condition`). Значит выдача на подмножество
// условий выразима — а List её игнорировал и показывал участнику проекта все
// условия проекта.
//
// Ровно эту асимметрию — «Get требует per-object грант, а List отдаёт всё, что
// есть в проекте» — платформа уже назвала дефектом на storage; ради неё и
// существует гейт audit-list-filter, который и нашёл это место, как только iam
// в него завели.
//
// # Почему сужение никого не обделяет
//
// Проектная привязка материализуется реконсайлером в per-object tuple на каждое
// условие проекта (containment транзитивен), поэтому у участника проекта эти
// tuple есть. На этом же допущении уже девять остальных ресурсов iam.
//
// # Почему это лежит в пакете ресурса, а не в общем CRUD-сервисе
//
// Так устроены все остальные ресурсы iam (api/<ресурс>/list.go), и так сужение
// остаётся достижимым по графу вызовов от объявления List — то есть проверяемым
// гейтом. Общий сервис делит Get/Create/Update/Delete между собой; страница —
// принадлежность именно этого List.

import (
	"context"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kacho/services/iam/internal/authzfilter"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// conditionObjectType — тип объекта прав, под которым условия живут в модели.
const conditionObjectType = "iam_condition"

// filterVisibleConditionIDs — UNION `viewer ∪ v_list` на iam_condition,
// спрашиваемый ПРЯМО по каждому объекту страницы.
//
// Форма вопроса выбрана намеренно: «перечисли всё видимое и пересеки» режется
// server-side пределом хранилища прав без continuation, из-за чего собственная
// строка тенанта выпадала бы из выдачи навсегда (см. package-doc authzfilter).
//
// Fail-closed: пустой subject → пустое множество, у хранилища не спрашивают
// вовсе; ошибка хранилища → ошибка наверх, НИКОГДА не «не видно».
func filterVisibleConditionIDs(
	ctx context.Context,
	chk authzfilter.ObjectChecker,
	subject string,
	ids []string,
) (map[string]bool, error) {
	return authzfilter.VisibleSet(ctx, chk, subject, conditionObjectType, ids)
}

// conditionIDsOf проецирует страницу условий в голые id.
func conditionIDsOf(rows []domain.Condition) []string {
	out := make([]string, 0, len(rows))
	for _, c := range rows {
		out = append(out, string(c.ID))
	}
	return out
}

// principalSubject строит subject модели прав: `user:<id>` / `service_account:<id>`.
// Любой другой тип → "" (нерезолвимый subject → ничего не видно).
func principalSubject(p operations.Principal) string {
	switch p.Type {
	case "user":
		return "user:" + p.ID
	case "service_account":
		return "service_account:" + p.ID
	default:
		return ""
	}
}
