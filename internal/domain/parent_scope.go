// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

// parent_scope.go — ВЫВОД РОДИТЕЛЯ регистрируемого объекта и сверка сведений
// модуля с ним (kaname#982, приёмка `kaname-derives-the-parent-of-a-registered-object.md`,
// Р5–Р7).
//
// Родителя объекта kaname выводит из своих данных — из опоры регистрации
// (проекта либо зарегистрированного контейнера) и своей иерархии, — а сведения,
// присланные модулем (поле проекта, поле аккаунта, цепь предков), только СВЕРЯЕТ:
// опущенное не дописывается, расходящееся отвергается.

// ContainerScope — ЗАПИСАННАЯ область зарегистрированного объекта-контейнера:
// проект его строки зеркала (при пустом — звено `project` его цепи) и аккаунт
// этого проекта. Registered=false — контейнер не зарегистрирован.
type ContainerScope struct {
	Registered bool
	ProjectID  string // пусто — проект контейнера не выводится
	AccountID  string // пусто — аккаунт проекта не выводится
}

// ParentHierarchy — иерархия kaname от опоры, H(a) приёмки: звенья от опоры
// вверх дословно (`<тип>:<id>`), проект и аккаунт H.
type ParentHierarchy struct {
	Links     []string
	ProjectID string // пусто — у H нет проекта
	AccountID string // пусто — у H нет аккаунта
}

// ProjectHierarchy — H опоры-проекта: `[project:P, account:A]`.
func ProjectHierarchy(projectID, accountID string) ParentHierarchy {
	return ParentHierarchy{
		Links:     []string{"project:" + projectID, "account:" + accountID},
		ProjectID: projectID,
		AccountID: accountID,
	}
}

// ContainerHierarchy — H опоры-контейнера (`<тип>:<id>`): `[K, project:P_K,
// account:A_K]`, без звеньев, которых записанная область не выводит. Контейнер
// без проекта даёт `[K]`: ребёнок не бывает в области шире, чем записана у его
// контейнера.
func ContainerHierarchy(container string, scope ContainerScope) ParentHierarchy {
	h := ParentHierarchy{Links: []string{container}}
	if scope.ProjectID == "" {
		return h
	}
	h.Links = append(h.Links, "project:"+scope.ProjectID)
	h.ProjectID = scope.ProjectID
	if scope.AccountID != "" {
		h.Links = append(h.Links, "account:"+scope.AccountID)
		h.AccountID = scope.AccountID
	}
	return h
}

// ParentClaim — сведения модуля о родителе регистрируемого объекта.
type ParentClaim struct {
	ProjectID string
	AccountID string
	Chain     []string
}

// Admits — сведения согласны с иерархией (Р6): поле проекта пусто либо равно
// проекту H, поле аккаунта пусто либо равно аккаунту H, цепь — подпоследовательность
// звеньев H (каждое звено есть звено H дословно, порядок H сохранён, повтора и
// звена вне H нет). У H без проекта (аккаунта) поле принимается только пустым.
func (h ParentHierarchy) Admits(c ParentClaim) bool {
	if c.ProjectID != "" && c.ProjectID != h.ProjectID {
		return false
	}
	if c.AccountID != "" && c.AccountID != h.AccountID {
		return false
	}
	next := 0
	for _, link := range c.Chain {
		for next < len(h.Links) && h.Links[next] != link {
			next++
		}
		if next == len(h.Links) {
			return false
		}
		next++
	}
	return true
}
