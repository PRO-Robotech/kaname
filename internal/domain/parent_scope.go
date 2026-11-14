// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/PRO-Robotech/kaname/internal/hierarchy"
)

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

// ParentHierarchyNode содержит только прочитанные сервером данные. Scope —
// сохранённый предел области, Parents — полный набор непосредственных фактов
// указателей, проверенных по текущей политике типа. ParentClaim сюда не входит.
// У project узла AccountID берётся из owning строки проекта, Parents пуст.
type ParentHierarchyNode struct {
	Ref     string
	Scope   ContainerScope
	Parents []string
}

type ParentHierarchyGraph map[string]ParentHierarchyNode

// Эти пределы ограничивают весь граф, а не отдельную страницу или ветвь.
// Глубина хранимой цепи и число указателей остаются общими с моделью.
const (
	MaxParentHierarchyNodes = 128
	MaxParentHierarchyEdges = 256
	MaxParentHierarchyPaths = 64
	MaxParentHierarchyReads = MaxParentHierarchyNodes * (2 + hierarchy.MaxImmediateParents)
)

var (
	ErrParentHierarchyIncomplete = errors.New("parent hierarchy source incomplete")
	ErrParentHierarchyInvalid    = errors.New("parent hierarchy source invalid")
)

// BuildParentHierarchies строит отдельный упорядоченный путь каждой ветви.
// Сохранённая цепь не является ребром графа, а утверждение клиента не является
// доказательством. Ни одна частичная ветвь не возвращается при ошибке другой.
// DP14: контейнер без сохранённого проекта даёт только [K], даже если его
// указатели достигают проекта. Внутри уже scoped пути такая граница неполна.
func BuildParentHierarchies(anchor string, graph ParentHierarchyGraph) ([]ParentHierarchy, error) {
	if len(graph) > MaxParentHierarchyNodes {
		return nil, fmt.Errorf("%w: node budget", ErrParentHierarchyInvalid)
	}
	edges := 0
	for ref, node := range graph {
		if ref != node.Ref || !validParentHierarchyRef(ref) || len(node.Parents) > hierarchy.MaxImmediateParents {
			return nil, fmt.Errorf("%w: node %q", ErrParentHierarchyInvalid, ref)
		}
		edges += len(node.Parents)
		if edges > MaxParentHierarchyEdges {
			return nil, fmt.Errorf("%w: edge budget", ErrParentHierarchyInvalid)
		}
		for _, parent := range node.Parents {
			if !validParentHierarchyRef(parent) {
				return nil, fmt.Errorf("%w: parent %q", ErrParentHierarchyInvalid, parent)
			}
		}
	}
	var out []ParentHierarchy
	stack := map[string]bool{}
	var walk func(string, []string, []ContainerScope) error
	walk = func(ref string, prefix []string, ceilings []ContainerScope) error {
		if stack[ref] {
			return fmt.Errorf("%w: cycle at %q", ErrParentHierarchyInvalid, ref)
		}
		node, ok := graph[ref]
		if !ok || !node.Scope.Registered {
			return fmt.Errorf("%w: node %q", ErrParentHierarchyIncomplete, ref)
		}
		typ, id, _ := strings.Cut(ref, ":")
		if typ == "project" {
			if node.Scope.ProjectID != id || len(node.Parents) != 0 {
				return fmt.Errorf("%w: project %q", ErrParentHierarchyInvalid, ref)
			}
			if node.Scope.AccountID == "" {
				return fmt.Errorf("%w: owner of %q", ErrParentHierarchyIncomplete, ref)
			}
			if !validParentHierarchyID(node.Scope.AccountID) {
				return fmt.Errorf("%w: project owner", ErrParentHierarchyInvalid)
			}
			if len(prefix)+2 > hierarchy.MaxStoredParentLinks {
				return fmt.Errorf("%w: path depth", ErrParentHierarchyInvalid)
			}
			for _, ceiling := range ceilings {
				if ceiling.ProjectID != id || ceiling.AccountID != node.Scope.AccountID {
					return fmt.Errorf("%w: saved scope disagrees with %q", ErrParentHierarchyInvalid, ref)
				}
			}
			links := append(append([]string(nil), prefix...), ref, "account:"+node.Scope.AccountID)
			out = append(out, ParentHierarchy{Links: links, ProjectID: id, AccountID: node.Scope.AccountID})
		} else {
			if node.Scope.ProjectID == "" {
				if node.Scope.AccountID != "" {
					return fmt.Errorf("%w: account without project", ErrParentHierarchyInvalid)
				}
				if len(prefix) != 0 {
					return fmt.Errorf("%w: intermediate saved scope %q", ErrParentHierarchyIncomplete, ref)
				}
				out = append(out, ParentHierarchy{Links: []string{ref}})
			} else {
				if !validParentHierarchyID(node.Scope.ProjectID) {
					return fmt.Errorf("%w: saved project", ErrParentHierarchyInvalid)
				}
				if node.Scope.AccountID == "" || len(node.Parents) == 0 {
					return fmt.Errorf("%w: scoped container %q", ErrParentHierarchyIncomplete, ref)
				}
				if len(prefix)+1 >= hierarchy.MaxStoredParentLinks {
					return fmt.Errorf("%w: path depth", ErrParentHierarchyInvalid)
				}
				stack[ref] = true
				parents := append([]string(nil), node.Parents...)
				sort.Strings(parents)
				next := append(append([]string(nil), prefix...), ref)
				nextCeilings := append(append([]ContainerScope(nil), ceilings...), node.Scope)
				for i, parent := range parents {
					if i > 0 && parent == parents[i-1] {
						continue
					}
					if err := walk(parent, next, nextCeilings); err != nil {
						return err
					}
				}
				delete(stack, ref)
			}
		}
		if len(out) > MaxParentHierarchyPaths {
			return fmt.Errorf("%w: path budget", ErrParentHierarchyInvalid)
		}
		return nil
	}
	if !validParentHierarchyRef(anchor) {
		return nil, fmt.Errorf("%w: anchor", ErrParentHierarchyInvalid)
	}
	if err := walk(anchor, nil, nil); err != nil {
		return nil, err
	}
	return out, nil
}

func validParentHierarchyRef(ref string) bool {
	typ, id, ok := strings.Cut(ref, ":")
	if !ok || typ == "" || !validParentHierarchyID(id) {
		return false
	}
	for i, r := range typ {
		if (r < 'a' || r > 'z') && (i == 0 || (r < '0' || r > '9') && r != '_') {
			return false
		}
	}
	switch typ {
	case "account", "cluster", "user", "service_account", "group", "system_class":
		return false
	}
	return true
}

func validParentHierarchyID(id string) bool {
	return id != "" && !strings.ContainsAny(id, ":#* \t\r\n")
}
