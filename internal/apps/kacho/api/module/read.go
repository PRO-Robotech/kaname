// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package module

// read.go — `InternalModuleService.Get` и `List`: ЖИВОЕ множество и ничего сверх.
//
// # Снятых строк здесь нет BY CONSTRUCTION, а не фильтром на пути к клиенту
//
// Читатель отдаёт живое множество; снятая строка до сюда не доходит вовсе.
// Показ снятого вместе с его преемником — отдельный предмет, уже назначенный
// задаче-преемнику со своим предикатом, и делать его наполовину здесь значило бы
// объявить возможность, которой нет.
//
// # Пагинации нет НАМЕРЕННО
//
// Популяция — собственный каталог платформы: единицы модулей, десятки ресурсов,
// низкая сотня действий, и арендатор его не пишет вовсе. Курсор на такой
// популяции — механизм без предмета. Поэтому запрос НЕ несёт ни размера
// страницы, ни курсора: поле, принимаемое и никогда не читаемое, хуже
// отсутствующего.

import (
	"context"
	"fmt"
	"sort"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho-iam/internal/catalog"
	iamerr "github.com/PRO-Robotech/kacho-iam/internal/errors"
)

// liveSource — то, что нужно чтениям: ОДНО живое множество.
//
// Уже́, чем `CatalogStateSource`: чтения снятой половины не спрашивают вовсе, и
// объявить её здесь значило бы потребовать от композиции больше, чем читателю
// нужно.
type liveSource interface {
	ReadLiveCatalog(ctx context.Context) (catalog.Rows, error)
}

// GetUseCase — живые строки ОДНОГО модуля.
type GetUseCase struct {
	catalogs liveSource
	// adminCheck — гейт права. nil ⇒ fail-closed (см. authz.go).
	adminCheck adminChecker
}

// NewGetUseCase — конструктор.
func NewGetUseCase(c liveSource) *GetUseCase { return &GetUseCase{catalogs: c} }

// WithAdminChecker — провязка гейта права. Только композиционный корень.
func (uc *GetUseCase) WithAdminChecker(c adminChecker) *GetUseCase {
	uc.adminCheck = c
	return uc
}

// Execute — синхронное чтение живого множества модуля.
func (uc *GetUseCase) Execute(ctx context.Context, module string) (*iamv1.ModuleCatalog, error) {
	// ГЕЙТ ПРАВА — ПЕРВЫМ СТЕЙТМЕНТОМ: отказ приходит раньше разбора входа,
	// поэтому по коду ответа нельзя узнать, существует ли названный модуль.
	if err := requireClusterSystemAdmin(ctx, uc.adminCheck); err != nil {
		return nil, err
	}
	if module == "" {
		return nil, shared.InvalidArg("module", "required")
	}
	if uc.catalogs == nil {
		return nil, shared.MapRepoErr(iamerr.Wrapf(iamerr.ErrFailedPrecondition,
			"читатель каталога не провязан"))
	}
	live, err := uc.catalogs.ReadLiveCatalog(ctx)
	if err != nil {
		return nil, shared.MapRepoErr(fmt.Errorf("прочитать живой каталог: %w", err))
	}

	rows := rowsOfModule(live, module)
	if len(rows.Modules) == 0 {
		// Это собственный ресурс iam, поэтому полоса прямого чтения: строки нет —
		// `NOT_FOUND` контракт-тоном, а не отказ предусловия.
		return nil, shared.MapRepoErr(iamerr.Wrapf(iamerr.ErrNotFound,
			"Module %s not found", module))
	}

	out := &iamv1.ModuleCatalog{
		Module:    module,
		Resources: make([]*iamv1.ModuleResourceRow, 0, len(rows.Resources)),
		Verbs:     make([]*iamv1.ModuleVerbRow, 0, len(rows.Verbs)),
	}
	for _, r := range rows.Resources {
		// Имя ресурса идёт БЕЗ приставки модуля: модуль назван оболочкой один раз.
		out.Resources = append(out.Resources, &iamv1.ModuleResourceRow{
			Resource:   r.Resource,
			ObjectType: r.ObjectType,
		})
	}
	for _, v := range rows.Verbs {
		out.Verbs = append(out.Verbs, &iamv1.ModuleVerbRow{
			Resource:  v.Resource,
			Verb:      v.Verb,
			PerObject: v.PerObject,
		})
	}
	return out, nil
}

// ListUseCase — живые модули каталога с числами.
type ListUseCase struct {
	catalogs liveSource
	// adminCheck — гейт права. nil ⇒ fail-closed (см. authz.go).
	adminCheck adminChecker
}

// NewListUseCase — конструктор.
func NewListUseCase(c liveSource) *ListUseCase { return &ListUseCase{catalogs: c} }

// WithAdminChecker — провязка гейта права. Только композиционный корень.
func (uc *ListUseCase) WithAdminChecker(c adminChecker) *ListUseCase {
	uc.adminCheck = c
	return uc
}

// Execute — синхронное чтение перечня модулей.
func (uc *ListUseCase) Execute(ctx context.Context) (*iamv1.ListModulesResponse, error) {
	// ГЕЙТ ПРАВА — ПЕРВЫМ СТЕЙТМЕНТОМ, как и у трёх соседних глаголов.
	if err := requireClusterSystemAdmin(ctx, uc.adminCheck); err != nil {
		return nil, err
	}
	if uc.catalogs == nil {
		return nil, shared.MapRepoErr(iamerr.Wrapf(iamerr.ErrFailedPrecondition,
			"читатель каталога не провязан"))
	}
	live, err := uc.catalogs.ReadLiveCatalog(ctx)
	if err != nil {
		return nil, shared.MapRepoErr(fmt.Errorf("прочитать живой каталог: %w", err))
	}

	resources := make(map[string]int32, len(live.Modules))
	verbs := make(map[string]int32, len(live.Modules))
	for _, r := range live.Resources {
		resources[r.Module]++
	}
	for _, v := range live.Verbs {
		verbs[v.Module]++
	}

	modules := make([]string, len(live.Modules))
	copy(modules, live.Modules)
	// Порядок задан ЗДЕСЬ, а не унаследован от читателя: контракт объявляет
	// перечень НАБОРОМ, поэтому сравнивать его полагается по составу, — но
	// недетерминированный порядок двух вызовов над одним состоянием читался бы
	// как движение каталога тем, кто ведёт состояние.
	sort.Strings(modules)

	out := &iamv1.ListModulesResponse{Modules: make([]*iamv1.ModuleSummary, 0, len(modules))}
	for _, m := range modules {
		out.Modules = append(out.Modules, &iamv1.ModuleSummary{
			Module:            m,
			LiveResourceCount: resources[m],
			LiveVerbCount:     verbs[m],
		})
	}
	return out, nil
}
