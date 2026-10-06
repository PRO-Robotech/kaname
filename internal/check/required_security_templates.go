// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// required_security_templates.go — гейт «обязательный класс» (приёмка NTF-2,
// kacho#2917, Р3, NTF2-99 (а), (в), (г); замысел issue-2917, З19; полоса F5).
//
// # Предмет
//
// Перечень обязательного класса `required-security.yaml` каталога шаблонов
// kaname — не производное от шаблонов: его 24 имени сверены с таблицей Р3, и он
// держит, что ни одно письмо этой таблицы не стало отключаемым. Гейт красен,
// если имя перечня объявлено не классом security (а), если перечень пуст (в)
// или если в нём имя, шаблона которого в каталоге нет (г).
//
// Каталог и перечень читает ЕДИНСТВЕННЫЙ валидатор формата — corelib
// `notify/spec` (NTF1-A09): разбора notification.yaml и перечня здесь нет.
// Форму перечня (последовательность имён без повторов) судит он же; гейт судит
// смысл.
//
// Отказ прогона (каталога нет, валидатор отверг каталог, перечня нет, в
// каталоге ни одного шаблона) — ошибка, а не находка: зелёный на непрочитанном
// каталоге неотличим от зелёного на прочитанном.
package check

import (
	"fmt"
	"os"
	"path"
	"path/filepath"

	"github.com/PRO-Robotech/corelib/notify/spec"
)

// RequiredSecurityCatalog — каталог шаблонов kaname от корня дерева: владелец
// вывода генератора — пакет функций постановки feedgen (замысел З1).
const RequiredSecurityCatalog = "internal/apps/kaname/mail/feedgen/notifications"

// Нарушения гейта обязательного класса — часть находки.
const (
	requiredSecurityNotSecurity = "класс не security — письмо обязательного класса стало отключаемым"
	requiredSecurityEmptyList   = "пустой перечень — обязательный класс ничего не держит"
	requiredSecurityNoTemplate  = "имя без шаблона — в каталоге шаблона с этим именем нет"
)

// RequiredSecurityFinding — находка гейта: файл от корня дерева, шаблон (пусто
// у находки о перечне целиком) и нарушенное.
type RequiredSecurityFinding struct {
	File      string
	Template  string
	Violation string
}

// String — находка одной строкой: файл · шаблон · нарушенное.
func (f RequiredSecurityFinding) String() string {
	if f.Template == "" {
		return f.File + " · " + f.Violation
	}
	return f.File + " · " + f.Template + " · " + f.Violation
}

// RequiredSecurityReport — исход гейта и объём осмотренного.
type RequiredSecurityReport struct {
	// List — перечень от корня дерева.
	List string
	// Catalog — каталог шаблонов от корня дерева.
	Catalog string
	// Names — имена перечня в порядке файла.
	Names []string
	// TemplatesRead — прочитано notification.yaml каталога.
	TemplatesRead int
	// Findings — находки.
	Findings []RequiredSecurityFinding
}

// AuditRequiredSecurityTemplates судит перечень обязательного класса каталога
// шаблонов kaname под корнем дерева root.
func AuditRequiredSecurityTemplates(root string) (RequiredSecurityReport, error) {
	r := RequiredSecurityReport{
		List:    path.Join(RequiredSecurityCatalog, spec.RequiredSecurityFile),
		Catalog: RequiredSecurityCatalog,
	}
	dir := filepath.Join(root, filepath.FromSlash(RequiredSecurityCatalog))
	fi, err := os.Stat(dir)
	if err != nil {
		return r, fmt.Errorf("каталог шаблонов %s под %s не читается: %w", RequiredSecurityCatalog, root, err)
	}
	if !fi.IsDir() {
		return r, fmt.Errorf("каталог шаблонов %s под %s — не каталог", RequiredSecurityCatalog, root)
	}
	cat, census, err := spec.Load(dir)
	if err != nil {
		return r, fmt.Errorf("каталог шаблонов %s отвергнут валидатором notify/spec: %w", RequiredSecurityCatalog, err)
	}
	r.TemplatesRead = census.Templates
	if r.TemplatesRead == 0 {
		return r, fmt.Errorf("в каталоге %s ни одного шаблона — судить перечень не о чем", RequiredSecurityCatalog)
	}
	if cat.RequiredSecurity == nil {
		return r, fmt.Errorf("перечня %s нет — обязательный класс не объявлен", r.List)
	}
	r.Names = append([]string(nil), cat.RequiredSecurity.Names...)
	if len(r.Names) == 0 {
		r.Findings = append(r.Findings, RequiredSecurityFinding{File: r.List, Violation: requiredSecurityEmptyList})
		return r, nil
	}
	classOf := make(map[string]spec.Class, len(cat.Templates))
	for _, tpl := range cat.Templates {
		classOf[tpl.Name] = tpl.Class
	}
	for _, name := range r.Names {
		class, ok := classOf[name]
		switch {
		case !ok:
			r.Findings = append(r.Findings, RequiredSecurityFinding{File: r.List, Template: name, Violation: requiredSecurityNoTemplate})
		case class != spec.ClassSecurity:
			r.Findings = append(r.Findings, RequiredSecurityFinding{
				File:      path.Join(RequiredSecurityCatalog, name, "notification.yaml"),
				Template:  name,
				Violation: requiredSecurityNotSecurity + " (объявлен " + string(class) + ")",
			})
		}
	}
	return r, nil
}
