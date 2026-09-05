// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// run.go — исполнение двух режимов, ПОРОЖДЕНИЯ и СВЕРКИ, одним кодом.
//
// Порождение и сверка обязаны быть одной функцией: два кода об одном предмете
// разойдутся молча и разойдутся именно там, где расхождение не видно — оба
// отвечают «годно» на годном.
//
// ─────────────────────────────────────────────────────────────────────────────
// ИСХОДОВ ЧЕТЫРЕ, И ТРЕТИЙ НЕ ЕСТЬ ВЕРДИКТ
//
//	0  сходится   — порождённое равно лежащему в дереве;
//	1  находка    — расхождение, неопознанная лицензия, пустая таблица, нет меток;
//	2  без предмета — сверять нечего (сборщик не назвал модулей, таблица пуста):
//	                  «ноль находок» обязано быть отличимо от «ноль прочитанного»;
//	3  не исполнялось — вызов разобрать не удалось.
package operatordocs

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/config"
)

// Коды возврата. Читаются вызывающим; вид вывода вердиктом не является.
const (
	ExitSynced  = 0
	ExitFinding = 1
	ExitVoid    = 2
	ExitNotRun  = 3
)

// Имена документов относительно корня дерева iam.
const (
	NoticesFile = "THIRD-PARTY-NOTICES.md"
	InstallFile = "INSTALL.md"
)

// Options — что делать и над чем.
type Options struct {
	Root  string
	Write bool
	Out   io.Writer
	// Table — таблица обязательных величин. Пустая означает «действующая»
	// (`config.RequiredSettings`).
	//
	// Поле существует ради ИНЪЕКЦИИ: гейт обязан быть способен упасть, а
	// доказать это можно только подачей ему битого входа на настоящем дереве.
	// Без этого шва инъекция дотянулась бы лишь до отдельных функций, и о
	// связке «таблица → блок → файл» — то есть о том, что гейт и стережёт, —
	// нельзя было бы утверждать ничего.
	Table []config.RequiredSetting
}

// Run исполняет порождение либо сверку и возвращает код исхода.
func Run(o Options) int {
	if o.Out == nil {
		o.Out = os.Stdout
	}
	if strings.TrimSpace(o.Root) == "" {
		_, _ = fmt.Fprintln(o.Out, "не назван корень дерева iam (-root) — исполнять нечего")
		return ExitNotRun
	}
	if _, err := os.Stat(filepath.Join(o.Root, "LICENSE")); err != nil {
		_, _ = fmt.Fprintf(o.Out, "корень %q не похож на дерево iam (нет LICENSE): %v\n", o.Root, err)
		return ExitNotRun
	}

	var findings []string
	void := true

	// ── перечень третьих сторон ───────────────────────────────────────────────
	notices, nf, ncensus, err := BuildNotices(o.Root)
	if err != nil {
		_, _ = fmt.Fprintf(o.Out, "перечень третьих сторон не построен: %v\n", err)
		return ExitNotRun
	}
	_, _ = fmt.Fprintf(o.Out, "третьи стороны: %s\n", ncensus)
	findings = append(findings, nf...)
	if ncensus.Modules > 0 {
		void = false
		findings = append(findings, syncFile(o, NoticesFile, notices, func(disk string) (string, error) {
			return notices, nil
		})...)
	}

	// ── обязательные величины ────────────────────────────────────────────────
	table := o.Table
	if table == nil {
		table = requiredSettings()
	}
	block, sf, scensus := BuildSettingsBlock(table)
	_, _ = fmt.Fprintf(o.Out, "обязательные величины: %s\n", scensus)
	findings = append(findings, sf...)
	if scensus.Rows > 0 {
		void = false
		findings = append(findings, syncFile(o, InstallFile, "", func(disk string) (string, error) {
			return SpliceBlock(disk, block)
		})...)
	}

	if void {
		_, _ = fmt.Fprintln(o.Out, "СВЕРЯТЬ НЕЧЕГО: ни одного модуля и ни одной строки таблицы — "+
			"это НЕ вердикт о дереве, а отсутствие предмета")
		return ExitVoid
	}
	if len(findings) > 0 {
		_, _ = fmt.Fprintf(o.Out, "\nНАХОДОК %d:\n", len(findings))
		for _, f := range findings {
			_, _ = fmt.Fprintf(o.Out, "  · %s\n", f)
		}
		return ExitFinding
	}
	_, _ = fmt.Fprintln(o.Out, "сходится: порождённое равно лежащему в дереве")
	return ExitSynced
}

// syncFile сверяет либо записывает один документ. `want` строит желаемое
// содержимое из лежащего на диске (для блочной подстановки) либо игнорирует его
// (для целиком порождаемого файла).
func syncFile(o Options, name, whole string, want func(disk string) (string, error)) []string {
	path := filepath.Join(o.Root, name)
	// #nosec G304 -- name приходит от вызывающего одним из ДВУХ значений, и оба —
	// константы этого пакета (NoticesFile, InstallFile); третьего вызова syncFile в
	// пакете нет. o.Root отвергнут выше в Run, если в нём нет LICENSE, то есть если
	// это не дерево iam.
	disk, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			if !o.Write {
				return []string{name + " — документа в дереве НЕТ; порождённый перечень некуда положить " +
					"(порождение: `make -C services/iam operator-docs`)"}
			}
			if whole == "" {
				return []string{name + " — документа в дереве нет, а его проза не порождается: " +
					"заведите файл с метками блока и повторите"}
			}
			if err := os.WriteFile(path, []byte(whole), 0o600); err != nil {
				return []string{fmt.Sprintf("%s — не записан: %v", name, err)}
			}
			_, _ = fmt.Fprintf(o.Out, "%s — записан\n", name)
			return nil
		}
		return []string{fmt.Sprintf("%s — не прочитан: %v", name, err)}
	}

	wanted, err := want(string(disk))
	if err != nil {
		return []string{fmt.Sprintf("%s — %v", name, err)}
	}
	if wanted == string(disk) {
		return nil
	}
	if o.Write {
		if err := os.WriteFile(path, []byte(wanted), 0o600); err != nil {
			return []string{fmt.Sprintf("%s — не записан: %v", name, err)}
		}
		_, _ = fmt.Fprintf(o.Out, "%s — обновлён\n", name)
		return nil
	}
	return []string{name + " — РАСХОДИТСЯ с порождённым: в дереве лежит не то, что производит сегодняшний " +
		"источник. Обычная причина — источник изменился, а документ нет. Починка: " +
		"`make -C services/iam operator-docs`"}
}
