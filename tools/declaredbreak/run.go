// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package declaredbreak

import (
	"flag"
	"fmt"
	"io"
	"os"
)

// Run — исполнение адъюдикатора: доводы, вход buf, отчёт и код возврата.
//
// ФОРМА
//
//	[--ancestor-findings <вывод buf против предка> --ancestor-ref <ревизия> |
//	 --ancestor-unknown <причина>] <перечень объявленных разрывов>
//
// Флаги предка — сведение для отказа (Ancestor): находки против базы читаются со
// стандартного входа, как прежде, и вердикт выносится только по ним. Вывод против
// предка, который не прочитан или не разобран, вердикта не меняет — у каждой
// находки сказано «предок не установлен» с причиной.
//
// ИСХОДОВ ТРИ: 0 — чисто · 1 — находка · 2 — гейт НЕ СДЕЛАЛ СВОЕЙ РАБОТЫ (в том
// числе вызов вне формы).
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("adjudicate-declared-breaks", flag.ContinueOnError)
	fs.SetOutput(stderr)
	ancFindings := fs.String("ancestor-findings", "", "вывод buf breaking --error-format=json против общего предка")
	ancRef := fs.String("ancestor-ref", "", "ревизия общего предка головы и базы")
	ancUnknown := fs.String("ancestor-unknown", "", "почему общий предок не установлен")
	if err := fs.Parse(args); err != nil {
		_, _ = fmt.Fprintf(stderr, "ПРОВЕРКА НЕ ИСПОЛНЯЛАСЬ: вызов вне формы: %v\n", err)
		return 2
	}
	if fs.NArg() != 1 {
		_, _ = fmt.Fprintln(stderr, "ПРОВЕРКА НЕ ИСПОЛНЯЛАСЬ: нужен ровно один довод — "+
			"путь к перечню объявленных разрывов")
		return 2
	}
	known := *ancFindings != "" || *ancRef != ""
	if known && (*ancFindings == "" || *ancRef == "") {
		_, _ = fmt.Fprintln(stderr, "ПРОВЕРКА НЕ ИСПОЛНЯЛАСЬ: --ancestor-findings и --ancestor-ref "+
			"даются вместе — находки предка без его ревизии некому приписать")
		return 2
	}
	if known && *ancUnknown != "" {
		_, _ = fmt.Fprintln(stderr, "ПРОВЕРКА НЕ ИСПОЛНЯЛАСЬ: предок и установлен, и не установлен — "+
			"--ancestor-unknown исключает --ancestor-findings")
		return 2
	}

	decls, err := LoadDeclarations(fs.Arg(0))
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "ПРОВЕРКА НЕ ИСПОЛНЯЛАСЬ: %v\n", err)
		return 2
	}
	findings, err := ParseFindings(stdin)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "ПРОВЕРКА НЕ ИСПОЛНЯЛАСЬ: %v\n", err)
		return 2
	}
	res := Adjudicate(findings, decls)
	switch {
	case known:
		res.SetAncestor(loadAncestor(*ancFindings, *ancRef))
	case *ancUnknown != "":
		res.SetAncestor(Ancestor{Unknown: *ancUnknown})
	}
	_, _ = fmt.Fprint(stdout, res.Report())
	if !res.Clean() {
		return 1
	}
	return 0
}

// loadAncestor — вывод buf против предка. Не прочитан или не разобран — предок
// «не установлен» с причиной, а не «предмета нет».
func loadAncestor(path, ref string) Ancestor {
	f, err := os.Open(path) // #nosec G304 -- путь даёт вызывающий сценарий шага
	if err != nil {
		return Ancestor{Unknown: fmt.Sprintf("вывод buf против предка %s не прочитан: %v", ref, err)}
	}
	defer func() { _ = f.Close() }()
	got, err := ParseFindings(f)
	if err != nil {
		return Ancestor{Unknown: fmt.Sprintf("вывод buf против предка %s не разобран: %v", ref, err)}
	}
	return Ancestor{Ref: ref, Findings: got}
}
