// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzplan

// canonical.go — где лежит каноническая модель и как её найти.
//
// Живёт рядом с компилятором, а не у прибора, по одной причине: и продукт, и
// прибор обязаны читать ОДИН файл. Две копии обхода дерева разошлись бы молча —
// например, одна нашла бы модель во вложенном клоне, — и сравнение форм измеряло
// бы разные тексты.
//
// Путь читается только пробами и гейтами (компилятор — чистая функция от текста),
// поэтому обход дерева здесь допустим: в рантайме продукта его никто не зовёт.

import (
	"fmt"
	"os"
	"path/filepath"
)

// fgaModelRelPath — the canonical authorization model, relative to the monorepo
// root. The SAME single source of truth every other real-FGA proof in this tree
// reads (services/iam/internal/testsupport/fgatest). Its absence is a hard error:
// a comparison against a model this harness invented would measure nothing about
// the product.
const fgaModelRelPath = "proto/kacho/cloud/iam/v1/fga_model.fga"

// ResolveCanonicalModel walks up from the working directory to the monorepo root
// and returns the canonical DSL.
func ResolveCanonicalModel() (path string, dsl []byte, err error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", nil, err
	}
	return ResolveCanonicalModelFrom(wd)
}

// ResolveCanonicalModelFrom walks up from start to the monorepo root and returns
// the canonical DSL.
//
// Обходчик и постоянная относительного пути здесь ОДНИ на обе точки входа: вторая
// копия обхода разошлась бы с первой молча — например, нашла бы модель во
// вложенном клоне, — и сравнение форм измеряло бы разные тексты.
//
// Параметр — КОРЕНЬ ДЕРЕВА, а не путь канона, и различие несущее (#1089, §2 п. 2):
// подменить канон снимком, лежащим рядом со сверщиком, нечем — предъявить такой
// путь этой подписи невозможно. Указать можно лишь целое дерево, у которого канон
// лежит по каноническому относительному пути; ровно этим и пользуется инъекция,
// подавая своё дерево намеренно.
func ResolveCanonicalModelFrom(start string) (path string, dsl []byte, err error) {
	dir := start
	for {
		cand := filepath.Join(dir, fgaModelRelPath)
		if _, statErr := os.Stat(cand); statErr == nil {
			b, rerr := os.ReadFile(cand) // #nosec G304 -- fixed in-repo path, tool-only
			if rerr != nil {
				return cand, nil, rerr
			}
			return cand, b, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", nil, fmt.Errorf("canonical model %s not found walking up from %s", fgaModelRelPath, start)
		}
		dir = parent
	}
}
