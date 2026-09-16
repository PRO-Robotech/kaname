// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"fmt"
	"io"
	"io/fs"

	"github.com/pressly/goose/v3"

	"github.com/PRO-Robotech/corelib/migratorcli"

	"github.com/PRO-Robotech/kaname/internal/migrations"
)

// СРЕДСТВО МИГРАЦИЙ ОТКАЗЫВАЕТ В ОБРАТНОМ ХОДЕ, КОТОРЫЙ СНЁС БЫ СВОД (#130).
//
// # Что стережётся
//
// Откатная половина свода — `DROP SCHEMA kaname CASCADE`, самый разрушительный
// оператор дерева. Среди сносимого — удостоверения вида SECRET: такое
// удостоверение предъявляется арендатору ОДИН раз, в хранилище лежит только его
// свёртка, и удалённая строка не восстанавливается НИЧЕМ. Обычная потеря данных
// обратима восстановлением из копии; эта — нет.
//
// # Почему страж здесь, а не там, где он уже есть
//
// Он есть и там: первым оператором откатной половины свода стоит перепись живых
// удостоверений, и на ненулевом счёте она отказывает. У неё ОКНО — перепись и
// снос суть два оператора, замка между ними нет, поэтому удостоверение,
// зафиксированное в промежутке, уничтожается, а откат при этом проходит успехом.
// Закрыть окно на том же месте нельзя: свод ПРИМЕНЁН, а применённую миграцию не
// правят (запрет #5).
//
// Значит окно закрывается там, где разрушительный путь ещё достижим, — у
// средства миграций, ДО единого оператора. Тогда окна нет вовсе, а не «оно стало
// уже».
//
// # Почему отказ безусловный, а не «с одобрения»
//
// Одобрение — по образцу того, которым путь наката одобряет снос таблицы, — окна
// НЕ закрывает: одобривший попадает ровно в тот же промежуток между переписью и
// сносом. Оно передвигает окно за лишний шаг оператора, и только. Снос схемы
// целиком — операция базы, а не продуктовый глагол службы: тому, кому он нужен
// осознанно, база доступна и без этого средства.
//
// # Чего страж НЕ отменяет
//
// Штатную процедуру отката выкатки. Она откатывает то, что легло ПОВЕРХ свода
// (`down --target <версия поверх свода>`), и этой формы страж не касается вовсе —
// иначе он отвергал бы всё, и его отрицание ничего не утверждало бы.
//
// `head` зовётся ТОЛЬКО когда цель не названа: у названной цели вопроса к базе
// нет, и открывать соединение ради него значило бы ждать базу две минуты там, где
// ответ известен заранее.
func refuseRollbackOfTheBaseline(
	ctx context.Context,
	migrationsFS fs.FS,
	target string,
	head func(context.Context) (int64, error),
) error {
	baseline, err := migrations.BaselineVersion(migrationsFS)
	if err != nil {
		return err
	}

	if target != "" {
		// Разбор — ТА ЖЕ функция, которой читает цель сам накат: своя редакция
		// приняла бы то, что он отвергнет, либо наоборот.
		v, perr := migratorcli.ParseTargetVersion(target)
		if perr != nil {
			return perr
		}
		// `DownTo(v)` откатывает всё, чья версия СТРОГО БОЛЬШЕ v. Свод уцелеет
		// ровно тогда, когда цель не ниже его версии.
		if v >= baseline {
			return nil
		}
		return baselineRollbackRefusal(baseline, fmt.Sprintf("down --target %s", target))
	}

	// `down` без цели откатывает РОВНО ОДНУ, самую позднюю миграцию. Она и есть
	// свод ровно тогда, когда поверх свода не лежит ничего применённого.
	current, herr := head(ctx)
	if herr != nil {
		// «НЕ СМОГ СПРОСИТЬ» НЕ ЕСТЬ «МОЖНО». Непрочитанная голова цепочки —
		// отказ: пропустив её, страж пропустил бы и снос.
		return fmt.Errorf("refusing to roll back: the applied head of the migration chain "+
			"could not be read, so whether this step would drop the baseline is UNKNOWN: %w", herr)
	}
	if current != baseline {
		return nil
	}
	return baselineRollbackRefusal(baseline, "down (one step back)")
}

// baselineRollbackRefusal — ОДИН текст на обе формы обращения.
//
// Он называет четыре разных слагаемых: что произойдёт · почему это необратимо ·
// что набрать вместо · и что снос схемы целиком этим средством не делается.
// Отказ, называющий только «нельзя», обходят — и обходят ровно тем, ради
// предотвращения чего он стоит.
func baselineRollbackRefusal(baseline int64, requested string) error {
	return fmt.Errorf("REFUSING to roll the iam baseline back (baseline version %d): its down half "+
		"drops the whole `kaname` schema. For SECRET credentials that is IRREVERSIBLE — such a "+
		"credential is shown to the tenant once and only its digest is stored, so the rows this "+
		"would destroy cannot be restored from any backup, and re-issuing yields a DIFFERENT "+
		"credential every holder must be reconfigured for. WAY OUT: roll back only what lies ON TOP "+
		"of the baseline — `down --target %d` keeps the baseline applied, and that is the form the "+
		"deployment page means. Tearing the whole schema down is a database operation, not a product "+
		"verb: this tool does not perform it. Requested: %s", baseline, baseline, requested)
}

// headVersionFrom — читатель применённой головы цепочки.
//
// Соединение открывается ЛЕНИВО, внутри замыкания: страж зовёт его только на
// форме без цели, а на `--target` не зовёт вовсе.
//
// Уведомления сервера уходят в никуда осознанно: чтение версии их не производит,
// а перепись доставленного печатает сам накат — вторая перепись в том же выводе
// сделала бы один отчёт двумя.
func headVersionFrom(opts *rootOptions, migrationsFS fs.FS) func(context.Context) (int64, error) {
	return func(ctx context.Context) (int64, error) {
		spec, err := migratorcli.ResolveDialectSpec(opts.dialect)
		if err != nil {
			return 0, err
		}
		if err := migratorcli.SetupGoose(migrationsFS, spec); err != nil {
			return 0, err
		}
		dsn, err := migratorcli.ResolveDSN(opts.dsn, configDSN)
		if err != nil {
			return 0, err
		}
		db, err := migratorcli.OpenDB(ctx, dsn, spec, migratorcli.NewNoticeRelay(serviceName, io.Discard))
		if err != nil {
			return 0, err
		}
		defer func() { _ = db.Close() }()
		return goose.GetDBVersionContext(ctx, db)
	}
}
