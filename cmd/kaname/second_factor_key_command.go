// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// second_factor_key_command.go — переобёртка секретов второго фактора,
// достижимая ОПЕРАТОРОМ (kaname#259 п.3).
//
//	kaname second-factor-key rewrap   каждый секрет — под первый ключ перечня
//
// # Зачем
//
// Перечень `authn.second-factor-encryption-key-hex` меняет ключ обёртки без
// простоя — новый первым, прежний следом, — но прежний ключ из перечня снять
// нельзя, пока им обёрнут хоть один секрет: сняв, служба отдаёт 503 каждому
// такому человеку. Команда переносит каждый секрет под ПЕРВЫЙ ключ перечня;
// после исхода `done` прежний ключ не читает ни одной строки. Порядок смены
// ключа для оператора — страница «Смена ключа обёртки второго фактора»
// (`docs/content/advanced/second-factor-wrapping-key.mdx`).
//
// # Почему команда процесса, а не вызов службы
//
// Та же причина, что у `signing-key`: команда идёт тем же путём, каким идёт
// служба, — та же загрузка и тот же страж настройки (main), тот же страж
// посадки до первого соединения, ТОТ ЖЕ перечень ключей обёртки той же ручки и
// тот же проверяющий, — и меняет ТЕ ЖЕ строки, которые читают реплики. Право
// на действие — обладание настройкой службы: адресом и удостоверением её базы
// и перечнем ключей обёртки; меньшего здесь не выражается.
//
// # Пределы
//
// Срока на всю команду НЕТ, и это решение, а не пропуск: работа прохода
// пропорциональна числу людей с фактором, и любой общий срок был бы либо
// короче прохода по большой базе, либо бессмысленно длинным. Ограничена
// КАЖДАЯ операция: связь с базой — secondFactorKeyConnectTimeout, каждое
// обращение прохода к хранилищу — secondFactorRewrapCallTimeout. Остановка
// (SIGTERM, SIGINT) прерывает проход между заменами; сделанное зафиксировано,
// и каждая строка читаема перечнем.
//
// # Коды возврата
//
//	0  каждый секрет под первым ключом перечня (`outcome=done`);
//	1  проход прошёл, но не всё переехало (`outcome=partial`): секреты, которых
//	   не открывает ни один ключ перечня, либо строки, не устоявшиеся за бюджет
//	   замен. Прежние ключи из перечня НЕ снимаются;
//	3  вердикта нет (`outcome=not-run` либо отказ до прохода): вызов не
//	   разобран, посадка без полосы входа, перечень не задан, страж посадки не
//	   принял, база недоступна либо отказала посреди. Повтор безопасен.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"time"

	coredb "github.com/PRO-Robotech/corelib/db"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/secondfactorwrap"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/PRO-Robotech/kaname/internal/keywrap"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/totpverify"
)

// Коды возврата команды.
const (
	secondFactorKeyExitDone    = 0
	secondFactorKeyExitPartial = 1
	secondFactorKeyExitNotRun  = 3
)

// secondFactorKeyCommandName — имя подкоманды процесса.
const secondFactorKeyCommandName = "second-factor-key"

// secondFactorRewrapPage — строк за одно чтение прохода. Одна страница — одно
// чтение по диапазону первичного ключа и столько же замен по одной строке;
// пятьсот строк читаются много быстрее предела вызова и держат число чтений
// на миллион людей в двух тысячах.
const secondFactorRewrapPage = 500

// secondFactorRewrapCallTimeout — предел КАЖДОГО обращения прохода к
// хранилищу: чтения страницы, замены, перечитывания. Замена ждёт замка строки,
// пока служба держит её в своей транзакции, — это мгновения; десять секунд
// много больше и короче того, что оператор готов ждать, не зная исхода.
const secondFactorRewrapCallTimeout = 10 * time.Second

// secondFactorKeyConnectTimeout — предел связи с базой до прохода.
const secondFactorKeyConnectTimeout = 10 * time.Second

const secondFactorKeyUsage = "kaname second-factor-key rewrap\n" +
	"  rewrap — каждый секрет второго фактора, обёрнутый не первым ключом перечня\n" +
	"           authn.second-factor-encryption-key-hex, переобёртывается первым; секрет не меняется\n" +
	"Коды возврата: 0 каждый секрет под первым ключом · 1 не всё переехало · 3 не исполнялось"

// runSecondFactorKeyCommand исполняет подкоманду и возвращает код возврата.
//
// Разбор вызова и все стражи — ДО первого соединения: неверный вызов и
// незаданный перечень не стоят открытия базы, а их отказ — «не исполнялось».
func runSecondFactorKeyCommand(ctx context.Context, cfg config.Config, args []string, out io.Writer, logger *slog.Logger) int {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(out, secondFactorKeyUsage)
		return secondFactorKeyExitNotRun
	}
	if args[0] != "rewrap" {
		_, _ = fmt.Fprintf(out, "неизвестное действие %q\n%s\n", args[0], secondFactorKeyUsage)
		return secondFactorKeyExitNotRun
	}
	fs := flag.NewFlagSet("kaname "+secondFactorKeyCommandName+" rewrap", flag.ContinueOnError)
	fs.SetOutput(out)
	if err := fs.Parse(args[1:]); err != nil {
		_, _ = fmt.Fprintln(out, secondFactorKeyUsage)
		return secondFactorKeyExitNotRun
	}
	if fs.NArg() > 0 {
		_, _ = fmt.Fprintf(out, "лишние аргументы: %v\n%s\n", fs.Args(), secondFactorKeyUsage)
		return secondFactorKeyExitNotRun
	}
	// Второй фактор живёт в полосе входа, а она поднимается ровно там, где её
	// поднимает служба (loginLaneWanted): на иной посадке секретов под этим
	// перечнем служба не держит, и проход судил бы чужое.
	if !loginLaneWanted(cfg) {
		_, _ = fmt.Fprintf(out, "второго фактора на этой посадке нет (%s=%s): полоса входа поднимается только под %s — действовать не над чем\n",
			config.IdentityProviderSetting, cfg.AuthN.IdentityProvider, config.IdentityProviderOwn)
		return secondFactorKeyExitNotRun
	}
	// Перечень — тем же разбором той же ручки, что у службы (loginlane.go):
	// другой перечень оборачивал бы то, чего реплики не откроют.
	ring, err := cfg.AuthN.ResolveSecondFactorEncryptionKeys()
	if err != nil {
		_, _ = fmt.Fprintf(out, "перечень ключей обёртки второго фактора: %v\n", err)
		return secondFactorKeyExitNotRun
	}
	wrapper, err := keywrap.New(ring...)
	if err != nil {
		_, _ = fmt.Fprintf(out, "перечень ключей обёртки второго фактора: %v\n", err)
		return secondFactorKeyExitNotRun
	}
	verifier, err := totpverify.New(wrapper)
	if err != nil {
		_, _ = fmt.Fprintf(out, "проверяющий кода по времени: %v\n", err)
		return secondFactorKeyExitNotRun
	}
	// Тот же страж посадки, что у `serve`, и ДО первого соединения: команда,
	// открывшая базу в обход него, прошла бы там, где служба не поднялась бы.
	if _, err := describePosture(cfg, logger); err != nil {
		_, _ = fmt.Fprintf(out, "посадка процесса: %v\n", err)
		return secondFactorKeyExitNotRun
	}

	connectCtx, cancelConnect := context.WithTimeout(ctx, secondFactorKeyConnectTimeout)
	pool, err := coredb.NewPool(connectCtx, cfg.DSN())
	cancelConnect()
	if err != nil {
		_, _ = fmt.Fprintf(out, "база: %v\n", err)
		return secondFactorKeyExitNotRun
	}
	defer pool.Close()

	uc, err := secondfactorwrap.New(kanamepg.NewLoginMethodRepo(pool), verifier, secondFactorRewrapPage, secondFactorRewrapCallTimeout)
	if err != nil {
		_, _ = fmt.Fprintf(out, "проход переобёртки: %v\n", err)
		return secondFactorKeyExitNotRun
	}
	rep, err := uc.Run(ctx)
	return reportSecondFactorRewrap(out, wrapper.KeyCount(), rep, err)
}

// reportSecondFactorRewrap печатает исход строкой «ключ=значение» — все счёты
// всегда, включая нули, — и выбирает код.
//
// Совет снимать прежние ключи печатается ТОЛЬКО при исходе `done`: при любом
// ином прежний ключ ещё открывает хоть одну строку либо это не установлено.
func reportSecondFactorRewrap(out io.Writer, keys int, rep secondfactorwrap.Report, err error) int {
	line := fmt.Sprintf("%s rewrap keys=%d rows=%d rewrapped=%d current=%d unreadable=%d vanished=%d unsettled=%d",
		secondFactorKeyCommandName, keys, rep.Rows, rep.Rewrapped, rep.Current, rep.Unreadable, rep.Vanished, rep.Unsettled)
	switch {
	case err != nil:
		reason := err.Error()
		if errors.Is(err, context.Canceled) {
			reason = "команда остановлена: " + reason
		}
		_, _ = fmt.Fprintf(out, "%s outcome=not-run reason=%q\n"+
			"проход не доведён: переобёрнутое до отказа зафиксировано и открывается первым ключом, "+
			"остальное — прежними, каждая строка читаема перечнем; повторите команду — повтор продолжит\n", line, reason)
		return secondFactorKeyExitNotRun
	case !rep.Settled():
		_, _ = fmt.Fprintf(out, "%s outcome=partial\n", line)
		if rep.Unreadable > 0 {
			_, _ = fmt.Fprintf(out, "секретов, которых не открывает ни один ключ перечня: %d — они не тронуты; "+
				"прежние ключи НЕ снимать: если ключ уже снят из перечня, верните его и повторите команду\n", rep.Unreadable)
		}
		if rep.Unsettled > 0 {
			_, _ = fmt.Fprintf(out, "строк, которые служба меняла перед каждой заменой дольше %d попыток: %d; повторите команду\n",
				secondfactorwrap.SwapAttempts, rep.Unsettled)
		}
		return secondFactorKeyExitPartial
	default:
		_, _ = fmt.Fprintf(out, "%s outcome=done\n"+
			"каждый секрет второго фактора под первым ключом перечня. Прежние ключи снимаются из перечня после "+
			"повторного прогона, напечатавшего rewrapped=0 и outcome=done: он подтверждает, что ни одна реплика "+
			"не обернула новое заведение прежним первым ключом\n", line)
		return secondFactorKeyExitDone
	}
}
