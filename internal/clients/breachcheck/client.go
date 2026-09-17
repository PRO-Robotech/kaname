// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package breachcheck — адаптер авторитета утечек паролей по протоколу
// k-анонимности (фаза Ф3, задача PRO-Robotech/kacho#1269; Р11, Ф3-34).
//
// # Протокол
//
// Пароль не покидает процесс: наружу уходят первые пять шестнадцатеричных
// знаков SHA-1, авторитет отвечает перечнем хвостов с числом вхождений
// (`SUFFIX:COUNT` построчно). Совпавший хвост — пароль в базе есть; число
// наружу не выходит (Ф1-34).
//
// # Три исхода, и различаются они ТИПОМ (Р11, security-hardening §8)
//
//   - отказ сети либо 5xx — авторитет НЕДОСТУПЕН: третья категория, проход
//     громко у правила пароля;
//   - 404/405, тело не по протоколу (HTML, не текст) — по адресу НЕ ТОТ
//     эндпоинт: наша ошибка настройки, отказ операции;
//   - 200 с текстом по протоколу — вердикт.
package breachcheck

import (
	"bufio"
	"context"
	"crypto/sha1" // #nosec G505 -- протокол k-анонимности авторитета определён на SHA-1; здесь не защита, а адресация диапазона
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
)

// maxBody — потолок ответа: диапазон из пяти знаков даёт сотни строк, не мегабайты.
const maxBody = 4 << 20

// Client — авторитет утечек по адресу.
type Client struct {
	base string
	http *http.Client
}

// New — клиент с явным адресом (без умолчания: адрес объявляет профиль) и
// собственным пределом времени на вызов.
func New(base string, timeout time.Duration) (*Client, error) {
	base = strings.TrimRight(strings.TrimSpace(base), "/")
	if base == "" {
		return nil, fmt.Errorf("breach check: authority address required")
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &Client{base: base, http: &http.Client{Timeout: timeout}}, nil
}

// Check — см. порт `humansession.BreachChecker`.
func (c *Client) Check(ctx context.Context, password string) (humansession.BreachVerdict, error) {
	sum := sha1.Sum([]byte(password)) // #nosec G401 -- см. шапку: адресация диапазона протокола, не защита
	digest := strings.ToUpper(hex.EncodeToString(sum[:]))
	prefix, suffix := digest[:5], digest[5:]

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/range/"+prefix, nil)
	if err != nil {
		return humansession.BreachNotFound, fmt.Errorf("%w: %v", humansession.ErrBreachAuthorityMisconfigured, err)
	}
	req.Header.Set("Accept", "text/plain")
	resp, err := c.http.Do(req)
	if err != nil {
		return humansession.BreachNotFound, fmt.Errorf("%w: %v", humansession.ErrBreachAuthorityUnavailable, err)
	}
	defer func() { _ = resp.Body.Close() }()

	switch {
	case resp.StatusCode >= 500:
		return humansession.BreachNotFound, fmt.Errorf("%w: status %d", humansession.ErrBreachAuthorityUnavailable, resp.StatusCode)
	case resp.StatusCode == http.StatusNotFound, resp.StatusCode == http.StatusMethodNotAllowed:
		return humansession.BreachNotFound, fmt.Errorf("%w: status %d at %s — not a range endpoint",
			humansession.ErrBreachAuthorityMisconfigured, resp.StatusCode, c.base)
	case resp.StatusCode != http.StatusOK:
		return humansession.BreachNotFound, fmt.Errorf("%w: status %d", humansession.ErrBreachAuthorityUnavailable, resp.StatusCode)
	}
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	if ct != "" && !strings.HasPrefix(ct, "text/plain") {
		return humansession.BreachNotFound, fmt.Errorf("%w: content-type %q at %s — not the range protocol",
			humansession.ErrBreachAuthorityMisconfigured, ct, c.base)
	}
	sc := bufio.NewScanner(io.LimitReader(resp.Body, maxBody))
	lines := 0
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		lines++
		tail, _, ok := strings.Cut(line, ":")
		if !ok || len(tail) != len(suffix) {
			return humansession.BreachNotFound, fmt.Errorf("%w: line %q at %s — not the range protocol",
				humansession.ErrBreachAuthorityMisconfigured, line, c.base)
		}
		if strings.EqualFold(tail, suffix) {
			return humansession.BreachFound, nil
		}
	}
	if err := sc.Err(); err != nil {
		return humansession.BreachNotFound, fmt.Errorf("%w: %v", humansession.ErrBreachAuthorityUnavailable, err)
	}
	if lines == 0 {
		// Пустой диапазон у настоящего авторитета не бывает (каждый префикс
		// несёт сотни хвостов) — по адресу не тот эндпоинт.
		return humansession.BreachNotFound, fmt.Errorf("%w: empty range at %s", humansession.ErrBreachAuthorityMisconfigured, c.base)
	}
	return humansession.BreachNotFound, nil
}

var _ humansession.BreachChecker = (*Client)(nil)
