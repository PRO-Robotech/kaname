// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package mailaddr — предикаты адреса ОТПРАВИТЕЛЯ письма, общие для стража
// старта (`config.InviteMailConfig.Validate`) и самого отправителя
// (`clients`): тем доменом отправитель представляется узлу (EHLO) и в нём
// чеканит `Message-ID`.
//
// Предикат ОДИН на обоих, и это требование, а не стиль (задача kaname#642):
// разойдясь, страж и отправитель разошлись бы ровно на вырожденном значении —
// страж пропустил бы адрес, на котором отправитель отказывает каждой отправке,
// и процесс стартовал бы здоровым, не доставляя ни одного письма.
//
// Пакет чистый (только стандартная библиотека): его импортируют и слой
// конфигурации, и адаптер отправки, и ни один из них не тянет другого.
package mailaddr

import "strings"

// SenderDomain — домен адреса отправителя.
//
// Домена нет либо он не годится в правую часть msg-id (RFC 5322 §3.6.4:
// dot-atom без пробелов, скобок и пустых меток) — ok=false. Молчаливого
// `localhost` нет: узел вправе отвергнуть такое приветствие, а `Message-ID` в
// чужом домене отличать письма не обязан, — это настройка, и решает её оператор.
func SenderDomain(from string) (string, bool) {
	addr := AddressOnly(from)
	at := strings.LastIndex(addr, "@")
	if at < 0 {
		return "", false
	}
	domain := addr[at+1:]
	if domain == "" || strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") ||
		strings.Contains(domain, "..") {
		return "", false
	}
	for i := 0; i < len(domain); i++ {
		if !isDomainByte(domain[i]) {
			return "", false
		}
	}
	return domain, true
}

// isDomainByte — байт, допустимый в dot-atom правой части msg-id: atext
// RFC 5322 §3.2.3, точка и восьмибитные байты UTF-8 (RFC 6532). Управляющих,
// пробелов и `<>@[]` в нём нет — значит, и CRLF в заголовок через домен не
// попадает.
func isDomainByte(c byte) bool {
	switch {
	case c >= 0x80, c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	}
	return strings.IndexByte(".!#$%&'*+-/=?^_`{|}~", c) >= 0
}

// AddressOnly снимает отображаемое имя: `Kachō <a@b>` → `a@b`.
func AddressOnly(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.LastIndex(s, "<"); i >= 0 {
		if j := strings.Index(s[i:], ">"); j > 0 {
			return strings.TrimSpace(s[i+1 : i+j])
		}
	}
	return s
}
