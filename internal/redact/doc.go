// SPDX-License-Identifier: Apache-2.0

// Package redact removes secrets from device output before it reaches the
// agent or the audit log.
//
// It runs at the response serialiser so no output bypasses it. An ordered
// list of vendor regexes runs first (Cisco password types, SNMP communities,
// key-strings, AAA server keys, BGP and OSPF keys; Junos encrypted-password,
// $9$ and the ## SECRET-DATA marker; EOS sha512 and type 7; PAN-OS phash and
// pre-shared-key; FortiOS ENC blobs), followed by generic hash and keyword
// patterns. Within one line the first rule that matches wins, so each secret
// is attributed to exactly one rule id.
//
// Every match is replaced with <redacted:hmac:XXXXXXXXXXXX>, the first twelve
// hex characters of HMAC-SHA256(key, secret). The same secret produces the
// same token across devices inside one deployment, so an operator can see
// that two routers share a TACACS key without learning the key, and the key
// cannot be brute-forced from the token without the HMAC key.
//
// The fixture corpus in tests/fixtures/configs/ pins every pattern; add a
// fixture line whenever a bug report shows a format the list missed.
package redact
