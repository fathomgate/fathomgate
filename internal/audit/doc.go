// SPDX-License-Identifier: Apache-2.0

// Package audit writes and verifies Fathomgate's hash-chained JSONL audit log.
//
// It is the last stage of the pipeline: after a call is allowed, held or
// denied, and after any result has been redacted, one Event is appended.
// Raw device output never enters the log; only counts and hashes do.
//
// Integrity follows the CloudTrail digest pattern. Every event carries a
// sequence number, the hash of the previous event and its own hash:
//
//	hash = sha256(canonical(event without hash) + prev_hash)
//
// where canonical is compact JSON with sorted keys, and the genesis prev_hash
// is sixty-four zeros. Every N events the Writer appends a checkpoint line
// {"type":"checkpoint","seq":N,"hash":H,"sig":S} signed with an Ed25519 key,
// so a verifier holding only the public key can prove the chain was not
// rewritten wholesale. Verify replays a file and reports the first sequence
// number at which the chain breaks.
//
// OCSF and CEF are exporters built on this package, never its native format.
package audit
