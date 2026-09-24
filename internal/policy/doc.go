// Package policy implements the Fathomgate YAML policy DSL and its evaluator.
//
// It is the fourth stage of the pipeline (normalise -> classify -> resolve
// role -> evaluate). Evaluate is a pure function from a Policy and a Request
// to a Decision, so it can be unit-tested without a proxy, a device or a
// network, and so contributors can test policies with `fathomgate policy test`
// over *.test.yaml files without a Go toolchain.
//
// Semantics, in order:
//
//  1. If any target is unknown (absent from every inventory provider), the
//     policy's defaults.unknown_target applies. "deny" denies every class;
//     "allow" lets the rules decide; unset denies WRITE_CONFIG and
//     EXEC_ARBITRARY and lets the rules decide for reads.
//  2. defaults.session.max_devices caps the number of distinct devices a
//     session may touch, counting the devices already touched plus the
//     targets of this request.
//  3. Rules are evaluated in file order and the first match wins. A matcher
//     list that is empty matches everything; a non-empty list must be
//     satisfied. device_roles and device_tags require every target to
//     satisfy them, so a mixed lab-plus-core fan-out never inherits the
//     lab rule.
//  4. A hold that would exceed defaults.session.max_pending becomes a deny.
//  5. No matching rule is a deny. The engine fails closed.
//
// Every Decision carries a Trace with one entry per rule and per default
// check, so the console and the audit log can show why a call was allowed,
// held or denied.
package policy
