// SPDX-License-Identifier: Apache-2.0

// Package gate decides every tools/call before the proxy forwards it.
//
// It implements steps 1 to 6 of the pipeline in ADR 0026 and the text of the
// tool error an agent sees when a call is not forwarded:
//
//  1. Parse: the call's arguments must be one JSON object, valid UTF-8, with
//     no key given twice. Otherwise deny, rule default:bad_arguments.
//  2. Normalise: the profile's target_params, targets_params and
//     group_params give the target names. Each name must be a hostname or an
//     IP literal exactly as the upstream will receive it (no trimming, no
//     case folding). A tool that declares a target source, is not
//     INVENTORY_READ or LOCAL_ADMIN, and arrives with no target, or with a
//     tag or group selector the upstream expands itself, is denied with
//     default:bad_arguments: fathomgate cannot see which devices it would
//     reach.
//  3. Classify: classify.Classify, then the tool's annotations, which can
//     only raise a read class (invariant 3, ADR 0010).
//  4. Resolve: each name through the inventory. A name is known only when an
//     inventory record carries exactly that name and it did not come from a
//     hostname pattern alone (ADR 0031).
//  5. Session counters: taken from the call, never counted here.
//  6. Evaluate: policy.Evaluate, which stays pure (invariant 1).
//
// The gate does no I/O of its own and keeps no state between calls: the
// inventory lookup is the caller's resolver (in-memory in M1), and the
// decision log line is returned as data for the proxy to write (ADR 0026
// step 8). With no profile for a server the gate classifies every call with
// the fallback classifier and checks no argument names; fathomgate serve
// warns at start when that happens (ADR 0027, board task M1-20).
//
// The only text the agent sees is Verdict.Error, one line in one shape:
//
//	fathomgate <denied|cannot run|held> <server>.<tool>: rule <rule_id> (class <CLASS>): <reason>
//
// The reason is the policy author's text or fathomgate's fixed text. No
// argument value, target name, command or upstream text is ever quoted in it.
package gate
