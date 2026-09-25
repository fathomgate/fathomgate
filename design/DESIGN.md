# Fathomgate design system

Fathomgate is a policy product: every screen exists to answer "what did the agent try, what did policy decide, and what happens next". The design system is **Fathom** (Josh's shared two-theme system) plus one **policy layer** defined in this folder. Nothing here introduces a new hue, font or spacing step; it names the states a guardrail has that a topology tool does not.

Fathom reference: the tokens in [`tokens.css`](tokens.css); open [`preview.html`](preview.html) in a browser to see them applied

## Files

| File | What it is | Consumed by |
| --- | --- | --- |
| `tokens.css` | Fathom semantic tokens (Midnight Zone dark, Chart Room light) plus the Fathomgate policy tokens | Console, docs site, README screenshots |
| `policy.css` | The `fg-*` components: decision badge, class chip, redacted token, diff view, approval card, TTL bar, blast-radius meter, audit timeline, rule trace | Console |
| `preview.html` | One approval-console screen rendered in both themes, using only the two files above | Design review, contributor onboarding |
| `brand/` | The logo: the gateway mark, wordmark and lockups as transparent SVGs, in dark, light and one-colour versions (see Brand below) | README, docs site, console, release pages |

The console is the only UI Fathomgate ships in v1 (milestone M5). The CLI and the audit log are text; their conventions are in the Voice section because words are the interface there too.

## Brand

The mark is a gateway: a divided arch with its gate panels open, a guiding star inside, steps leading through, and three of Fathom's sonar rings around it. It says what Fathomgate does: a way through, with boundaries around it.

| Use | File |
| --- | --- |
| README and docs headers | `fathomgate-horizontal-tagline-dark.svg` / `-light.svg`, swapped with `<picture>` and `prefers-color-scheme`, at 480 px wide or more |
| Headers without room for the tagline | `fathomgate-horizontal-dark.svg` / `-light.svg`, 240 px wide or more |
| Square places: avatars, social cards, the console sign-in screen | `fathomgate-icon-dark.svg` / `-light.svg`, 48 px or more; `fathomgate-stacked-*.svg` when the name must be there too |
| 16 to 32 px: favicons, tabs, small UI | `fathomgate-favicon.svg` (adapts to light and dark by itself) or `fathomgate-small-*.svg`. Never shrink the detailed mark this far |
| One colour only: print, engraving, vinyl, monochrome UI | `fathomgate-icon-teal/-white/-ink.svg`, `fathomgate-horizontal-white/-ink.svg` |

"Dark" means *for a dark page*, "light" means *for a light page*; every canvas is transparent. `manifest.json` lists each file with its size and checksum.

- **Colours belong to the artwork.** The logo's teal (`#00D4C7`), ink (`#0B1B2E`) and light (`#E6ECF1`) are for the logo only. UI keeps using Fathom's semantic tokens; the "no new hue" rule above still holds for everything that isn't the logo.
- **The wordmark is uppercase artwork; prose is not.** The logo spells FATHOMGATE in custom display lettering. In text, the product is always Fathomgate (one word, capital F only) and `fathomgate` in mono for the command. The `fathomgate-brandcase-*.svg` lockups spell it "Fathomgate" for places where the uppercase would read as shouting.
- **Leave it alone.** Don't recolour the detailed mark, stretch it, add effects, or set it on a busy background. Give it clear space of at least the height of the gate panels on every side.
- **The logo is a trademark.** It marks the project's own releases; see [TRADEMARKS.md](../TRADEMARKS.md).

## Theme

Tools default to **Midnight Zone** (dark). The console follows the OS preference and offers a toggle; the light theme is Chart Room. Components use only semantic names (`--surface`, `--text`, `--decision-hold`), never raw palette names (`--lure`), so both themes work with no per-component overrides.

## Decision vocabulary

A call has exactly one decision. The word is always shown; colour is reinforcement.

| Decision | Word shown | Token | Fathom source | Meaning |
| --- | --- | --- | --- | --- |
| allow | Allowed | `--decision-allow` | `success` | Forwarded upstream |
| hold | Holding | `--decision-hold` | `warning` | Waiting for a human; pulses while the TTL is live |
| deny | Denied | `--decision-deny` | `danger` | Refused; the rule id is shown beside it |
| expired | Expired | `--decision-expired` | `text-disabled` | A hold whose TTL ran out; terminal |

Redaction is not a decision. A masked secret renders as the `fg-redacted` token in `--redacted` (Fathom `accent`): dashed edge, `hmac:` prefix, first 12 hex characters. It reads as "something comparable was here", not as an error.

Command classes are chips with an outline only: `READ_OPERATIONAL`, `READ_CONFIG` and `INVENTORY_READ` in muted text; `WRITE_CONFIG` in warning; `EXEC_ARBITRARY` in danger. The chip never has a filled ground, so it never competes with the decision badge next to it.

## Components

**Decision badge (`fg-decision`)** — dot plus uppercase mono word. Use `data-decision` for state and `data-live` on a hold that can still be approved. One per call row; never stack two.

**Approval card (`fg-approval`)** — the primary object of the console. Pending cards carry `shadow-glow`, the one glow allowed per view; approved and denied cards drop back to `shadow-sm`. Order inside the card is fixed: head (decision, class chip, title), meta (device, role, requester, rule), diff, TTL, actions. Actions are two buttons: **Approve** (primary) and **Deny** (danger outline). No third option; "ask later" is what the TTL does.

**Diff view (`fg-diff`)** — line number, sign, text in a three-column grid. Added lines on `--diff-add-bg`, removed on `--diff-del-bg`, hunk headers in `--diff-hunk`. Secrets inside a diff are already redacted before they reach the view. The diff scrolls horizontally inside its own box; the page never does.

**TTL bar (`fg-ttl`)** — fills from the right so the empty part reads as time gone. Under two minutes it switches to `--decision-deny` via `data-urgency="low"`. The label always shows the exact remaining time in mono, tabular numerals.

**Blast-radius meter (`fg-blast`)** — four discrete bands, never a gradient. Band 0 is within policy (success), band 1 approaching a cap (info), band 2 at the cap and needing approval (warning), band 3 over the cap and denied (danger). One row per counter: devices this session, pending holds, fan-out in this call.

**Audit timeline (`fg-timeline`)** — newest first, a dot per event coloured by decision, event line in sans with tool and device in `code`, meta line in mono with time, principal, rule id and the first 8 characters of the chain hash. The eye never verifies a chain; `fathomgate audit verify` does. The hash is shown so a reader can cross-reference the CLI output.

**Rule trace (`fg-trace`)** — the rules evaluated in order, the one that fired marked with `▸` in `--primary`. Shown inside the approval card behind a disclosure, and in every denied response.

## Voice

Plain, exact and calm, as in Fathom. Fathomgate adds three rules because the product speaks to two readers at once, the operator and the agent:

- **Every denial names its rule.** "Denied by `no-exec`: free-form `reload` on core-rtr-01" — never "Operation not permitted". The agent can self-correct and the operator can find the rule.
- **Verbs match the state machine.** Holding, Approved, Denied, Expired, Executed, Failed. No synonyms ("blocked", "rejected", "pending review") anywhere: UI, CLI, audit log, docs.
- **Technical values are typed exactly and set in mono.** `core-rtr-01`, `10.20.0.1/31`, `commit confirmed 5`, `prod-core-needs-approval`. A rule id is a technical value.

CLI output uses the same words and the same order as the console: decision, class, target, rule, reason. Audit JSONL uses the same field names as the console's meta labels, lowercased with underscores, so a screenshot and a log line describe one event in one vocabulary.

## Motif

Fathom's sonar rings suit Fathomgate exactly: a guardrail is a boundary, and a ping is a probe against it. Use the rings on the empty state ("No calls held") and the sign-in screen, cropped at an edge, never behind text.

## Accessibility

All decision and class colours are Fathom's status colours, which pass 4.5:1 on `bg`, `surface` and `surface-raised` in both themes (see Fathom's contrast table). Status never relies on colour alone: badges carry a word, chips carry the class name, the meter carries the number. Focus is a 2px `--focus` ring with 2px offset. The hold pulse and TTL transition stop under `prefers-reduced-motion`.

## Do and don't

- Do show the decision word and the rule id together on every denied or held call.
- Do keep one glowing card per screen; the glow means "act here".
- Do render the diff even when it is one line; the operator approves a diff, not a description.
- Don't invent a fifth decision state. If a call needs a new outcome, it is a new obligation on an existing state, not a new colour.
- Don't colour the class chip's ground; only the decision badge has a filled ground.
- Don't use the blast meter as a progress bar; it shows a band, not a percentage.
