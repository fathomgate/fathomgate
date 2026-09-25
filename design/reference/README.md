# Reference mockups

These two images are the maintainer's reference mockups for the local console. They are AI-generated, and they are not a spec. [DESIGN.md](../DESIGN.md) wins wherever they differ from it, and every number, name, device and agent in them is illustrative data, not product behaviour. Like the rest of `design/`, they are under Apache-2.0 ([ADR 0020](../../docs/adr/0020-open-core-apache-2.md), *Amendments*); the Fathomgate name and logo in them stay governed by [TRADEMARKS.md](../../TRADEMARKS.md).

| File | What it shows |
| --- | --- |
| `oss-console-screens.webp` | Three console screens: an overview of live activity, one held request with its diff and rule trace, and the audit history |
| `oss-console-stack.webp` | A proposed frontend stack, font system, architecture and folder layout |

[ADR 0024](../../docs/adr/0024-local-console-embedded-loopback-only.md) records what the core console takes from them and what it does not: the stack it uses instead, and the design rules the screens must bend to (the decision words, one glow per screen, the one-colour mark on views that show decisions, Deny as a danger outline, the blast meter instead of a risk level, the OS user instead of an account name, no marketing hero or quote card).
