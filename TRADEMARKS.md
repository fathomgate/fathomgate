# Trademarks

The Apache License 2.0 covers Fathomgate's code, not its name: you may use, change and redistribute the code under [LICENSE](LICENSE), but a product built from it must not call itself Fathomgate.

Section 6 of the licence says so directly: it "does not grant permission to use the trade names, trademarks, service marks, or product names of the Licensor". This page says what that means in practice. The decision behind it is [ADR 0020](docs/adr/0020-open-core-apache-2.md).

## What you may do

| Use | Example |
| --- | --- |
| Refer to the project by name | "We run Fathomgate in front of our Junos MCP server." |
| Say what your work is based on or works with | "Based on Fathomgate", "a fork of Fathomgate", "a profile for Fathomgate" |
| Redistribute an unmodified official release under its own name | A package of a tagged release, built from the tag, with `LICENSE` and `NOTICE` intact |
| Write about it | Articles, talks, tutorials, comparisons, bug reports |

## What you may not do

| Use | Why |
| --- | --- |
| Ship a fork, modified build or derived product as "Fathomgate", or under a name that could be confused with it ("Fathomgate Pro", "FathomGate", "Fathomgate Enterprise") | Users must be able to tell the project's releases from someone else's build of a policy proxy that sits in front of their routers |
| Suggest that the project or its maintainer endorses, sponsors, certifies or supports your product or service | Only the maintainer can make that statement |
| Use the name, or a confusingly similar one, in your product, company or domain name | Same reason as the first row |
| Use any logo the project adopts on a modified build | A logo marks an official release |

## If you fork

1. Choose a new name, and change it everywhere a user sees it: the binary, the Go module path, the container image, the Homebrew formula, the CLI's output and the docs.
2. Keep `LICENSE` and `NOTICE`, as Apache-2.0 section 4 requires, and state in the modified files that you changed them.
3. You may say "based on Fathomgate" in your README and release notes.

## Status of the name

This page is not legal advice. The name has not had a professional trademark clearance search. [ADR 0019](docs/adr/0019-rename-to-fathomgate.md) recommends one in classes 9 and 42 before any commercial or public use, because the FATHOM field is crowded, and this page may change when that search is done. Nothing here claims a registered mark.

Questions about a use not covered here go to the maintainer in a GitHub Discussion before you ship.
