# Notes for coding agents

## Start here

- Read `README.md`, `docs/design.md` and `docs/protocol.md`.
- If `AGENT-HANDOFF.md` exists, read it: it's the untracked hand-over from
  the previous session.
- If `docs/private.local.md` exists, read it as well. It's gitignored and
  has my network's values and where my infrastructure repository lives.
- The Android client is a separate project; its side of the protocol is
  summarised in `docs/protocol.md`. Deployment (OpenBao mounts, roles,
  AppRole, host) is done from my infrastructure repository, not here.

## Boundaries

- Don't log in to my servers, call my OpenBao or other production APIs, or
  change RADIUS, Wi-Fi or router configuration. Test against a throwaway
  OpenBao dev server (`bao server -dev`) or the fake in the tests.
- No secrets in Git: no private keys, tokens, AppRole secret IDs or
  enrollment codes, also not in test fixtures (generate them in the test).
- Nothing personal in tracked files: no real domains, CA names, host names,
  SSIDs, usernames or local paths. Use placeholders like
  `enroll.example.org`; personal values go in `docs/private.local.md`.
- Don't push, tag or publish unless I ask. Commits are signed; keep it
  that way.

## Code

- Go, one module, licence MPL-2.0. Build with Go >= 1.27.3 (crypto/x509
  security fixes).
- Standard library first. Each extra dependency needs a reason in
  `docs/design.md`; currently only `modernc.org/sqlite` (pure Go, no cgo).
- Security-relevant behaviour (what is checked, what is logged, what is
  never logged) is documented in `docs/design.md` and covered by tests.
- Checks before handing over: `gofmt -l .` prints nothing, `go vet ./...`
  and `go test ./...` pass.
