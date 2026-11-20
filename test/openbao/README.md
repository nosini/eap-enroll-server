# Test against a real OpenBao

End-to-end test of the service, the roles and the AppRole policy from
[docs/openbao.md](../../docs/openbao.md) against a throwaway OpenBao dev
server. Never point it at a real OpenBao: `setup.sh` kills any running
`bao server -dev` and recreates everything.

Needs `bao`, `openssl`, `curl` and `python3` on a Linux machine (it uses
random 127.x.y.z source addresses). In an empty directory:

```sh
mkdir bin
cp /path/to/bao /path/to/eap-enroll bin/
cp /path/to/repo/docs/openbao.md docs-openbao.md
/path/to/repo/test/openbao/setup.sh   # dev server, PKI, AppRole, config
/path/to/repo/test/openbao/run.sh     # prints ok/FAIL lines and "failures: N"
```

`setup.sh` takes the device role and the policy from `docs-openbao.md`,
so the test checks what the documentation says. The `eap-client` role
mirrors the production role definition. Stop the dev server afterwards
with `pkill -f "[b]ao server -dev"`.
