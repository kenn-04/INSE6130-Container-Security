# INSE6130-Container-Security
Attack 2:
# INSE 6130 — Container Security Project

Attack: Docker authorization (AuthZ) plugin bypass — **CVE-2024-41110**
Defense: hardened, fail-closed authorization policy using **OPA**
---

## 1. Lab architecture

One environment, two components talking to each other:

- **Docker Engine** (vulnerable version, < 27.1.1) with an **AuthZ plugin** enabled
- **OPA** (Open Policy Agent) evaluating our policy on every API request

Each request sent to the Docker API is presented to OPA, which returns
`allow` or `deny` based on the loaded policy.

```
docker client  →  Docker daemon  →  AuthZ plugin  →  OPA (policy.rego)  →  allow / deny
```

--

## 2. Running the environment

> Fill in with your exact commands once the compose file is finalized.

1. Start the isolated VM.
2. Check the Docker version (must be < 27.1.1):
   ```
   docker version
   ```
3. Start OPA and wire up the AuthZ plugin (see `/lab`).
4. Confirm OPA has loaded the policy from `/opa/policy.rego`.

---

## 4. The starting policy (naive version)

File: `/opa/policy.rego`

```rego
default allow = false

allow {
    not privileged_container
}

privileged_container {
    input.Body.HostConfig.Privileged == true
}
```

**Expected behavior:** a request to create a **privileged** container
(`Privileged: true`) must be **denied**.

**Known weakness (this is the core of the project):** this policy makes its
decision by inspecting `input.Body`. If the request body never reaches the
plugin, the `HostConfig.Privileged` field is absent, `privileged_container`
becomes false, `not privileged_container` becomes true, and the request is
**wrongly allowed**. This is exactly what the defense must fix.

---

## 5. Control tests (for both sides)

These tests contain **no exploit** — they are normal requests used to verify
that the gatekeeper works.

| Test | Request | Expected result |
|------|---------|-----------------|
| Negative control | A standard **non-privileged** container | Allowed ✅ |
| Positive control | A **privileged** container (`Privileged: true`), normal request | Denied ✅ |

If both tests pass, the AuthZ plugin + OPA are correctly wired.

---

## 6. Success criteria for the DEFENSE

The hardened policy (in `/defense`) must satisfy **all** of the following:

1. **Keeps the correct behavior:** a normal non-privileged container stays
   allowed; a normal privileged container stays denied.
2. **Fail-closed:** if the policy **cannot confirm** the request is safe —
   body missing, empty, unreadable, or unexpected — it **denies** instead of
   allowing.
3. **Resists the bypass:** a request that aims to create a privileged container
   but is shaped so the body does not reach the plugin must be **denied**, not
   allowed.

In short: move from an "allow unless I see something dangerous" logic to an
"allow only if I explicitly see that it is safe" logic.

---

## 7. References

- Docker / Moby — security advisory (GHSA) on the AuthZ bypass
- NVD — CVE-2024-41110
- Open Policy Agent — Rego language documentation

> Grading reminder: zero tolerance for plagiarism. All writing must be
> reworded in your own words.
