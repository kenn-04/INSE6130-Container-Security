# ============================================================================
# INSE 6130 — Container Security Project
# OPA authorization policy for the Docker AuthZ plugin — NAIVE VERSION
# ----------------------------------------------------------------------------
# Purpose:
#   This policy acts as the gatekeeper in front of the Docker API. For every
#   request, OPA returns `allow` (true/false). The AuthZ plugin denies the
#   request when `allow` is false.
#
# What it does:
#   It blocks the creation of PRIVILEGED containers (HostConfig.Privileged),
#   which would otherwise grant broad access to the host.
#
# Known limitation (this is intentional — it is the target of the attack):
#   The decision relies entirely on reading the request body (input.Body).
#   If the body does not reach the plugin, the privileged flag is invisible,
#   the policy sees "nothing dangerous", and the request is wrongly allowed.
#   The hardened (fail-closed) version in /defense is meant to fix this.
#
# Scope: coursework only. Runs in an isolated VM, disconnected from the network.
# ============================================================================

package docker.authz

# Deny by default: unless a rule explicitly allows the request, it is refused.
default allow = false

# Allow the request only when it is NOT trying to create a privileged container.
allow {
    not privileged_container
}

# A request counts as "privileged" when its body sets HostConfig.Privileged to true.
privileged_container {
    input.Body.HostConfig.Privileged == true
}
