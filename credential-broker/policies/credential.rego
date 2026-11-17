package runtime_shield.credential
import rego.v1

default allow := false

allow if {
  input.agent != ""
  input.workload in data.workloads[input.agent]
  input.credential_alias in data.credentials[input.agent]
  input.tool in data.tools[input.agent]
  input.operation in data.operations[input.agent]
  input.resource in data.resources[input.agent]
  input.manifest_hash in data.manifest_hashes
  input.lease_seconds > 0
  input.lease_seconds <= data.max_lease_seconds
  delegation_ok
}

delegation_ok if input.delegation == null
# A caller-supplied parent/depth/scope object cannot prove parent authority.
# Delegated leases stay denied until the broker verifies a trusted signed chain.
