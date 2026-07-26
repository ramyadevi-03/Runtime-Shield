package runtime_shield.authz

default decision := {
    "allow": false,
    "reason": "Default deny: no matching rule found",
    "risk_delta": 0,
    "redact_output": false,
    "quarantine": false,
    "rule_id": "default_deny",
    "policy_backend": "opa"
}

# Evaluate all rules and pick the first match (based on array order)
decision := out {
    matches := [ result |
        some i
        rule := data.runtime_shield.rules[i]
        rule_matches(rule)
        result := build_decision(rule)
    ]
    count(matches) > 0
    out := matches[0]
}

rule_matches(rule) {
    regex.match(rule.tool, input.mcp.tool)
    role_matches(rule)
    path_matches(rule)
}

role_matches(rule) {
    not object.get(rule, "match", {})["role"]
}
role_matches(rule) {
    expected_role := object.get(rule, "match", {})["role"]
    regex.match(expected_role, input.user.role)
}

path_matches(rule) {
    not object.get(rule, "match", {})["path"]
}
path_matches(rule) {
    expected_path := object.get(rule, "match", {})["path"]
    input_path := input.resource.path
    input_path != ""
    glob.match(expected_path, ["/"], input_path)
}
path_matches(rule) {
    expected_path := object.get(rule, "match", {})["path"]
    input_path := input.resource.path
    input_path != ""
    regex.match(expected_path, input_path)
}

build_decision(rule) = out {
    quarantine := rule_is_quarantine(rule)
    out := {
        "allow": rule.action == "allow",
        "reason": object.get(rule, "message", "No reason provided"),
        "risk_delta": object.get(rule, "risk_delta", 0),
        "redact_output": rule.action == "redact",
        "quarantine": quarantine,
        "rule_id": rule.name,
        "policy_backend": "opa"
    }
}

rule_is_quarantine(rule) {
    object.get(rule, "priority", "") == "critical"
    rule.action == "deny"
}
default rule_is_quarantine(_) = false
