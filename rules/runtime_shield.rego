package runtime_shield.authz

import rego.v1

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
decision := out if {
    matches := [ result |
        some i
        rule := data.runtime_shield.rules[i]
        rule_matches(rule)
        result := build_decision(rule)
    ]
    count(matches) > 0
    out := matches[0]
}

rule_matches(rule) if {
    regex.match(rule.tool, input.mcp.tool)
    role_matches(rule)
    path_matches(rule)
    extra_field_matches(rule)
}

role_matches(rule) if {
    not object.get(rule, "match", {})["role"]
}
role_matches(rule) if {
    expected_role := object.get(rule, "match", {})["role"]
    actual_role := object.get(object.get(input, "user", {}), "role", "")
    regex.match(expected_role, actual_role)
}

path_matches(rule) if {
    not object.get(rule, "match", {})["path"]
}
path_matches(rule) if {
    expected_path := object.get(rule, "match", {})["path"]
    input_path := get_input_path
    input_path != ""
    glob.match(expected_path, ["/"], input_path)
}
path_matches(rule) if {
    expected_path := object.get(rule, "match", {})["path"]
    input_path := get_input_path
    input_path != ""
    regex.match(expected_path, input_path)
}

get_input_path := p if {
    p := object.get(object.get(input, "resource", {}), "path", "")
    p != ""
} else := p if {
    p := object.get(object.get(object.get(input, "request", {}), "original_args", {}), "path", "")
}

# Extra fields matching: every match clause key other than 'role' and 'path' must match the corresponding original_args value
extra_field_matches(rule) if {
    match_args := object.get(rule, "match", {})
    extra_keys := { k | match_args[k]; k != "role"; k != "path" }
    count(extra_keys) == 0
}

extra_field_matches(rule) if {
    match_args := object.get(rule, "match", {})
    extra_keys := { k | match_args[k]; k != "role"; k != "path" }
    count(extra_keys) > 0
    matching_keys := { k |
        some k
        extra_keys[k]
        expected := match_args[k]
        actual := object.get(object.get(object.get(input, "request", {}), "original_args", {}), k, "")
        actual != ""
        regex.match(expected, actual)
    }
    count(matching_keys) == count(extra_keys)
}

build_decision(rule) := out if {
    quarantine := rule_is_quarantine(rule)
    out := {
        "allow": rule.action == "allow",
        "reason": object.get(rule, "message", "No reason provided"),
        "risk_delta": object.get(rule, "risk_delta", 0),
        "redact_output": false,
        "quarantine": quarantine,
        "rule_id": rule.name,
        "policy_backend": "opa"
    }
}
# Admin dashboard fetch_url permission rule moved to data file (removed from Rego).

default rule_is_quarantine(_) := false

rule_is_quarantine(rule) if {
    object.get(rule, "priority", "") == "critical"
    rule.action == "deny"
}


