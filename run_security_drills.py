import sys
import os
import json

# Ensure terminal standard streams handle UTF-8/emojis correctly on Windows
if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except Exception:
        pass

# Add project root to sys.path
PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_DIR)

from mcp_firewall.sdk import Gateway

def run_drills(config_path=None):
    if config_path is None:
        config_path = os.path.join(PROJECT_DIR, "mcp-firewall.yaml")
        
    if not os.path.exists(config_path):
        print(f"❌ Policy configuration file not found at {config_path}")
        return False, f"Policy file not found: {config_path}"
        
    print("🛡️  Loading Security Policy Gateway from:", config_path)
    # Load config without auditing to prevent populating live database logs during drills
    gw = Gateway(config_path=config_path)
    
    # Pre-defined test cases: (category, name, tool_name, arguments, expected_blocked)
    test_cases = [
        # 1. Directory Traversal
        {
            "category": "Directory Traversal",
            "name": "Traverse to etc/passwd as standard user",
            "tool": "read_file",
            "args": {"path": "../../etc/passwd", "role": "user"},
            "expect_blocked": True,
        },
        {
            "category": "Directory Traversal",
            "name": "Access secure-experiment-zone as standard user",
            "tool": "read_file",
            "args": {"path": "secure-experiment-zone/research_notes.txt", "role": "user"},
            "expect_blocked": False,
        },
        # 2. RBAC Policy
        {
            "category": "Role-Based Access Control",
            "name": "Call GetActiveConnections as standard user",
            "tool": "GetActiveConnections",
            "args": {"role": "user"},
            "expect_blocked": True,
        },
        {
            "category": "Role-Based Access Control",
            "name": "Call GetActiveConnections as admin user",
            "tool": "GetActiveConnections",
            "args": {"role": "admin"},
            "expect_blocked": False,
        },
        # 3. Sensitive Configuration Files
        {
            "category": "Sensitive Config Files",
            "name": "Read .env file as user",
            "tool": "read_file",
            "args": {"path": ".env", "role": "user"},
            "expect_blocked": True,
        },
        {
            "category": "Sensitive Config Files",
            "name": "Read .env file as admin",
            "tool": "read_file",
            "args": {"path": ".env", "role": "admin"},
            "expect_blocked": True, # Strictly blocked for all roles
        },
        # 4. Honeypot Traps
        {
            "category": "Honeypot Interception",
            "name": "Query get_system_config honeypot tool",
            "tool": "get_system_config",
            "args": {},
            "expect_blocked": True,
        },
        {
            "category": "Honeypot Interception",
            "name": "Query fetch_internal_db honeypot tool",
            "tool": "fetch_internal_db",
            "args": {},
            "expect_blocked": True,
        },
    ]

    print("\n🔍 Running Inbound Security Drills...")
    passed_count = 0
    total_count = len(test_cases)
    results = []
    
    for tc in test_cases:
        decision = gw.check(tool_name=tc["tool"], arguments=tc["args"])
        is_blocked = decision.blocked
        
        status = "🟢 PASSED" if is_blocked == tc["expect_blocked"] else "🔴 FAILED"
        if status == "🟢 PASSED":
            passed_count += 1
            
        results.append({
            "category": tc["category"],
            "name": tc["name"],
            "tool": tc["tool"],
            "args": json.dumps(tc["args"]),
            "expected": "Blocked" if tc["expect_blocked"] else "Allowed",
            "actual": "Blocked" if is_blocked else "Allowed",
            "status": status,
            "reason": decision.reason if is_blocked else ""
        })
        
    # 5. Outbound PII/Sensitive Data Scan Drill
    pii_tests = [
        {
            "name": "Mask email address in output",
            "content": "Please send emails to admin@bank-security.com",
            "expect_redacted": True
        },
        {
            "name": "Safe text without PII",
            "content": "This is a clean response with transaction references 12345.",
            "expect_redacted": False
        }
    ]
    
    print("🔍 Running Outbound PII Redaction Drills...")
    for pt in pii_tests:
        scan_res = gw.scan_response(pt["content"])
        status = "🟢 PASSED" if scan_res.modified == pt["expect_redacted"] else "🔴 FAILED"
        
        total_count += 1
        if status == "🟢 PASSED":
            passed_count += 1
            
        results.append({
            "category": "PII Redaction",
            "name": pt["name"],
            "tool": "(outbound_scan)",
            "args": pt["content"][:30] + "...",
            "expected": "Redacted" if pt["expect_redacted"] else "Unmodified",
            "actual": "Redacted" if scan_res.modified else "Unmodified",
            "status": status,
            "reason": "Redacted: " + scan_res.content if scan_res.modified else ""
        })

    # Render Report
    report = []
    report.append("\n==========================================================================================")
    report.append("🛡️  RUNTIME SHIELD: POLICY VERIFICATION COMPLIANCE REPORT")
    report.append("==========================================================================================")
    report.append(f"Result: {passed_count}/{total_count} drills passed.\n")
    
    report.append(f"{'Category':<24} | {'Test Case':<42} | {'Expected':<10} | {'Status':<8}")
    report.append("-" * 94)
    for res in results:
        report.append(f"{res['category'][:24]:<24} | {res['name'][:42]:<42} | {res['expected']:<10} | {res['status']}")
    report.append("==========================================================================================")
    
    report_str = "\n".join(report)
    print(report_str)
    return passed_count == total_count, report_str

if __name__ == "__main__":
    success, _ = run_drills()
    sys.exit(0 if success else 1)
