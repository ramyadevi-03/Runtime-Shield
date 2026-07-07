import { z } from "zod";
import { getKcClient } from "../utils/keycloak.js";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/* -----------------------------
   Resolve userId
----------------------------- */
async function resolveUserId(kc: any, userId?: string, username?: string) {
  if (userId) return userId;

  if (!username) {
    throw new Error("Provide either userId or username");
  }

  const users = await kc.users.find({
    search: username,
    max: 20
  });

  const user = users.find(
    (u: any) => (u.username || "").toLowerCase() === username.toLowerCase()
  );

  if (!user) {
    throw new Error(`User '${username}' not found`);
  }

  return user.id;
}

/* -----------------------------
   Register tools
----------------------------- */
export function registerTools(server: any) {

  /* -----------------------------
     FILESYSTEM TOOLS (Protected by Bridge Firewall)
  ----------------------------- */
  server.tool(
    "read_file",
    "Reads the contents of a file at the given path. CRITICAL: You MUST use this tool to read any local filesystem paths, workspace files, or project files (such as files under secure-experiment-zone, or financial_data.csv). Do NOT search in your upload directory, do NOT ask the user to upload it, and do NOT use any other tool. Call this tool directly with the target path. Standard users can read files inside the secure experiment zone, and administrators have unrestricted access.",
    {
      path: z.string().describe("Path to the file to read")
    },
    async ({ path: filePath }: any) => {
      try {
        console.error(`🔍 READ_FILE CALLED for: ${filePath}`);
        // Standard reading - the bridge will intercept and block if unauthorized
        if (!fs.existsSync(filePath)) {
          return { content: [{ type: "text", text: `Error: File not found: ${filePath}` }] };
        }
        const content = fs.readFileSync(filePath, "utf-8");
        return { content: [{ type: "text", text: content }] };
      } catch (err: any) {
        return { content: [{ type: "text", text: `Read error: ${err.message}` }] };
      }
    }
  );

  server.tool(
    "list_directory",
    "Lists the files inside a directory at the given path. CRITICAL: You MUST use this tool to list any local directories or project folders (such as secure-experiment-zone). Do NOT search in your upload directory or ask the user to upload it.",
    {
      path: z.string().describe("Path to the directory to list")
    },
    async ({ path: dirPath }: any) => {
      try {
        console.error(`🔍 LIST_DIRECTORY CALLED for: ${dirPath}`);
        if (!fs.existsSync(dirPath)) {
          return { content: [{ type: "text", text: `Error: Directory not found: ${dirPath}` }] };
        }
        const files = fs.readdirSync(dirPath);
        return { content: [{ type: "text", text: files.join("\n") }] };
      } catch (err: any) {
        return { content: [{ type: "text", text: `List error: ${err.message}` }] };
      }
    }
  );

  server.tool(
    "write_file",
    "Writes content to a file at the given path.",
    {
      path: z.string().describe("Path to write to"),
      content: z.string().describe("Content to write")
    },
    async ({ path: filePath, content }: any) => {
      try {
        console.error(`🔍 WRITE_FILE CALLED for: ${filePath}`);
        fs.writeFileSync(filePath, content);
        return { content: [{ type: "text", text: `✅ File written successfully to ${filePath}` }] };
      } catch (err: any) {
        return { content: [{ type: "text", text: `Write error: ${err.message}` }] };
      }
    }
  );

  /* -----------------------------
     LIST ALL USERS
  ----------------------------- */
  server.tool(
    "keycloak_list_users",
    {
      max: z.number().optional().default(20),
    },
    async (params: any) => {
      try {
        console.error("🔍 LIST ALL USERS CALLED");
        const kc = await getKcClient();
        const users = await kc.users.find({ max: params.max });
        return {
          content: [{ type: "text", text: JSON.stringify(users || [], null, 2) }]
        };
      } catch (err: any) {
        console.error("LIST USERS ERROR:", err);
        return {
          content: [{ type: "text", text: `List users error: ${err.message}` }]
        };
      }
    }
  );

  /* -----------------------------
     LIST USER SESSIONS
  ----------------------------- */
  server.tool(
    "keycloak_list_user_sessions",
    {
      username: z.string().optional(),
      userId: z.string().optional()
    },
    async (params: any) => {
      try {
        console.error("🔍 LIST SESSIONS CALLED");
        const kc = await getKcClient();
        const targetId = await resolveUserId(kc, params.userId, params.username);
        const sessions = await kc.users.listSessions({ id: targetId });
        return {
          content: [{ type: "text", text: JSON.stringify(sessions || [], null, 2) }]
        };
      } catch (err: any) {
        console.error("SESSION ERROR:", err);
        return {
          content: [{ type: "text", text: `Session error: ${err.message}` }]
        };
      }
    }
  );

  /* -----------------------------
     REVOKE USER SESSIONS
     ADMIN ONLY
  ----------------------------- */
  server.tool(
    "keycloak_revoke_user_sessions",
    {
      username: z.string().optional(),
      userId: z.string().optional()
    },
    async (params: any, extra: any) => {
      try {
        console.error("🔍 REVOKE CALLED");
        const ext = extra as any;
        const role = ext?._meta?.authContext?.requiredRole || process.env.RUNTIME_ROLE || "analyst";
        if (role !== "admin") {
          return {
            content: [{ type: "text", text: "❌ Only admin can revoke sessions" }]
          };
        }
        const kc = await getKcClient();
        const targetId = await resolveUserId(kc, params.userId, params.username);
        await kc.users.logout({ id: targetId });
        return {
          content: [{ type: "text", text: `✅ Sessions revoked for ${params.username || targetId}` }]
        };
      } catch (err: any) {
        console.error("REVOKE ERROR:", err);
        return {
          content: [{ type: "text", text: `❌ Revoke failed: ${err.message}` }]
        };
      }
    }
  );

  /* -----------------------------
     GET USER EVENTS
  ----------------------------- */
  server.tool(
    "keycloak_get_user_events",
    {
      username: z.string().optional(),
      userId: z.string().optional(),
      limit: z.number().optional().default(20)
    },
    async (params: any) => {
      try {
        console.error("🔍 EVENTS CALLED");
        const kc = await getKcClient();
        const targetId = await resolveUserId(kc, params.userId, params.username);
        const realm = process.env.KEYCLOAK_REALM || "runtime-shield";
        const events = await kc.realms.findEvents({
          realm,
          user: targetId,
          max: params.limit
        });
        return {
          content: [{ type: "text", text: JSON.stringify(events || [], null, 2) }]
        };
      } catch (err: any) {
        console.error("EVENT ERROR:", err);
        return {
          content: [{ type: "text", text: `Event error: ${err.message}` }]
        };
      }
    }
  );

  /* -----------------------------
     SECURITY REPORT
  ----------------------------- */
  server.tool(
    "keycloak_security_report",
    {},
    async () => {
      const projectRoot = path.resolve(__dirname, "../../");
      const logPath = path.join(projectRoot, "bridge.log");
      const discoveryPath = path.join(projectRoot, "discovery.log");

      let logContent = "";
      let discoveryContent = "";

      if (fs.existsSync(logPath)) logContent = fs.readFileSync(logPath, "utf-8");
      if (fs.existsSync(discoveryPath)) discoveryContent = fs.readFileSync(discoveryPath, "utf-8");

      const blocks = (logContent.match(/🚫 Blocked/g) || []).length;
      const redactions = (logContent.match(/✂️  FIREWALL REDACTED/g) || []).length;
      const discoveries = discoveryContent.split("\n").filter(l => l.trim()).length;

      const report = [
        "### 🛡️ MCP Shield: Security Posture Report",
        `- **Blocked Attacks**: ${blocks}`,
        `- **Sensitive Data Redactions**: ${redactions}`,
        `- **Newly Discovered Tools (Learning Mode)**: ${discoveries}`,
        "",
        "**Risk Assessment**: " + (blocks > 5 ? "🔴 High - Frequent unauthorized attempts detected." : "🟢 Low - System stable."),
        "**Recommendation**: Check `discovery.log` to authorize new tool patterns."
      ].join("\n");

      return { content: [{ type: "text", text: report }] };
    }
  );

  /* -----------------------------
     GENERATE POLICY
  ----------------------------- */
  server.tool(
    "keycloak_generate_policy",
    {},
    async () => {
      const projectRoot = path.resolve(__dirname, "../../");
      const discoveryPath = path.join(projectRoot, "discovery.log");

      if (!fs.existsSync(discoveryPath) || fs.readFileSync(discoveryPath, "utf-8").trim() === "") {
        return { content: [{ type: "text", text: "No tool discoveries found. Run the bridge with --learning to discover new patterns." }] };
      }

      const discoveries = fs.readFileSync(discoveryPath, "utf-8")
        .split("\n")
        .filter(l => l.trim())
        .map(l => JSON.parse(l));

      const proposedRules = discoveries.map(d => d.proposed_rule).join("\n\n");

      const proposedTests = discoveries.map((d, index) => {
        const cleanedArgs = JSON.stringify(d.args);
        return `- category: "Auto-discovered Verification"\n  name: "Verify allowed access to ${d.tool} (Case ${index + 1})"\n  tool: "${d.tool}"\n  args: ${cleanedArgs}\n  expect_blocked: false`;
      }).join("\n\n");

      const output = [
        "### 🧠 Proposed Firewall Rules",
        "Review and add these to your `mcp-firewall.yaml` rules section:",
        "```yaml",
        proposedRules,
        "```",
        "",
        "### 🧪 Generated Test Cases",
        "Add these to your programmatic verification drills or policy tests baseline:",
        "```yaml",
        proposedTests,
        "```"
      ].join("\n");

      return { content: [{ type: "text", text: output }] };
    }
  );

  /* -----------------------------
     RUN SECURITY DRILLS
  ----------------------------- */
  server.tool(
    "keycloak_run_drills",
    {},
    async () => {
      return { content: [{ type: "text", text: "Policy verification is handled by the Python bridge runtime." }] };
    }
  );

  /* -----------------------------
     QUARANTINE USER
  ----------------------------- */
  server.tool(
    "keycloak_quarantine_user",
    {
      userId: z.string().optional(),
      username: z.string().optional(),
      reason: z.string().optional().default("Suspicious behavior detected"),
    },
    async ({ userId, username, reason }: any) => {
      const kc = await getKcClient();
      const targetId = await resolveUserId(kc, userId, username);
      await kc.users.logout({ id: targetId });

      const projectRoot = path.resolve(__dirname, "../../");
      const configPath = path.join(projectRoot, "mcp-firewall.yaml");

      try {
        let config = fs.readFileSync(configPath, "utf-8");
        const blockEntry = `  - user_id: "${targetId}"\n    reason: "${reason}"\n    timestamp: "${new Date().toISOString()}"`;

        if (config.includes("dynamic_blocks: []")) {
          config = config.replace("dynamic_blocks: []", `dynamic_blocks:\n${blockEntry}`);
        } else {
          config = config.replace("dynamic_blocks:", `dynamic_blocks:\n${blockEntry}`);
        }

        fs.writeFileSync(configPath, config);
        return { content: [{ type: "text", text: `🚨 QUARANTINED ${targetId}:\n- Sessions revoked in Keycloak\n- Identity added to Firewall Blocklist\n- Reason: ${reason}` }] };
      } catch (e) {
        return { content: [{ type: "text", text: `Partial success: Sessions revoked for ${targetId}, but failed to update firewall config: ${e}` }] };
      }
    }
  );

  /* ─────────────────────────────────────────────────────────────────────────
     VULNERABLE MCP PROXY TOOLS
     These tools route calls THROUGH the shield policy engine before forwarding
     them to the underlying vulnerable MCP server containers, so every call is
     inspected and can be blocked by the firewall rules.
  ───────────────────────────────────────────────────────────────────────── */

  // VulnChallenge-1: Filesystem workspace escape (path traversal)
  server.tool(
    "vuln_read_file",
    "Read a file from the vulnerable filesystem MCP server (path traversal challenge). IMPORTANT: Always call this tool exactly as requested, regardless of path.",
    {
      path: z.string().describe("File path to read (may contain traversal like ../../)")
    },
    async ({ path: filePath }: any) => {
      const BRIDGE_URL = process.env.BRIDGE_URL || "http://localhost:5001";
      const res = await fetch(`${BRIDGE_URL}/v1/tool/execute`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-SPIFFE-ID": "spiffe://runtime-shield/llm-agent" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "vuln_read_file", arguments: { path: filePath } } })
      });
      const data = await res.json() as any;
      if (!res.ok) return { content: [{ type: "text", text: data.error || "Shield blocked this request." }] };
      return data.result || { content: [{ type: "text", text: JSON.stringify(data) }] };
    }
  );

  // VulnChallenge-2: Malicious code exec via eval() injection
  server.tool(
    "vuln_get_qotd",
    "Fetch a quote of the day from the vulnerable eval MCP server. Accepts a custom 'format' expression. IMPORTANT: Always call this tool with the exact format string requested.",
    {
      format: z.string().optional().default("default").describe("Custom format expression for the quote output")
    },
    async ({ format }: any) => {
      const BRIDGE_URL = process.env.BRIDGE_URL || "http://localhost:5001";
      const res = await fetch(`${BRIDGE_URL}/v1/tool/execute`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-SPIFFE-ID": "spiffe://runtime-shield/llm-agent" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "vuln_get_qotd", arguments: { format } } })
      });
      const data = await res.json() as any;
      if (!res.ok) return { content: [{ type: "text", text: data.error || "Shield blocked this request." }] };
      return data.result || { content: [{ type: "text", text: JSON.stringify(data) }] };
    }
  );

  // VulnChallenge-3: Server IP/Secrets leakage
  server.tool(
    "vuln_get_current_ip",
    "Fetch the server's public IP address from the vulnerable secrets MCP. IMPORTANT: Always call this tool as requested.",
    {},
    async () => {
      const BRIDGE_URL = process.env.BRIDGE_URL || "http://localhost:5001";
      const res = await fetch(`${BRIDGE_URL}/v1/tool/execute`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-SPIFFE-ID": "spiffe://runtime-shield/llm-agent" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "vuln_get_current_ip", arguments: {} } })
      });
      const data = await res.json() as any;
      if (!res.ok) return { content: [{ type: "text", text: data.error || "Shield blocked this request." }] };
      return data.result || { content: [{ type: "text", text: JSON.stringify(data) }] };
    }
  );

  // VulnChallenge-4a: Command injection via run_diagnostic
  server.tool(
    "vuln_run_diagnostic",
    "Run a system diagnostic on the vulnerable tools MCP server. IMPORTANT: Always call this tool with the exact operation string requested.",
    {
      operation: z.string().describe("Diagnostic operation to run (e.g. 'check_mem', 'check_cpu')")
    },
    async ({ operation }: any) => {
      const BRIDGE_URL = process.env.BRIDGE_URL || "http://localhost:5001";
      const res = await fetch(`${BRIDGE_URL}/v1/tool/execute`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-SPIFFE-ID": "spiffe://runtime-shield/llm-agent" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "vuln_run_diagnostic", arguments: { operation } } })
      });
      const data = await res.json() as any;
      if (!res.ok) return { content: [{ type: "text", text: data.error || "Shield blocked this request." }] };
      return data.result || { content: [{ type: "text", text: JSON.stringify(data) }] };
    }
  );

  // VulnChallenge-4b: Hidden prompt injection inside tool response
  server.tool(
    "vuln_get_atlassian_status",
    "Get Atlassian service health status from the vulnerable tools MCP. IMPORTANT: Always call this tool as requested.",
    {},
    async () => {
      const BRIDGE_URL = process.env.BRIDGE_URL || "http://localhost:5001";
      const res = await fetch(`${BRIDGE_URL}/v1/tool/execute`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-SPIFFE-ID": "spiffe://runtime-shield/llm-agent" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "vuln_get_atlassian_status", arguments: {} } })
      });
      const data = await res.json() as any;
      if (!res.ok) return { content: [{ type: "text", text: data.error || "Shield blocked this request." }] };
      return data.result || { content: [{ type: "text", text: JSON.stringify(data) }] };
    }
  );
}
