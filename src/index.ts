import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { registerTools } from "./tools/tools.js";
import { verifySpiffeIdentity } from "./tools/spiffeAuth.js";
import dotenv from "dotenv";

import path from "node:path";
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);


const envPath = path.resolve(__dirname, '../.env');
dotenv.config({ path: envPath });

import child_process from "node:child_process";
import net from "node:net";
import dgram from "node:dgram";

function applyNodeRuntimeContainment() {
  console.error("🔒 [Node Hardening Gateway] Initializing Layer 7 Runtime Containment...");

  // 1. Phase 4: Child Process Control (Default Deny)
  const blockCP = () => {
    const errorMsg = "Security Violation: Child process spawning is strictly prohibited in this sandboxed environment.";
    (child_process as any).spawn = () => { throw new Error(errorMsg); };
    (child_process as any).spawnSync = () => { throw new Error(errorMsg) as any; };
    (child_process as any).exec = () => { throw new Error(errorMsg) as any; };
    (child_process as any).execSync = () => { throw new Error(errorMsg) as any; };
    (child_process as any).execFile = () => { throw new Error(errorMsg) as any; };
    (child_process as any).execFileSync = () => { throw new Error(errorMsg) as any; };
    (child_process as any).fork = () => { throw new Error(errorMsg); };
    console.error("🔒 [Node Hardening Gateway] Child process spawning permanently disabled.");
  };
  blockCP();

  // 2. Phase 5: Network Isolation (Environment-dependent L7 Socket Blocking)
  const provider = process.env.PROVIDER_NAME || "unknown";
  if (provider === "filesystem-provider") {
    // filesystem-provider gets NO network access
    (net as any).Socket = class extends net.Socket {
      constructor(options: any) {
        super(options);
        throw new Error("Security Violation: Socket creation is strictly prohibited for the filesystem-provider.");
      }
    };
    (dgram as any).Socket = class extends dgram.Socket {
      constructor() {
        super();
        throw new Error("Security Violation: UDP socket creation is strictly prohibited for the filesystem-provider.");
      }
    };
    console.error("🔒 [Node Hardening Gateway] TCP/UDP socket creation permanently blocked for filesystem-provider.");
  } else if (provider === "keycloak-provider") {
    // keycloak-provider only allowed to access localhost:8080
    const originalConnect = net.Socket.prototype.connect;
    net.Socket.prototype.connect = function(options: any, cb: any) {
      let host = "";
      let port: any = 0;
      
      // Unpack wrapped options array (Node/Undici internal argument normalization)
      let parsedOptions = options;
      if (Array.isArray(parsedOptions)) {
        parsedOptions = parsedOptions[0];
      }
      
      if (parsedOptions && typeof parsedOptions === "object") {
        host = parsedOptions.host || "localhost";
        port = parsedOptions.port;
      } else if (typeof options === "number") {
        port = options;
        host = arguments[1] || "localhost";
      }
      
      // Normalize port to a number in case it was passed as a string "8080"
      const portNum = typeof port === "string" ? parseInt(port, 10) : port;
      
      const isLocalhost = host === "localhost" || host === "127.0.0.1" || host === "::1";
      if (!isLocalhost || portNum !== 8080) {
        throw new Error(`Security Violation: Connection to '${host}:${portNum}' is blocked for keycloak-provider. ONLY connection to localhost:8080 is allowed.`);
      }
      return originalConnect.apply(this, arguments as any);
    };
    console.error("🔒 [Node Hardening Gateway] Outbound TCP network calls restricted ONLY to localhost:8080 for keycloak-provider.");
  }
}

// applyNodeRuntimeContainment() will be called in main() after attestation

const provider = process.env.PROVIDER_NAME || "unknown";
const mandatoryVars = ["KEYCLOAK_URL", "KEYCLOAK_REALM"];
if (provider === "keycloak-provider") {
    mandatoryVars.push("KEYCLOAK_CLIENT_ID", "KEYCLOAK_CLIENT_SECRET");
}
const missingVars = mandatoryVars.filter(v => !process.env[v]);
if (missingVars.length > 0) {
    console.error(`❌ Fatal Startup Error: Keycloak configuration is incomplete. Missing environment variables: ${missingVars.join(", ")}`);
    console.error("Make sure your .env file is set up correctly and you run the server from the project root.");
    console.error("Current directory:", process.cwd());
    process.exit(1);
}

// Create an MCP server instance
const server = new McpServer({
    name: "Secure-Runtime-Shield",
    version: "1.0.0",
});

// Register the Keycloak tools
registerTools(server);



// --- AGENT IDENTITY HARDENING (JIT TOKENS) ---
import { verifyJitToken, verifyAuthContext, AuthContext } from "./tools/rbac.js";

const TOOL_SCOPES: Record<string, string> = {
  "read_file": "tool:read_file",
  "write_file": "tool:write_file",
  "list_directory": "tool:list_directory",
  "get_system_config": "tool:admin_internal",
  "fetch_internal_db": "tool:admin_internal",
  "keycloak_list_users": "tool:keycloak_read",
  "keycloak_list_user_sessions": "tool:keycloak_read",
  "keycloak_revoke_user_sessions": "tool:keycloak_admin",
  "keycloak_get_user_events": "tool:keycloak_read",
  "keycloak_security_report": "tool:keycloak_report",
  "keycloak_generate_policy": "tool:keycloak_report",
  "keycloak_quarantine_user": "tool:keycloak_admin"
};

const TOOL_ROLE_POLICY: Record<string, string> = {
  "keycloak_revoke_user_sessions": "admin",
  "keycloak_list_user_sessions": "admin",
  "keycloak_list_users": "admin",
  "keycloak_get_user_events": "admin",
  "keycloak_security_report": "admin",
  "keycloak_generate_policy": "admin",
  "keycloak_quarantine_user": "admin"
};

function wrapToolsWithJitVerification(serverInstance: any) {
  const registeredTools = serverInstance._registeredTools || {};
  for (const [toolName, toolObj] of Object.entries(registeredTools)) {
    const originalHandler = (toolObj as any).handler;
    if (typeof originalHandler !== "function") continue;

    (toolObj as any).handler = async (args: any, extra: any) => {
      console.error(`🔒 [JIT Security Gateway] Intercepted tool call: '${toolName}'`);
      
      const expectedScope = TOOL_SCOPES[toolName] || `tool:${toolName}`;
      const expectedAudience = process.env.KEYCLOAK_AUDIENCE || process.env.KEYCLOAK_CLIENT_ID || "admin-cli";
      const requiredRole = TOOL_ROLE_POLICY[toolName]; // could be admin or undefined

      let token: string | undefined = undefined;
      let authSource: "new_context" | "_meta_fallback" | "missing" = "missing";
      let authContext: AuthContext | undefined = undefined;

      const ext = extra as any;
      if (ext?._meta?.authContext?.jitToken) {
        authContext = ext._meta.authContext;
        token = ext._meta.authContext.jitToken;
        authSource = "new_context";
      } else if (ext?._meta?.metadata?.token) {
        token = ext._meta.metadata.token;
        authSource = "_meta_fallback";
      }

      console.error(`🔒 [JIT Security Gateway] AUTH_CONTEXT_SOURCE=${authSource}`);

      // Centralized Filesystem Root Containment & Traversal Hardening (Phase 1)
      if (["read_file", "write_file", "list_directory"].includes(toolName)) {
        const filePath = args.path;
        if (filePath && typeof filePath === "string") {
          // 1. Normalize separators
          let normalizedPath = filePath.replace(/\\/g, "/");
          
          // 2. Traversal and absolute path pattern checks
          const segments = normalizedPath.split("/").map(s => s.trim()).filter(Boolean);
          const hasTraversal = segments.includes("..") || segments.some(s => s === ".." || s.startsWith("..") || s.endsWith(".."));
          const hasTrailingDot = normalizedPath.endsWith("/.") || normalizedPath.endsWith("/..") || normalizedPath === "." || normalizedPath === "..";
          const isAbsolute = normalizedPath.startsWith("/") || normalizedPath.includes(":") || normalizedPath.startsWith("//");
          
          if (hasTraversal || hasTrailingDot || isAbsolute) {
            console.error(`❌ [JIT Security Gateway] DENIED: Traversal or absolute path attempt blocked inside MCP: '${filePath}'`);
            throw new Error(`Security Violation: Directory traversal or absolute path attempt detected: '${filePath}'`);
          }

          // 3. Resolve to absolute paths
          const projectRoot = path.resolve(process.cwd());
          const allowedRoot = path.resolve(projectRoot, "secure-experiment-zone");
          const resolvedPath = path.resolve(projectRoot, normalizedPath);

          const role = authContext?.requiredRole || process.env.RUNTIME_ROLE || "user";
          if (role !== "admin") {
            // Verify path is strictly within the allowed zone
            if (resolvedPath !== allowedRoot && !resolvedPath.startsWith(allowedRoot + path.sep) && !resolvedPath.startsWith(allowedRoot + "/")) {
              console.error(`❌ [JIT Security Gateway] DENIED: Path '${filePath}' resolves to '${resolvedPath}' which escapes allowed zone '${allowedRoot}' for role '${role}'`);
              throw new Error(`Security Violation: Path '${filePath}' is outside the authorized secure-experiment-zone`);
            }
          }
          
          // Update the argument to normalized absolute path
          args.path = resolvedPath;
          console.error(`🔒 [JIT Security Gateway] Path validated & normalized: '${resolvedPath}'`);
        }
      }

      if (process.env.LOCAL_DEV_MODE === "true") {
        console.error(`⚠️ [JIT Security Gateway] LOCAL DEV BYPASS: LOCAL_DEV_MODE=true. Bypassing JIT token verification for '${toolName}'.`);
        return await originalHandler(args, extra);
      }

      if (!token) {
        console.error(`❌ [JIT Security Gateway] DENIED: No JIT token found in metadata for tool '${toolName}'`);
        throw new Error(`Unauthorized: No JIT token found in metadata for tool '${toolName}'`);
      }

      try {
        console.error(`🔒 [JIT Security Gateway] Verifying token for tool '${toolName}'...`);
        console.error(`   - Expected Scope: '${expectedScope}'`);
        console.error(`   - Expected Audience: '${expectedAudience}'`);
        console.error(`   - Expected Role: '${requiredRole || "any"}'`);

        let decoded: any;
        if (authContext) {
          authContext.requiredScope = expectedScope;
          authContext.requiredRole = requiredRole;
          decoded = await verifyAuthContext(authContext);
        } else {
          decoded = await verifyJitToken(token, expectedScope, expectedAudience, requiredRole);
        }
        console.error(`✅ [JIT Security Gateway] JIT Token verified successfully for user: ${decoded.preferred_username || decoded.sub}`);
      } catch (err: any) {
        console.error(`❌ [JIT Security Gateway] DENIED: Token verification failed for tool '${toolName}': ${err.message}`);
        throw new Error(`Security Violation: JIT Token Verification Failed: ${err.message}`);
      }

      return await originalHandler(args, extra);
    };
  }
  console.error("🔒 [JIT Security Gateway] All registered tools wrapped with JIT token verification.");
}

wrapToolsWithJitVerification(server);


// Connect via Stdio
async function main() {
    console.error("🔐 Initializing SPIFFE Workload Attestation...");
    const attestation = await verifySpiffeIdentity().catch(err => ({ valid: false, error: err.message })) as any;
    
    if (!attestation.valid) {
        console.error(`❌ SPIFFE Attestation Failed: ${attestation.error || "Unknown error"}`);
        process.exit(1);
    }
    console.error(`✅ SPIFFE Verification Active: Trusted Workload SVID verified: ${attestation.spiffe_id}`);

    // Lock down child processes and networking now that SPIFFE attestation is complete
    applyNodeRuntimeContainment();

    const transport = new StdioServerTransport();

    await server.connect(transport);
    console.error("Keycloak MCP Server running on stdio");
}

main().catch((error) => {
    console.error("Fatal error in main():", error);
    process.exit(1);
});
