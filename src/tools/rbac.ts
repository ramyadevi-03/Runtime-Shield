import jwt from "jsonwebtoken";
import fetch from "node-fetch";

let cachedKeys: any = null;
let lastFetchTime = 0;

async function getPublicKey(kid: string): Promise<string> {
    const now = Date.now();
    if (!cachedKeys || (now - lastFetchTime > 5 * 60 * 1000)) {
        const keycloakUrl = process.env.KEYCLOAK_URL;
        const realm = process.env.KEYCLOAK_REALM;
        if (!keycloakUrl || !realm) {
            throw new Error("Fatal Error: KEYCLOAK_URL or KEYCLOAK_REALM not configured in environment variables");
        }
        const url = `${keycloakUrl}/realms/${realm}/protocol/openid-connect/certs`;
        
        const res = await fetch(url);
        if (!res.ok) {
            throw new Error(`Failed to fetch JWKS from Keycloak: ${res.statusText}`);
        }
        const jwks: any = await res.json();
        cachedKeys = jwks.keys || [];
        lastFetchTime = now;
    }

    const key = cachedKeys.find((k: any) => k.kid === kid);
    if (!key) {
        throw new Error(`Key with kid ${kid} not found in Keycloak JWKS`);
    }

    if (!key.x5c || key.x5c.length === 0) {
        throw new Error(`No x5c certificate found for kid ${kid}`);
    }

    // Format the base64 x5c DER cert into PEM format
    const pem = `-----BEGIN CERTIFICATE-----\n${key.x5c[0]}\n-----END CERTIFICATE-----`;
    return pem;
}

export interface AuthContext {
  requestId: string | number;
  jitToken: string;
  jitClaims?: any;
  requiredScope?: string;
  requiredRole?: string;
  workloadSpiffeId?: string;
  trustedWorkload?: boolean;
  source: "bridge";
}

export async function verifyAuthContext(context: AuthContext): Promise<any> {
    if (!context.jitToken) {
        throw new Error("No JIT token found in Auth Context");
    }

    // Workload attestation check (SPIFFE)
    if (context.workloadSpiffeId) {
        if (context.trustedWorkload === false) {
            throw new Error(`Security Violation: Untrusted workload identity: ${context.workloadSpiffeId}`);
        }
        console.error(`🔒 [JIT Security Gateway] Trusted Workload SVID bound & verified: ${context.workloadSpiffeId}`);
    }

    const expectedScope = context.requiredScope || "";
    const expectedAudience = process.env.KEYCLOAK_AUDIENCE || process.env.KEYCLOAK_CLIENT_ID || "admin-cli";
    const expectedRole = context.requiredRole;

    const decoded = await verifyJitToken(context.jitToken, expectedScope, expectedAudience, expectedRole);
    context.jitClaims = decoded;
    return decoded;
}

export async function verifyJitToken(
    token: string,
    expectedScope: string,
    expectedAudience: string,
    expectedRole?: string
): Promise<any> {
    if (!token) {
        throw new Error("No authentication token provided");
    }

    // Decode token header to extract dynamic kid
    const decodedHeader: any = jwt.decode(token, { complete: true });
    if (!decodedHeader || !decodedHeader.header || !decodedHeader.header.kid) {
        throw new Error("Invalid JWT token format or missing kid header");
    }

    const kid = decodedHeader.header.kid;
    const cert = await getPublicKey(kid);

    const keycloakUrl = process.env.KEYCLOAK_URL;
    const realm = process.env.KEYCLOAK_REALM;
    if (!keycloakUrl || !realm) {
        throw new Error("Fatal Error: KEYCLOAK_URL or KEYCLOAK_REALM not configured in environment variables");
    }
    const expectedIssuer = `${keycloakUrl}/realms/${realm}`;

    // Cryptographic validation using jsonwebtoken (without strict audience check inside verify, as public client tokens might not have aud claim)
    const decoded: any = jwt.verify(token, cert, {
        algorithms: ["RS256"],
        issuer: expectedIssuer,
    });

    if (!decoded) {
        throw new Error("JWT cryptographic validation failed");
    }

    // Dynamic audience/authorized party (azp) verification
    const aud = decoded.aud;
    const azp = decoded.azp;
    let audValid = false;

    if (aud) {
        const audiences = Array.isArray(aud) ? aud : [aud];
        if (audiences.includes(expectedAudience)) {
            audValid = true;
        }
    }
    
    if (azp && azp === expectedAudience) {
        audValid = true;
    }

    if (!audValid) {
        if (aud) {
            throw new Error(`jwt audience invalid. expected: ${expectedAudience}, got: ${JSON.stringify(aud)}`);
        } else if (azp) {
            throw new Error(`jwt authorized party (azp) invalid. expected: ${expectedAudience}, got: ${azp}`);
        } else {
            throw new Error("Missing both aud and azp claims in JWT token");
        }
    }

    // Scope verification
    const scope = decoded.scope || "";
    const scopes = typeof scope === "string" ? scope.split(" ") : [];
    if (expectedScope && !scopes.includes(expectedScope)) {
        throw new Error(`Token missing required scope: ${expectedScope}`);
    }

    // Role verification
    if (expectedRole) {
        const roles = decoded.realm_access?.roles || [];
        if (!roles.includes(expectedRole)) {
            throw new Error(`User does not possess required role: ${expectedRole}`);
        }
    }

    return decoded;
}

export function getUserRoles(token: string): string[] {

    const decoded: any = jwt.decode(token);

    if (!decoded || !decoded.realm_access) {
        throw new Error("Invalid token");
    }

    return decoded.realm_access.roles || [];
}

export function checkRole(userRoles: string[], allowedRoles: string[]) {

    const allowed = userRoles.some(role =>
        allowedRoles.includes(role)
    );

    if (!allowed) {
        throw new Error("Unauthorized tool access");
    }
}