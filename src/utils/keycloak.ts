import KcAdminClient from "@keycloak/keycloak-admin-client";

let kc: KcAdminClient | null = null;

export async function getKcClient() {

  if (!kc) {
    kc = new KcAdminClient({
      baseUrl: process.env.KEYCLOAK_URL,
      realmName: process.env.KEYCLOAK_REALM
    });
  }

  // 🔥 ALWAYS AUTH (refresh token every time)
  await kc.auth({
    grantType: "client_credentials",
    clientId: process.env.KEYCLOAK_CLIENT_ID!,
    clientSecret: process.env.KEYCLOAK_CLIENT_SECRET!
  });

  return kc;
}