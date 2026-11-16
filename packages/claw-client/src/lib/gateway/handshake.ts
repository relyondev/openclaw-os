import type { Settings } from "../storage";
import type { DeviceIdentity } from "./device-identity";
import { signMessage, toBase64Url } from "./device-identity";
import type { ConnectParams } from "./types";
import { GATEWAY_CLIENT_CAPS, GATEWAY_CLIENT_IDS, GATEWAY_CLIENT_MODES } from "./types";

const PROTOCOL_VERSION = 4;
const CLIENT_ID = GATEWAY_CLIENT_IDS.CONTROL_UI;
const CLIENT_MODE = GATEWAY_CLIENT_MODES.UI;
const CLIENT_VERSION = "0.1.0";
const ROLE = "operator";
const SCOPES = ["operator.read", "operator.write", "operator.admin"];

/**
 * Builds the v3 signature payload string.
 * Format: v3|deviceId|clientId|clientMode|role|scopesCsv|signedAtMs|token|nonce|platformNorm|deviceFamilyNorm
 */
function buildV3Payload(
  deviceId: string,
  clientMode: string,
  signedAtMs: number,
  token: string,
  nonce: string,
): string {
  const scopesCsv = SCOPES.join(",");
  const platformNorm = "web";
  const deviceFamilyNorm = "";
  return [
    "v3",
    deviceId,
    CLIENT_ID,
    clientMode,
    ROLE,
    scopesCsv,
    signedAtMs.toString(),
    token,
    nonce,
    platformNorm,
    deviceFamilyNorm,
  ].join("|");
}

let cachedBuildId: { gatewayUrl: string; buildId: string | undefined } | null = null;

/**
 * Reads the gateway's build id from its HTTP `control-ui-config.json`, served
 * next to the WebSocket. Newer gateways refuse Control UI clients that don't
 * report a matching build. Returns undefined when unavailable (older gateways
 * don't check, so connecting without it still works there).
 */
async function resolveGatewayBuildId(gatewayUrl: string): Promise<string | undefined> {
  if (cachedBuildId?.gatewayUrl === gatewayUrl) return cachedBuildId.buildId;
  let buildId: string | undefined;
  try {
    const url = new URL(gatewayUrl);
    url.protocol = url.protocol === "wss:" ? "https:" : "http:";
    url.pathname = `${url.pathname.replace(/\/+$/, "")}/control-ui-config.json`;
    url.search = "";
    url.hash = "";
    const res = await fetch(url.toString(), { credentials: "include", cache: "no-store" });
    if (res.ok) {
      const config = (await res.json()) as { serverBuildId?: unknown };
      if (typeof config.serverBuildId === "string" && config.serverBuildId.trim()) {
        buildId = config.serverBuildId.trim();
      }
    }
  } catch {
    // Older gateway, cross-origin without CORS, or offline: connect without it.
  }
  cachedBuildId = { gatewayUrl, buildId };
  return buildId;
}

/** Drops the cached build id so the next connect re-reads it (e.g. after a gateway upgrade). */
export function resetGatewayBuildId(): void {
  cachedBuildId = null;
}

export async function buildConnectParams(
  nonce: string,
  settings: Settings,
  device: DeviceIdentity,
): Promise<ConnectParams> {
  const signedAtMs = Date.now();
  const token = settings.deviceToken ?? settings.token ?? "";
  const payload = buildV3Payload(device.deviceId, CLIENT_MODE, signedAtMs, token, nonce);
  const signatureBytes = await signMessage(payload, device.privateKey);
  const buildId = await resolveGatewayBuildId(settings.gatewayUrl);

  return {
    minProtocol: PROTOCOL_VERSION,
    maxProtocol: PROTOCOL_VERSION,
    caps: [GATEWAY_CLIENT_CAPS.TOOL_EVENTS, GATEWAY_CLIENT_CAPS.THINKING_EVENTS],
    client: {
      id: CLIENT_ID,
      version: CLIENT_VERSION,
      platform: "web",
      mode: CLIENT_MODE,
      ...(buildId ? { buildId } : {}),
    },
    role: ROLE,
    scopes: SCOPES,
    auth: settings.deviceToken ? { deviceToken: settings.deviceToken } : { token: settings.token },
    device: {
      id: device.deviceId,
      publicKey: toBase64Url(device.publicKey),
      signature: toBase64Url(signatureBytes),
      signedAt: signedAtMs,
      nonce,
    },
    locale: "en-US",
    userAgent: `claw/${CLIENT_VERSION}`,
  };
}
