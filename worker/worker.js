/**
 * melody-r2-worker
 *
 * Old behaviour: the worker accepted one fixed string ("melody-secret-2026")
 * as a bearer token. That string sat in index.html in a public repository, so
 * any reader could upload, overwrite and delete the entire music library, and
 * /list was open to everyone, which handed out the exact key of every object
 * in the bucket.
 *
 * New behaviour: every mutating request and /list must carry a real Firebase
 * ID token. The token is verified against Google's published signing keys, is
 * pinned to this one Firebase project, must carry an email (which rejects
 * anonymous sign-in, since anyone can mint an anonymous token using the public
 * web API key), and the caller must be an approved member in the database.
 * Uploads and deletes additionally require the admin role.
 *
 * Plain GET of a single object stays open on purpose: playback happens through
 * <audio src="..."> and a media element cannot send an Authorization header.
 * Keys are long and unguessable, and /list is now closed, so the bucket can no
 * longer be enumerated.
 */

const PROJECT_ID = "melody-app-e29f5";
const DB_URL     = "https://melody-app-e29f5-default-rtdb.asia-southeast1.firebasedatabase.app";
const JWK_URL    = "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com";

const ALLOWED_ORIGINS = [
  "https://melody.sramesh.in",
  "http://localhost:8080",
];

// ---------------------------------------------------------------- CORS
function corsHeaders(request) {
  const origin = request.headers.get("Origin") || "";
  const allow  = ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0];
  return {
    "Access-Control-Allow-Origin":  allow,
    "Access-Control-Allow-Methods": "GET,PUT,DELETE,OPTIONS",
    "Access-Control-Allow-Headers": "Authorization,Content-Type",
    "Access-Control-Max-Age":       "86400",
    "Vary":                         "Origin",
  };
}

function json(body, status, request) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...corsHeaders(request) },
  });
}

// ---------------------------------------------------------------- JWT
function b64urlToBytes(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function b64urlToJson(s) {
  return JSON.parse(new TextDecoder().decode(b64urlToBytes(s)));
}

// Google rotates these keys; cache them for as long as Google says, no longer.
let jwkCache = { keys: null, expires: 0 };

async function getSigningKeys() {
  const now = Date.now();
  if (jwkCache.keys && now < jwkCache.expires) return jwkCache.keys;

  const resp = await fetch(JWK_URL);
  if (!resp.ok) throw new Error("could not fetch signing keys");
  const body = await resp.json();

  const cc = resp.headers.get("Cache-Control") || "";
  const m = cc.match(/max-age=(\d+)/);
  const ttl = m ? parseInt(m[1], 10) * 1000 : 3600 * 1000;

  jwkCache = { keys: body.keys, expires: now + ttl };
  return body.keys;
}

async function verifyIdToken(idToken) {
  const parts = idToken.split(".");
  if (parts.length !== 3) throw new Error("malformed token");

  const header = b64urlToJson(parts[0]);
  if (header.alg !== "RS256") throw new Error("wrong algorithm");
  if (!header.kid) throw new Error("no key id");

  const keys = await getSigningKeys();
  const jwk  = keys.find(k => k.kid === header.kid);
  if (!jwk) throw new Error("unknown key id");

  const key = await crypto.subtle.importKey(
    "jwk",
    { kty: jwk.kty, n: jwk.n, e: jwk.e, alg: "RS256", ext: true },
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"]
  );

  const signed = new TextEncoder().encode(parts[0] + "." + parts[1]);
  const ok = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5", key, b64urlToBytes(parts[2]), signed
  );
  if (!ok) throw new Error("bad signature");

  const payload = b64urlToJson(parts[1]);
  const now  = Math.floor(Date.now() / 1000);
  const skew = 60;

  if (payload.aud !== PROJECT_ID) throw new Error("wrong project");
  if (payload.iss !== "https://securetoken.google.com/" + PROJECT_ID) throw new Error("wrong issuer");
  if (typeof payload.exp !== "number" || payload.exp + skew < now) throw new Error("token expired");
  if (typeof payload.iat !== "number" || payload.iat - skew > now) throw new Error("token from the future");
  if (!payload.sub) throw new Error("no subject");

  // An anonymous sign-in produces a perfectly valid token with no email, and
  // anyone at all can obtain one using the public web API key. Reject it.
  if (!payload.email) throw new Error("anonymous token rejected");

  return payload;
}

// ---------------------------------------------------------------- membership
// The database itself is the single source of truth for who may do what, so
// the worker asks it rather than keeping a second copy of the member list.
async function getMember(uid, idToken) {
  const url = `${DB_URL}/members/${encodeURIComponent(uid)}.json?auth=${encodeURIComponent(idToken)}`;
  const resp = await fetch(url);
  if (!resp.ok) throw new Error("membership lookup failed");
  const m = await resp.json();
  if (!m || m.status !== "approved") throw new Error("not an approved member");
  return m;
}

async function requireMember(request, needAdmin) {
  const header = request.headers.get("Authorization") || "";
  if (!header.startsWith("Bearer ")) throw new Error("no token");
  const idToken = header.slice(7).trim();

  const payload = await verifyIdToken(idToken);
  const member  = await getMember(payload.sub, idToken);
  if (needAdmin && member.role !== "admin") throw new Error("admin only");
  return member;
}

// ---------------------------------------------------------------- R2
async function listObjects(bucket) {
  const out = [];
  let cursor;
  // R2 pages at 1000; keep going so the library is never silently truncated.
  do {
    const page = await bucket.list({ cursor, limit: 1000 });
    for (const o of page.objects) {
      out.push({ key: o.key, size: o.size, uploaded: o.uploaded });
    }
    cursor = page.truncated ? page.cursor : undefined;
  } while (cursor);
  return out;
}

function parseRange(header) {
  const m = /^bytes=(\d*)-(\d*)$/.exec((header || "").trim());
  if (!m) return null;

  if (m[1] === "") {
    const suffix = parseInt(m[2], 10);
    if (isNaN(suffix) || suffix <= 0) return null;
    return { suffix };
  }

  const offset = parseInt(m[1], 10);
  if (isNaN(offset) || offset < 0) return null;
  if (m[2] === "") return { offset };

  const end = parseInt(m[2], 10);
  if (isNaN(end) || end < offset) return null;
  return { offset, length: end - offset + 1 };
}

// ---------------------------------------------------------------- handler
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const key = decodeURIComponent(url.pathname.slice(1));

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders(request) });
    }

    // ---- /list : approved members only ----
    if (key === "list") {
      if (request.method !== "GET") return json({ error: "method not allowed" }, 405, request);
      try {
        await requireMember(request, false);
      } catch (e) {
        return json({ error: "unauthorized" }, 401, request);
      }
      try {
        return json(await listObjects(env.MELODY_BUCKET), 200, request);
      } catch (e) {
        return json({ error: "list failed" }, 500, request);
      }
    }

    if (!key) return json({ error: "no key" }, 400, request);

    // ---- GET one object : open, so <audio> can stream it ----
    if (request.method === "GET" || request.method === "HEAD") {
      const range = parseRange(request.headers.get("Range"));
      let obj;
      try {
        obj = await env.MELODY_BUCKET.get(key, range ? { range } : undefined);
      } catch (e) {
        // An unsatisfiable range throws rather than returning null.
        return new Response(null, { status: 416, headers: corsHeaders(request) });
      }
      if (!obj) return json({ error: "not found" }, 404, request);

      const headers = new Headers(corsHeaders(request));
      obj.writeHttpMetadata(headers);
      headers.set("etag", obj.httpEtag);
      headers.set("Accept-Ranges", "bytes");
      headers.set("Cache-Control", "public, max-age=31536000, immutable");

      if (obj.range) {
        const r = obj.range;
        const start = typeof r.offset === "number" ? r.offset : obj.size - r.suffix;
        const len   = typeof r.length === "number" ? r.length
                    : typeof r.suffix === "number" ? r.suffix
                    : obj.size - start;
        const end   = start + len - 1;
        headers.set("Content-Range", `bytes ${start}-${end}/${obj.size}`);
        headers.set("Content-Length", String(len));
        return new Response(request.method === "HEAD" ? null : obj.body, { status: 206, headers });
      }

      headers.set("Content-Length", String(obj.size));
      return new Response(request.method === "HEAD" ? null : obj.body, { status: 200, headers });
    }

    // ---- PUT / DELETE : admin only ----
    if (request.method === "PUT" || request.method === "DELETE") {
      try {
        await requireMember(request, true);
      } catch (e) {
        return json({ error: "unauthorized" }, 401, request);
      }

      try {
        if (request.method === "PUT") {
          await env.MELODY_BUCKET.put(key, request.body, {
            httpMetadata: {
              contentType: request.headers.get("Content-Type") || "application/octet-stream",
            },
          });
          return json({ ok: true, key }, 200, request);
        }
        await env.MELODY_BUCKET.delete(key);
        return json({ ok: true, key }, 200, request);
      } catch (e) {
        return json({ error: "storage error" }, 500, request);
      }
    }

    return json({ error: "method not allowed" }, 405, request);
  },
};
