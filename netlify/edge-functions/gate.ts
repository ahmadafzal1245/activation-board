import { getStore } from "https://esm.sh/@netlify/blobs@10.7.13";

const STORE_NAME = "auth-users";

function unauthorized(realm: string) {
  return new Response("Authentication required", {
    status: 401,
    headers: { "WWW-Authenticate": `Basic realm="${realm}"` },
  });
}

async function sha256Hex(text: string) {
  const enc = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest("SHA-256", enc);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function randomSalt() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function parseBasicAuth(request: Request) {
  const header = request.headers.get("authorization") || "";
  if (!header.startsWith("Basic ")) return null;
  try {
    const decoded = atob(header.slice(6));
    const idx = decoded.indexOf(":");
    if (idx < 0) return null;
    return { username: decoded.slice(0, idx), password: decoded.slice(idx + 1) };
  } catch {
    return null;
  }
}

async function verifyUser(store: ReturnType<typeof getStore>, username: string, password: string) {
  const raw = await store.get(username.toLowerCase());
  if (!raw) return null;
  const user = JSON.parse(raw);
  const hash = await sha256Hex(user.salt + password);
  if (hash !== user.hash) return null;
  return user;
}

function escapeHtml(s: string) {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]!));
}

export default async (request: Request, context: any) => {
  const url = new URL(request.url);
  const store = getStore({ name: STORE_NAME, consistency: "strong" });

  const creds = parseBasicAuth(request);
  const user = creds ? await verifyUser(store, creds.username, creds.password) : null;

  if (url.pathname === "/admin" || url.pathname === "/admin/") {
    if (!user || !user.isAdmin) return unauthorized("Admin area");

    if (request.method === "POST") {
      const form = await request.formData();
      const action = form.get("action");

      if (action === "add") {
        const newUsername = String(form.get("username") || "").trim().toLowerCase();
        const newPassword = String(form.get("password") || "");
        const isAdmin = form.get("isAdmin") === "on";
        if (newUsername && newPassword) {
          const salt = randomSalt();
          const hash = await sha256Hex(salt + newPassword);
          await store.set(
            newUsername,
            JSON.stringify({ username: newUsername, salt, hash, isAdmin, createdAt: new Date().toISOString() })
          );
        }
      } else if (action === "delete") {
        const target = String(form.get("username") || "").trim().toLowerCase();
        if (target && target !== user.username) {
          await store.delete(target);
        }
      }
      return new Response(null, { status: 303, headers: { Location: "/admin" } });
    }

    const { blobs } = await store.list();
    const users: { username: string; isAdmin: boolean; createdAt?: string }[] = [];
    for (const b of blobs) {
      const raw = await store.get(b.key);
      if (raw) {
        const u = JSON.parse(raw);
        users.push({ username: u.username, isAdmin: !!u.isAdmin, createdAt: u.createdAt });
      }
    }
    users.sort((a, b) => a.username.localeCompare(b.username));

    const rows = users
      .map(
        (u) => `
      <tr>
        <td>${escapeHtml(u.username)}</td>
        <td>${u.isAdmin ? "Yes" : "No"}</td>
        <td>${u.createdAt ? escapeHtml(u.createdAt) : ""}</td>
        <td>
          <form method="POST" onsubmit="return confirm('Delete ${escapeHtml(u.username)}?')">
            <input type="hidden" name="action" value="delete">
            <input type="hidden" name="username" value="${escapeHtml(u.username)}">
            <button type="submit" ${u.username === user.username ? "disabled" : ""}>Delete</button>
          </form>
        </td>
      </tr>`
      )
      .join("");

    const html = `<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Admin - Activation Board</title>
<style>
  body{font-family:-apple-system,sans-serif;max-width:720px;margin:40px auto;padding:0 16px;background:#0A0D13;color:#E8EAF0;}
  h1{font-size:20px;}
  table{width:100%;border-collapse:collapse;margin-top:20px;}
  th,td{padding:8px;border-bottom:1px solid #232A38;text-align:left;font-size:14px;}
  input{padding:8px;margin:4px 0;font-size:14px;border-radius:6px;border:1px solid #232A38;background:#171C27;color:#E8EAF0;}
  button{padding:8px 14px;font-size:13px;border-radius:6px;border:1px solid #232A38;background:#171C27;color:#E8EAF0;cursor:pointer;}
  button:hover{background:#1A2029;}
  form.add{background:#12161F;padding:16px;border-radius:10px;margin-top:16px;display:flex;flex-direction:column;gap:4px;max-width:320px;}
  label{font-size:13px;color:#8D96AC;}
</style></head>
<body>
<h1>User Management</h1>
<p>Logged in as <b>${escapeHtml(user.username)}</b></p>
<form class="add" method="POST">
  <input type="hidden" name="action" value="add">
  <label>Username</label>
  <input name="username" required autocomplete="off">
  <label>Password</label>
  <input name="password" type="password" required autocomplete="new-password">
  <label><input type="checkbox" name="isAdmin" style="width:auto"> Grant admin access</label>
  <button type="submit" style="margin-top:8px">Add user</button>
</form>
<table>
<thead><tr><th>Username</th><th>Admin</th><th>Created</th><th></th></tr></thead>
<tbody>${rows}</tbody>
</table>
</body></html>`;
    return new Response(html, { headers: { "content-type": "text/html; charset=utf-8" } });
  }

  if (!user) return unauthorized("Activation Board");
  return context.next();
};

export const config = { path: "/*" };
