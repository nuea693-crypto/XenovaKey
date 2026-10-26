import { getStore } from "@netlify/blobs";

const DAY = 864e5, ONLINE_MS = 90e3;
const store = () => getStore({ name: "xenova", consistency: "strong" });
const json = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { "content-type": "application/json" } });
const genKey = () => {
  const c = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const s = [...crypto.getRandomValues(new Uint8Array(12))].map(x => c[x % c.length]).join("");
  return `XENOVA-${s.slice(0, 4)}-${s.slice(4, 8)}-${s.slice(8)}`;
};
const clip = (v, n) => String(v ?? "").slice(0, n);

function check(r, hwid) {
  if (!r) return "ไม่พบคีย์นี้";
  if (r.banned) return "คีย์ถูกระงับ";
  if (r.expiresAt && Date.now() > r.expiresAt) return "คีย์หมดอายุแล้ว";
  if (!r.users[hwid] && Object.keys(r.users).length >= r.maxUses) return "คีย์เต็มโควตาผู้ใช้แล้ว";
  return null;
}

const LOADER = `
local Players=game:GetService("Players")
local HttpService=game:GetService("HttpService")
local lp=Players.LocalPlayer
local BASE="__BASE__"
local req=(syn and syn.request) or (http and http.request) or http_request or request
local function hwid()
  local ok,id=pcall(function() return game:GetService("RbxAnalyticsService"):GetClientId() end)
  return ok and id or "unknown"
end
local function info(k)
  return {key=k,hwid=hwid(),userId=lp.UserId,username=lp.Name,placeId=game.PlaceId,jobId=game.JobId}
end
local function call(path,body)
  local ok,res=pcall(function()
    local r=req({Url=BASE..path,Method="POST",Headers={["Content-Type"]="application/json"},Body=HttpService:JSONEncode(body)})
    return HttpService:JSONDecode(r.Body)
  end)
  if ok then return res end
  return {ok=false,msg="เชื่อมต่อเซิร์ฟเวอร์ไม่ได้"}
end
local function start(k)
  local res=call("/api/verify",info(k))
  if not res.ok then return false,res.msg end
  task.spawn(function()
    while true do
      task.wait(30)
      local h=call("/api/heartbeat",info(k))
      if h.ok==false and h.msg~="เชื่อมต่อเซิร์ฟเวอร์ไม่ได้" then warn("[Xenova] "..tostring(h.msg)) break end
    end
  end)
  local f,err=loadstring(res.script)
  if f then task.spawn(f) else warn(err) end
  return true
end
local preset=getgenv and getgenv().Key
if preset then
  local ok,msg=start(preset)
  if not ok then warn("[Xenova] "..tostring(msg)) end
  return
end
local gui=Instance.new("ScreenGui") gui.ResetOnSpawn=false
if not pcall(function() gui.Parent=game:GetService("CoreGui") end) then gui.Parent=lp:WaitForChild("PlayerGui") end
local f=Instance.new("Frame",gui) f.Size=UDim2.fromOffset(340,180) f.Position=UDim2.new(0.5,-170,0.5,-90)
f.BackgroundColor3=Color3.fromRGB(15,15,22) f.Active=true f.Draggable=true
Instance.new("UICorner",f).CornerRadius=UDim.new(0,12)
local t=Instance.new("TextLabel",f) t.Size=UDim2.new(1,0,0,40) t.BackgroundTransparency=1 t.Text="Xenova - Key System"
t.TextColor3=Color3.fromRGB(190,110,255) t.Font=Enum.Font.GothamBold t.TextSize=15
local box=Instance.new("TextBox",f) box.Size=UDim2.new(1,-40,0,36) box.Position=UDim2.new(0,20,0,48)
box.BackgroundColor3=Color3.fromRGB(25,25,35) box.TextColor3=Color3.new(1,1,1) box.PlaceholderText="XENOVA-XXXX-XXXX-XXXX"
box.Text="" box.Font=Enum.Font.Gotham box.TextSize=13 Instance.new("UICorner",box)
local b=Instance.new("TextButton",f) b.Size=UDim2.new(1,-40,0,36) b.Position=UDim2.new(0,20,0,94)
b.BackgroundColor3=Color3.fromRGB(110,40,230) b.TextColor3=Color3.new(1,1,1) b.Text="ตรวจสอบคีย์" b.Font=Enum.Font.GothamBold b.TextSize=13
Instance.new("UICorner",b)
local s=Instance.new("TextLabel",f) s.Size=UDim2.new(1,0,0,30) s.Position=UDim2.new(0,0,0,140) s.BackgroundTransparency=1
s.Text="" s.TextColor3=Color3.fromRGB(150,150,190) s.Font=Enum.Font.Gotham s.TextSize=12
b.MouseButton1Click:Connect(function()
  s.Text="กำลังตรวจสอบ..."
  local ok,msg=start(box.Text:upper():gsub("%s",""))
  if ok then gui:Destroy() else s.TextColor3=Color3.fromRGB(255,70,70) s.Text="❌ "..tostring(msg) end
end)
`;

export default async (req) => {
  const url = new URL(req.url);
  const path = url.pathname.replace(/^\/api/, "");
  const s = store();

  if (path === "/loader")
    return new Response(LOADER.replaceAll("__BASE__", url.origin), { headers: { "content-type": "text/plain; charset=utf-8" } });

  // ---------- Admin ----------
  if (path.startsWith("/admin/")) {
    const pw = process.env.ADMIN_PASSWORD;
    if (!pw || req.headers.get("x-admin-pass") !== pw) return json({ ok: false, msg: "unauthorized" }, 401);
    const b = req.method === "POST" ? await req.json().catch(() => ({})) : {};
    const kk = "k:" + clip(b.key, 40);

    if (path === "/admin/list") {
      const { blobs } = await s.list({ prefix: "k:" });
      const recs = (await Promise.all(blobs.map(x => s.get(x.key, { type: "json" })))).filter(Boolean);
      recs.forEach(r => { r.hasScript = !!r.script; delete r.script; });
      recs.sort((a, c) => c.createdAt - a.createdAt);
      return json({ ok: true, now: Date.now(), onlineMs: ONLINE_MS, keys: recs });
    }
    if (path === "/admin/create") {
      const script = String(b.script || "");
      if (!script.trim()) return json({ ok: false, msg: "ยังไม่ได้ใส่สคริปต์" });
      const count = Math.min(Math.max(parseInt(b.count) || 1, 1), 50);
      const out = [];
      for (let i = 0; i < count; i++) {
        const key = genKey();
        const rec = {
          key, name: clip(b.name, 60) || "Unnamed", script,
          maxUses: Math.min(Math.max(parseInt(b.maxUses) || 1, 1), 9999),
          durationDays: Math.max(parseInt(b.durationDays) || 0, 0),
          createdAt: Date.now(), activatedAt: null, expiresAt: null, banned: false, users: {},
        };
        await s.setJSON("k:" + key, rec);
        out.push(key);
      }
      return json({ ok: true, keys: out });
    }
    const r = await s.get(kk, { type: "json" });
    if (!r) return json({ ok: false, msg: "ไม่พบคีย์" });
    if (path === "/admin/delete") { await s.delete(kk); return json({ ok: true }); }
    if (path === "/admin/reset") { r.users = {}; }
    else if (path === "/admin/ban") { r.banned = !r.banned; }
    else if (path === "/admin/kick") { delete r.users[clip(b.hwid, 128)]; }
    else return json({ ok: false, msg: "unknown" }, 404);
    await s.setJSON(kk, r);
    return json({ ok: true });
  }

  // ---------- Script client ----------
  if (req.method !== "POST" || (path !== "/verify" && path !== "/heartbeat")) return json({ ok: false, msg: "not found" }, 404);
  const b = await req.json().catch(() => ({}));
  const key = "k:" + clip(b.key, 40).toUpperCase().trim();
  const hwid = clip(b.hwid, 128) || "unknown";
  const r = await s.get(key, { type: "json" });
  const err = check(r, hwid);
  if (err) return json({ ok: false, msg: err });

  const now = Date.now();
  if (!r.activatedAt) {
    r.activatedAt = now;
    r.expiresAt = r.durationDays ? now + r.durationDays * DAY : null;
  }
  const u = r.users[hwid] || { firstSeen: now };
  Object.assign(u, {
    username: clip(b.username, 40), userId: Number(b.userId) || 0,
    placeId: Number(b.placeId) || 0, jobId: clip(b.jobId, 60), lastSeen: now,
  });
  r.users[hwid] = u;
  await s.setJSON(key, r);
  return json({ ok: true, msg: "OK", expiresAt: r.expiresAt, ...(path === "/verify" ? { script: r.script } : {}) });
};

export const config = { path: "/api/*" };
