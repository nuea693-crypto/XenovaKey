import { getStore } from "@netlify/blobs";

const DAY = 864e5, ONLINE_MS = 90e3, SESSION_MS = 30 * DAY;
const OWNER_USERNAME = "nyvexhub"; // ชื่อผู้ใช้เจ้าของระบบ (เปลี่ยนได้ตามต้องการ)
const CUSTOMER_ACTIONS = new Set(["create_key", "delete_key", "ban_key", "unban_key", "reset_key", "tamper_detected", "announcement", "customer_reply"]);
const MAX_IMAGE_LEN = 400000; // ~300KB
const store = () => getStore({ name: "nvex", consistency: "strong" });
const json = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { "content-type": "application/json" } });
const clip = (v, n) => String(v ?? "").slice(0, n);
const safe = v => String(v).replace(/[^\w.:\/-]/g, "");
const hex = n => [...crypto.getRandomValues(new Uint8Array(n))].map(b => b.toString(16).padStart(2, "0")).join("");
const genKey = () => {
  const c = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const s = [...crypto.getRandomValues(new Uint8Array(12))].map(x => c[x % c.length]).join("");
  return `NVEX-${s.slice(0, 4)}-${s.slice(4, 8)}-${s.slice(8)}`;
};
async function hashPw(pw, salt) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(salt + ":" + pw));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
}

// ---------- IP helper ----------
function getIp(req) {
  return req.headers.get("x-nf-client-connection-ip")
    || (req.headers.get("x-forwarded-for") || "").split(",")[0].trim()
    || "unknown";
}

// ---------- Rate limiting / brute-force lockout (กันยิงเว็บ, กันบอท) ----------
async function rateLimit(s, bucket, ip, max, windowMs) {
  const key = "rl:" + bucket + ":" + safe(ip);
  const now = Date.now();
  const rec = await s.get(key, { type: "json" }).catch(() => null);
  if (!rec || now - rec.start > windowMs) { await s.setJSON(key, { start: now, count: 1 }); return true; }
  if (rec.count >= max) return false;
  rec.count++;
  await s.setJSON(key, rec);
  return true;
}
async function guardLock(s, bucket, ip) {
  const rec = await s.get("lock:" + bucket + ":" + safe(ip), { type: "json" }).catch(() => null);
  return !(rec && rec.until && Date.now() < rec.until);
}
async function guardFail(s, bucket, ip, maxFails, failWindowMs, lockMs, onLock) {
  const key = "lock:" + bucket + ":" + safe(ip);
  const now = Date.now();
  const rec = (await s.get(key, { type: "json" }).catch(() => null)) || { fails: 0, start: now };
  if (now - rec.start > failWindowMs) { rec.fails = 0; rec.start = now; }
  rec.fails++;
  if (rec.fails >= maxFails) { rec.until = now + lockMs; if (onLock) await onLock(); }
  await s.setJSON(key, rec);
}
async function guardReset(s, bucket, ip) { await s.delete("lock:" + bucket + ":" + safe(ip)).catch(() => {}); }

async function log(s, user, action, detail) {
  await s.setJSON("log:" + (1e15 - Date.now()) + ":" + hex(4), { t: Date.now(), user, action, detail: clip(detail, 200) });
}

// ---------- ตัวเข้ารหัสแบบใช้ซ้ำ (XOR + escape) ----------
function xorEnc(str, key) {
  const bytes = new TextEncoder().encode(str);
  let out = "";
  for (let i = 0; i < bytes.length; i++) out += "\\" + String(bytes[i] ^ key[i % key.length]).padStart(3, "0");
  return out;
}
function randKey(n = 12) { return [...crypto.getRandomValues(new Uint8Array(n))].map(b => 1 + (b % 254)); }
function wrapObfuscated(code) {
  const k = randKey();
  return `local function _d(s,k) local b=(bit32 or bit).bxor local o={} for i=1,#s do o[i]=string.char(b(s:byte(i),k[(i-1)%#k+1])) end return table.concat(o) end
local _k={${k.join(",")}}
local _f=loadstring(_d("${xorEnc(code, k)}",_k))
if _f then _f() end`;
}

function check(r, hwid) {
  if (!r) return "ไม่พบคีย์นี้";
  if (r.banned) return "คีย์ถูกระงับ";
  if (r.expiresAt && Date.now() > r.expiresAt) return "คีย์หมดอายุแล้ว";
  if (!r.users[hwid] && Object.keys(r.users).length >= r.maxUses) return "คีย์เต็มโควตาผู้ใช้แล้ว";
  return null;
}

async function auth(req, s) {
  const token = req.headers.get("x-session-token");
  if (!token) return null;
  const sess = await s.get("sess:" + safe(clip(token, 80)), { type: "json" });
  if (!sess || sess.exp < Date.now()) return null;
  return sess;
}

// ---------- Loader (ตัวโหลดฝั่งลูกค้า) ----------
const LOADER = `
local Players=game:GetService("Players")
local HttpService=game:GetService("HttpService")
local CoreGui=game:GetService("CoreGui")
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
local function showBanner(text,soundId,allowReply,k,h)
  pcall(function()
    local sg=Instance.new("ScreenGui") sg.Name="NVEX_Announce" sg.ResetOnSpawn=false
    pcall(function() sg.Parent=CoreGui end) if not sg.Parent then sg.Parent=lp:WaitForChild("PlayerGui") end
    local card=Instance.new("Frame",sg)
    card.Size=UDim2.new(0,380,0,allowReply and 112 or 72)
    card.Position=UDim2.new(0.5,-190,0,-160)
    card.BackgroundColor3=Color3.fromRGB(20,16,35) card.BorderSizePixel=0
    Instance.new("UICorner",card).CornerRadius=UDim.new(0,16)
    local grad=Instance.new("UIGradient",card)
    grad.Color=ColorSequence.new({ColorSequenceKeypoint.new(0,Color3.fromRGB(130,45,255)),ColorSequenceKeypoint.new(1,Color3.fromRGB(255,60,170))})
    grad.Rotation=45 grad.Transparency=NumberSequence.new({NumberSequenceKeypoint.new(0,0.82),NumberSequenceKeypoint.new(1,0.82)})
    local stroke=Instance.new("UIStroke",card) stroke.Color=Color3.new(1,1,1) stroke.Transparency=0.7 stroke.Thickness=1.5
    local icon=Instance.new("TextLabel",card) icon.Size=UDim2.new(0,40,0,40) icon.Position=UDim2.new(0,14,0,14)
    icon.BackgroundTransparency=1 icon.Text="📢" icon.TextSize=28
    local title=Instance.new("TextLabel",card) title.Size=UDim2.new(1,-70,0,20) title.Position=UDim2.new(0,64,0,10)
    title.BackgroundTransparency=1 title.TextXAlignment=Enum.TextXAlignment.Left title.Text="ประกาศจากแอดมิน NVEX"
    title.TextColor3=Color3.new(1,1,1) title.Font=Enum.Font.GothamBold title.TextSize=14
    local msg=Instance.new("TextLabel",card) msg.Size=UDim2.new(1,-80,0,26) msg.Position=UDim2.new(0,64,0,32)
    msg.BackgroundTransparency=1 msg.TextXAlignment=Enum.TextXAlignment.Left msg.TextWrapped=true
    msg.Text=tostring(text) msg.TextColor3=Color3.fromRGB(230,225,255) msg.Font=Enum.Font.Gotham msg.TextSize=13
    if soundId and soundId~="" then
      pcall(function() local snd=Instance.new("Sound",card) snd.SoundId="rbxassetid://"..tostring(soundId) snd.Volume=3 snd:Play() snd.Ended:Connect(function() snd:Destroy() end) end)
    end
    if allowReply then
      local rb=Instance.new("TextBox",card) rb.Size=UDim2.new(1,-80,0,28) rb.Position=UDim2.new(0,64,0,68)
      rb.BackgroundColor3=Color3.fromRGB(10,8,20) rb.TextColor3=Color3.new(1,1,1) rb.PlaceholderText="พิมพ์ตอบกลับแล้วกด Enter..."
      rb.Font=Enum.Font.Gotham rb.TextSize=12 Instance.new("UICorner",rb).CornerRadius=UDim.new(0,8)
      rb.FocusLost:Connect(function(enter)
        if enter and rb.Text~="" then
          call("/api/announce-reply",{key=k,hwid=h,username=lp.Name,text=rb.Text})
          rb.Text="✅ ส่งแล้ว" task.wait(1) pcall(function() rb.Text="" end)
        end
      end)
    end
    card:TweenPosition(UDim2.new(0.5,-190,0,20),"Out","Back",0.6,true)
    task.wait(allowReply and 14 or 8)
    card:TweenPosition(UDim2.new(0.5,-190,0,-160),"In","Quad",0.5,true)
    task.wait(0.6) sg:Destroy()
  end)
end
local function showOwnerJoined(owner)
  pcall(function()
    local sg=Instance.new("ScreenGui") sg.Name="NVEX_OwnerJoin" sg.ResetOnSpawn=false
    pcall(function() sg.Parent=game:GetService("CoreGui") end)
    if not sg.Parent then sg.Parent=game:GetService("Players").LocalPlayer:WaitForChild("PlayerGui") end
    local card=Instance.new("Frame",sg)
    card.Size=UDim2.new(0,300,0,60) card.Position=UDim2.new(1,-320,1,-80)
    card.BackgroundColor3=Color3.fromRGB(10,8,18) card.BorderSizePixel=0
    Instance.new("UICorner",card).CornerRadius=UDim.new(0,10)
    local stroke=Instance.new("UIStroke",card) stroke.Color=Color3.fromRGB(220,38,38) stroke.Thickness=1.5 stroke.Transparency=0.3
    local icon=Instance.new("TextLabel",card) icon.Size=UDim2.new(0,40,1,0) icon.BackgroundTransparency=1
    icon.Text="👁️" icon.TextSize=22
    local msg=Instance.new("TextLabel",card) msg.Size=UDim2.new(1,-50,1,0) msg.Position=UDim2.new(0,44,0,0)
    msg.BackgroundTransparency=1 msg.TextXAlignment=Enum.TextXAlignment.Left msg.TextWrapped=true
    msg.Text="⚔️ "..tostring(owner).." เข้าสู่เซิร์ฟเวอร์แล้ว" msg.TextColor3=Color3.fromRGB(252,165,165)
    msg.Font=Enum.Font.GothamBold msg.TextSize=12
    card:TweenPosition(UDim2.new(1,-320,1,-80),"Out","Back",0.5,true)
    task.wait(5) card:TweenPosition(UDim2.new(1,20,1,-80),"In","Quad",0.4,true)
    task.wait(0.5) sg:Destroy()
  end)
end
local function pollAnnounce(k,h)
  task.spawn(function()
    while true do
      task.wait(6)
      local res=call("/api/poll-commands",{key=k,hwid=h})
      if res and res.ok and res.commands then
        for _,c in ipairs(res.commands) do
          if c.type=="announcement" then showBanner(c.text,c.soundId,c.allowReply,k,h)
          elseif c.type=="owner_joined" then showOwnerJoined(c.owner) end
        end
      end
    end
  end)
end
local function start(k)
  local res=call("/api/verify",info(k))
  if not res.ok then return false,res.msg end
  task.spawn(function()
    while true do
      task.wait(30)
      local h=call("/api/heartbeat",info(k))
      if h.ok==false and h.msg~="เชื่อมต่อเซิร์ฟเวอร์ไม่ได้" then warn("[NVEX] "..tostring(h.msg)) break end
    end
  end)
  pollAnnounce(k,hwid())
  local f,err=loadstring(res.script)
  if f then task.spawn(f) else warn(err) end
  return true
end
local preset=getgenv and getgenv().Key
if preset then
  local ok,msg=start(preset)
  if not ok then warn("[NVEX] "..tostring(msg)) end
  return
end
local gui=Instance.new("ScreenGui") gui.ResetOnSpawn=false
if not pcall(function() gui.Parent=CoreGui end) then gui.Parent=lp:WaitForChild("PlayerGui") end
local f=Instance.new("Frame",gui) f.Size=UDim2.fromOffset(340,180) f.Position=UDim2.new(0.5,-170,0.5,-90)
f.BackgroundColor3=Color3.fromRGB(15,15,22) f.Active=true f.Draggable=true
Instance.new("UICorner",f).CornerRadius=UDim.new(0,12)
local t=Instance.new("TextLabel",f) t.Size=UDim2.new(1,0,0,40) t.BackgroundTransparency=1 t.Text="NVEX Loader"
t.TextColor3=Color3.fromRGB(190,110,255) t.Font=Enum.Font.GothamBold t.TextSize=15
local box=Instance.new("TextBox",f) box.Size=UDim2.new(1,-40,0,36) box.Position=UDim2.new(0,20,0,48)
box.BackgroundColor3=Color3.fromRGB(25,25,35) box.TextColor3=Color3.new(1,1,1) box.PlaceholderText="NVEX-XXXX-XXXX-XXXX"
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
  const ip = getIp(req);

  // ---------- ขอ loader (obfuscated เต็มรูปแบบ กันเปิดดูตรงๆ) ----------
  if (path === "/loader") {
    if (!(await rateLimit(s, "loader", ip, 20, 60000))) return json({ ok: false, msg: "too many requests" }, 429);
    const code = LOADER.replaceAll("__BASE__", url.origin);
    return new Response(wrapObfuscated(code), { headers: { "content-type": "text/plain; charset=utf-8" } });
  }

  // ---------- Auth (บัญชีผู้ใช้เว็บ) ----------
  if (path === "/auth/login" && req.method === "POST") {
    if (!(await guardLock(s, "login", ip))) return json({ ok: false, msg: "ลองรหัสผิดหลายครั้งเกินไป ลองใหม่อีก 10 นาที" }, 429);
    const b = await req.json().catch(() => ({}));
    const username = safe(clip(b.username, 40)).toLowerCase();
    const password = clip(b.password, 100);
    if (!username || !password) return json({ ok: false, msg: "กรอกให้ครบ" });
    const uk = "u:" + username;
    let rec = await s.get(uk, { type: "json" });
    if (!rec) {
      const pw = process.env.ADMIN_PASSWORD;
      if (username === OWNER_USERNAME && pw && password === pw) {
        const salt = hex(8);
        rec = { username: OWNER_USERNAME, role: "owner", salt, passHash: await hashPw(password, salt), createdAt: Date.now(), createdBy: "system" };
        await s.setJSON(uk, rec);
      } else {
        await guardFail(s, "login", ip, 8, 5 * 60000, 10 * 60000, () => log(s, "system", "bot_blocked", `login brute-force จาก IP ${ip}`));
        return json({ ok: false, msg: "ไม่พบผู้ใช้นี้ หรือรหัสผ่านไม่ถูกต้อง" });
      }
    } else {
      const h = await hashPw(password, rec.salt);
      if (h !== rec.passHash) {
        await guardFail(s, "login", ip, 8, 5 * 60000, 10 * 60000, () => log(s, "system", "bot_blocked", `login brute-force จาก IP ${ip}`));
        return json({ ok: false, msg: "ไม่พบผู้ใช้นี้ หรือรหัสผ่านไม่ถูกต้อง" });
      }
    }
    await guardReset(s, "login", ip);
    const token = hex(24);
    await s.setJSON("sess:" + token, { username: rec.username, role: rec.role, exp: Date.now() + SESSION_MS });
    await log(s, rec.username, "login", "");
    return json({ ok: true, token, username: rec.username, role: rec.role });
  }
  if (path === "/auth/logout" && req.method === "POST") {
    const b = await req.json().catch(() => ({}));
    if (b.token) await s.delete("sess:" + safe(clip(b.token, 80)));
    return json({ ok: true });
  }

  // ---------- Admin (ต้องล็อกอินแล้ว) ----------
  if (path.startsWith("/admin/")) {
    const sess = await auth(req, s);
    if (!sess) return json({ ok: false, msg: "unauthorized" }, 401);
    const b = req.method === "POST" ? await req.json().catch(() => ({})) : {};
    const kk = "k:" + clip(b.key, 40);
    const isOwner = sess.role === "owner";

    if (path === "/admin/users/list") {
      if (!isOwner) return json({ ok: false, msg: "เฉพาะเจ้าของระบบ" }, 403);
      const { blobs } = await s.list({ prefix: "u:" });
      const recs = (await Promise.all(blobs.map(x => s.get(x.key, { type: "json" })))).filter(Boolean);
      return json({ ok: true, users: recs.map(r => ({ username: r.username, role: r.role, createdAt: r.createdAt })) });
    }
    if (path === "/admin/users/create") {
      if (!isOwner) return json({ ok: false, msg: "เฉพาะเจ้าของระบบ" }, 403);
      const username = safe(clip(b.username, 40)).toLowerCase();
      const password = clip(b.password, 100);
      if (!username || password.length < 4) return json({ ok: false, msg: "ตั้งชื่อผู้ใช้ และรหัสผ่านอย่างน้อย 4 ตัว" });
      if (username === OWNER_USERNAME) return json({ ok: false, msg: "ชื่อนี้ถูกใช้แล้ว" });
      const uk = "u:" + username;
      if (await s.get(uk, { type: "json" })) return json({ ok: false, msg: "มีชื่อผู้ใช้นี้แล้ว" });
      const salt = hex(8);
      await s.setJSON(uk, { username, role: "admin", salt, passHash: await hashPw(password, salt), createdAt: Date.now(), createdBy: sess.username });
      await log(s, sess.username, "create_user", username);
      return json({ ok: true });
    }
    if (path === "/admin/users/delete") {
      if (!isOwner) return json({ ok: false, msg: "เฉพาะเจ้าของระบบ" }, 403);
      const username = safe(clip(b.username, 40)).toLowerCase();
      if (username === OWNER_USERNAME) return json({ ok: false, msg: "ลบเจ้าของระบบไม่ได้" });
      await s.delete("u:" + username);
      await log(s, sess.username, "delete_user", username);
      return json({ ok: true });
    }

    if (path === "/admin/logs" || path === "/admin/audit") {
      const isFullAudit = path === "/admin/audit";
      if (isFullAudit && !isOwner) return json({ ok: false, msg: "เฉพาะเจ้าของระบบ" }, 403);
      const { blobs } = await s.list({ prefix: "log:", limit: 200 });
      let recs = (await Promise.all(blobs.slice(0, 200).map(x => s.get(x.key, { type: "json" })))).filter(Boolean);
      if (!isFullAudit) recs = recs.filter(r => CUSTOMER_ACTIONS.has(r.action));
      recs.sort((a, c) => c.t - a.t);
      return json({ ok: true, logs: recs.slice(0, 150) });
    }

    if (path === "/admin/chat/list") {
      const { blobs } = await s.list({ prefix: "chat:", limit: 80 });
      const recs = (await Promise.all(blobs.slice(-80).map(x => s.get(x.key, { type: "json" })))).filter(Boolean);
      recs.sort((a, c) => a.t - c.t);
      for (const m of recs) {
        if (m.user !== sess.username && !(m.readBy || []).includes(sess.username)) {
          m.readBy = [...(m.readBy || []), sess.username];
          await s.setJSON("chat:" + m.id, m).catch(() => {});
        }
      }
      return json({ ok: true, messages: recs });
    }
    if (path === "/admin/chat/send") {
      const text = clip(b.text, 500);
      const image = typeof b.image === "string" && b.image.startsWith("data:image/") ? b.image : null;
      if (!text.trim() && !image) return json({ ok: false, msg: "พิมพ์ข้อความหรือแนบรูปก่อน" });
      if (image && image.length > MAX_IMAGE_LEN) return json({ ok: false, msg: "รูปใหญ่เกินไป (ไม่เกิน ~300KB)" });
      const id = (1e15 - Date.now()) + ":" + hex(4);
      await s.setJSON("chat:" + id, { id, t: Date.now(), user: sess.username, text, image, readBy: [sess.username] });
      return json({ ok: true });
    }

    if (path === "/admin/list") {
      const { blobs } = await s.list({ prefix: "k:" });
      const recs = (await Promise.all(blobs.map(x => s.get(x.key, { type: "json" })))).filter(Boolean);
      recs.forEach(r => { r.hasScript = !!r.script; delete r.script; });
      // ส่วนตัว = เฉพาะผู้สร้าง, ส่วนรวม (room) = ทุกคนเห็น, owner เห็นทั้งหมด
      const filtered = isOwner ? recs : recs.filter(r => r.createdBy === sess.username || !!r.room);
      filtered.sort((a, c) => c.createdAt - a.createdAt);
      return json({ ok: true, now: Date.now(), onlineMs: ONLINE_MS, keys: filtered, me: { username: sess.username, role: sess.role } });
    }
    if (path === "/admin/create") {
      const script = String(b.script || "");
      if (!script.trim()) return json({ ok: false, msg: "ยังไม่ได้ใส่สคริปต์" });
      const count = Math.min(Math.max(parseInt(b.count) || 1, 1), 50);
      const out = [];
      for (let i = 0; i < count; i++) {
        const key = genKey();
        const rec = {
          key, name: clip(b.name, 60) || "NVEX Project", script,
          maxUses: Math.min(Math.max(parseInt(b.maxUses) || 1, 1), 9999),
          durationDays: Math.max(parseInt(b.durationDays) || 0, 0),
          createdAt: Date.now(), activatedAt: null, expiresAt: null, banned: false, users: {},
          createdBy: sess.username, tamper: [], commands: [], room: !!b.room,
        };
        await s.setJSON("k:" + key, rec);
        out.push(key);
      }
      await log(s, sess.username, "create_key", `${count} key(s)${b.room ? " [ห้องแชท]" : ""}: ${clip(b.name, 60)}`);
      return json({ ok: true, keys: out });
    }
    if (path === "/admin/announce-one") {
      const text = clip(b.text, 200) || "👋 ทีมงาน NVEX เข้ามาที่เซิร์ฟเวอร์นี้แล้ว";
      const r1 = await s.get(kk, { type: "json" });
      if (!r1) return json({ ok: false, msg: "ไม่พบคีย์" });
      r1.commands = [...(r1.commands || []), { type: "announcement", text, soundId: "", allowReply: false }].slice(-10);
      await s.setJSON(kk, r1);
      return json({ ok: true });
    }
    if (path === "/admin/notify-key") {
      // ส่งแจ้งเตือน "เจ้าของเข้ามาแล้ว" ไปยังคีย์นั้นโดยตรง
      const r = await s.get(kk, { type: "json" });
      if (!r) return json({ ok: false, msg: "ไม่พบคีย์" });
      r.commands = [...(r.commands || []), { type: "owner_joined", owner: sess.username }].slice(-10);
      await s.setJSON(kk, r);
      return json({ ok: true });
    }
    if (path === "/admin/announce") {
      const text = clip(b.text, 200);
      if (!text.trim()) return json({ ok: false, msg: "พิมพ์ข้อความก่อน" });
      const soundId = b.sound ? clip(String(b.sound).replace(/\D/g, ""), 30) : "";
      const allowReply = !!b.allowReply;
      const { blobs } = await s.list({ prefix: "k:" });
      for (const blob of blobs) {
        const kRec = await s.get(blob.key, { type: "json" });
        if (kRec && !kRec.banned) {
          kRec.commands = [...(kRec.commands || []), { type: "announcement", text, soundId, allowReply }].slice(-10);
          await s.setJSON(blob.key, kRec);
        }
      }
      await log(s, sess.username, "announcement", text);
      return json({ ok: true });
    }
    const r = await s.get(kk, { type: "json" });
    if (!r) return json({ ok: false, msg: "ไม่พบคีย์" });
    if (path === "/admin/delete") { await s.delete(kk); await log(s, sess.username, "delete_key", r.key); return json({ ok: true }); }
    if (path === "/admin/reset") { r.users = {}; await log(s, sess.username, "reset_key", r.key); }
    else if (path === "/admin/ban") { r.banned = !r.banned; await log(s, sess.username, r.banned ? "ban_key" : "unban_key", r.key); }
    else if (path === "/admin/kick") { delete r.users[clip(b.hwid, 128)]; }
    else return json({ ok: false, msg: "unknown" }, 404);
    await s.setJSON(kk, r);
    return json({ ok: true });
  }

  // ---------- กับดักตรวจจับการแกะสคริปต์ ----------
  if (path === "/trap" && req.method === "POST") {
    if (!(await rateLimit(s, "trap", ip, 20, 60000))) return json({ ok: false }, 429);
    const tb = await req.json().catch(() => ({}));
    const tk = "k:" + clip(tb.key, 40).toUpperCase().trim();
    const tr = await s.get(tk, { type: "json" });
    if (tr) {
      tr.tamper = [...(tr.tamper || []), { t: Date.now(), hwid: clip(tb.hwid, 128), username: clip(tb.username, 40), reason: clip(tb.reason, 40) }].slice(-20);
      tr.banned = true;
      await s.setJSON(tk, tr);
      await log(s, "system", "tamper_detected", `${tr.key} by ${clip(tb.username, 40)}`);
    }
    return json({ ok: true });
  }

  // ---------- ลูกค้าตอบกลับประกาศ ----------
  if (path === "/announce-reply" && req.method === "POST") {
    if (!(await rateLimit(s, "reply", ip, 10, 60000))) return json({ ok: false }, 429);
    const rb = await req.json().catch(() => ({}));
    const text = clip(rb.text, 300);
    if (text.trim()) await log(s, clip(rb.username, 40) || "ลูกค้า", "customer_reply", text);
    return json({ ok: true });
  }

  // ---------- ดึงประกาศ (ฝั่งลูกค้า) ----------
  if (path === "/poll-commands" && req.method === "POST") {
    if (!(await rateLimit(s, "poll", ip, 40, 60000))) return json({ ok: false, msg: "too many requests" }, 429);
    const b = await req.json().catch(() => ({}));
    const kk = "k:" + clip(b.key, 40).toUpperCase().trim();
    const r = await s.get(kk, { type: "json" });
    if (r && r.commands && r.commands.length) {
      const cmds = [...r.commands];
      r.commands = [];
      await s.setJSON(kk, r);
      return json({ ok: true, commands: cmds });
    }
    return json({ ok: true, commands: [] });
  }

  // ---------- ฝั่งสคริปต์ลูกค้า (verify/heartbeat) ----------
  if (req.method !== "POST" || (path !== "/verify" && path !== "/heartbeat")) return json({ ok: false, msg: "not found" }, 404);

  if (!(await rateLimit(s, "vh", ip, 60, 60000))) return json({ ok: false, msg: "too many requests" }, 429);
  if (path === "/verify" && !(await guardLock(s, "keyfail", ip)))
    return json({ ok: false, msg: "ตรวจพบความพยายามเดาคีย์ผิดปกติ ถูกบล็อกชั่วคราว" }, 429);

  const b = await req.json().catch(() => ({}));
  const key = "k:" + clip(b.key, 40).toUpperCase().trim();
  const hwid = clip(b.hwid, 128) || "unknown";
  const r = await s.get(key, { type: "json" });
  const err = check(r, hwid);
  if (err) {
    // คีย์ไม่พบ/ผิด ถือเป็นสัญญาณของการเดาคีย์ (บอท) เฉพาะตอน verify
    if (path === "/verify" && err === "ไม่พบคีย์นี้") {
      await guardFail(s, "keyfail", ip, 15, 5 * 60000, 15 * 60000, () => log(s, "system", "bot_blocked", `เดาคีย์รัว ๆ จาก IP ${ip}`));
    }
    return json({ ok: false, msg: err });
  }
  if (path === "/verify") await guardReset(s, "keyfail", ip);

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
  const payload = { ok: true, msg: "OK", expiresAt: r.expiresAt };
  if (path === "/verify") {
    const tag = `local __X={k="${safe(key.slice(2))}",h="${safe(hwid)}",b="${url.origin}"}\n`;
    payload.script = tag + r.script;
  }
  return json(payload);
};

export const config = { path: "/api/*" };
