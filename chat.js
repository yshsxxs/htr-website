/* 小姚聊天 YaoChat v2.0 — 端到端加密 IM (无服务器: MQTT 通道 + Web Crypto)
 * 账号: PBKDF2 密码 → 加密私钥存本地; 公钥上传用户目录
 * 私聊: ECDH 协商 AES-256-GCM; 群聊: 群口令派生 AES-256-GCM
 * 文件: 加密后 base64 分片传输 (≤5MB)
 */
(function () {
  "use strict";
  var TOPIC = "yaochat/v2/";
  var MAX_FILE = 5 * 1024 * 1024;
  var CHUNK = 45000;

  var S = {
    acc: null,          // {u, nick, salt, hash, iter, privWrapped, pub}
    priv: null,         // 解包后的私钥 JWK
    me: null, nick: null,
    dir: {},            // 用户目录 {u: {nick, pub}}
    friends: [],        // [{u, nick, pub}]
    groups: [],         // [{gid, name, pass}]
    msgs: {},           // {chatKey: [msg]}
    keys: {},           // 运行时密钥缓存 {pm:xx|grp:xx: CryptoKey}
    fileRx: {},         // 接收中的文件 {fid: {meta, parts:[]}}
    cur: null           // 当前打开的聊天 {kind:'pm'|'grp', id, name}
  };
  var client = null, unread = 0;

  /* ================= 工具 ================= */
  function $(id) { return document.getElementById(id); }
  function esc(s) { return String(s == null ? "" : s).replace(/[<>&"]/g, function (c) {
    return { "<": "&lt;", ">": "&gt;", "&": "&amp;", '"': "&quot;" }[c]; }); }
  function ts() { return Date.now(); }
  function fmt(t) {
    var d = new Date(t);
    return ("0" + d.getHours()).slice(-2) + ":" + ("0" + d.getMinutes()).slice(-2);
  }
  function bytes(n) {
    if (n < 1024) return n + " B";
    if (n < 1048576) return (n / 1024).toFixed(1) + " KB";
    return (n / 1048576).toFixed(2) + " MB";
  }
  function save() {
    localStorage.setItem("yao_chat_v2", JSON.stringify({
      acc: S.acc, friends: S.friends, groups: S.groups, msgs: S.msgs
    }));
  }
  function load() {
    try {
      var d = JSON.parse(localStorage.getItem("yao_chat_v2") || "{}");
      S.acc = d.acc || null; S.friends = d.friends || [];
      S.groups = d.groups || []; S.msgs = d.msgs || {};
    } catch (e) {}
  }
  function lastMsg(k) { var a = S.msgs[k] || []; return a.length ? a[a.length - 1] : null; }
  function push(k, m) {
    if (!S.msgs[k]) S.msgs[k] = [];
    S.msgs[k].push(m);
    if (S.msgs[k].length > 500) S.msgs[k] = S.msgs[k].slice(-500);
    save();
  }
  function chatKey(kind, id) { return kind + ":" + id; }

  /* ================= 注册 / 登录 ================= */
  async function doRegister() {
    var u = $("au-user").value.trim().toLowerCase();
    var p = $("au-pass").value;
    var nick = $("au-nick").value.trim() || u;
    if (!/^[a-z0-9_]{3,16}$/.test(u)) { err("用户名需 3-16 位英文/数字/下划线"); return; }
    if (p.length < 6) { err("密码至少 6 位"); return; }
    err("");
    btnWait(true, "正在生成密钥…");
    try {
      var h = await YaoCrypto.hashPassword(p);
      var kp = await YaoCrypto.genKeyPair();
      var wrapped = await YaoCrypto.wrapPrivateKey(kp.priv, p, h.salt);
      S.acc = { u: u, nick: nick, salt: h.salt, hash: h.hash, iter: h.iter, privWrapped: wrapped, pub: kp.pub };
      S.priv = kp.priv;
      save();
      afterAuth("注册成功！正在上线…");
    } catch (e) { err("注册失败: " + e.message); btnWait(false); }
  }

  async function doLogin() {
    var u = $("au-user").value.trim().toLowerCase();
    var p = $("au-pass").value;
    if (!S.acc || S.acc.u !== u) { err("本机没有这个账号（请先注册，或用「导入账号」）"); return; }
    err("");
    btnWait(true, "正在验证…");
    try {
      var ok = await YaoCrypto.verifyPassword(p, S.acc.hash, S.acc.salt, S.acc.iter);
      if (!ok) { err("密码错误"); btnWait(false); return; }
      var priv = await YaoCrypto.unwrapPrivateKey(S.acc.privWrapped, p, S.acc.salt);
      if (!priv) { err("私钥解包失败（密码可能已变）"); btnWait(false); return; }
      S.priv = priv;
      afterAuth("登录成功！正在上线…");
    } catch (e) { err("登录失败: " + e.message); btnWait(false); }
  }

  function afterAuth(msg) {
    S.me = S.acc.u; S.nick = S.acc.nick;
    $("auth").classList.add("hide");
    $("app").classList.remove("hide");
    $("meName").textContent = S.nick + " (@" + S.me + ")";
    ok(msg);
    connect();
    renderAll();
  }

  function err(t) { $("authErr").textContent = t; }
  function ok(t) { var e = $("authOk"); e.textContent = t || ""; }
  function btnWait(b, t) {
    var btn = $("authBtn");
    btn.disabled = !!b;
    btn.textContent = b ? (t || "请稍候…") : ($("authTitle").textContent === "登录" ? "登 录" : "注 册");
  }

  /* ================= MQTT (多服务器自动故障切换) ================= */
  var BROKERS = [
    "wss://broker.emqx.io:8084/mqtt",
    "wss://broker.hivemq.com:8884/mqtt",
    "wss://test.mosquitto.org:8081/mqtt"
  ];
  var bIdx = 0, everConnected = false;

  function connect() {
    if (typeof mqtt === "undefined") { ok("通信库未加载，请检查网络后刷新"); return; }
    if (client) { try { client.end(true); } catch (e) {} }
    var url = BROKERS[bIdx % BROKERS.length];
    everConnected = false;
    client = mqtt.connect(url, {
      clientId: "yaochat_" + S.me + "_" + Math.floor(Math.random() * 999999),
      keepalive: 30, reconnectPeriod: 0, connectTimeout: 9000, clean: true
    });
    var switched = false;
    function trySwitch() {
      if (switched || everConnected) return;
      switched = true;
      bIdx++;
      ok("正在切换通信服务器 (" + ((bIdx % BROKERS.length) + 1) + "/" + BROKERS.length + ")…");
      try { client.end(true); } catch (e) {}
      setTimeout(connect, 400);
    }
    var to = setTimeout(function () { if (!everConnected) trySwitch(); }, 10000);
    client.on("connect", function () {
      everConnected = true;
      clearTimeout(to);
      ok("已上线 · " + url.replace(/^wss?:\/\//, "").split("/")[0]);
      pub(TOPIC + "users/" + S.me, { u: S.me, nick: S.nick, pub: S.acc.pub }, true);
      client.subscribe(TOPIC + "users/#", { qos: 1 });
      client.subscribe(TOPIC + "pm/" + S.me + "/#", { qos: 1 });
      client.subscribe(TOPIC + "file/" + S.me + "/#", { qos: 1 });
      S.groups.forEach(function (g) { client.subscribe(TOPIC + "grp/" + g.gid, { qos: 1 }); });
    });
    client.on("message", function (t, p) {
      var d;
      try { d = JSON.parse(p.toString()); } catch (e) { return; }
      handle(t, d);
    });
    client.on("error", function () { if (!everConnected) trySwitch(); else ok("通信异常，自动重连中…"); });
    client.on("close", function () {
      if (!everConnected) { trySwitch(); }
      else { ok("已断开，重连中…"); try { client.reconnect(); } catch (e) {} }
    });
  }
  function pub(t, obj, retain) {
    if (client && client.connected) {
      client.publish(t, JSON.stringify(obj), { qos: 1, retain: !!retain });
    }
  }

  async function handle(t, d) {
    // 用户目录
    if (t.indexOf(TOPIC + "users/") === 0) {
      if (d.u && d.pub) {
        S.dir[d.u] = { nick: d.nick || d.u, pub: d.pub };
        var f = S.friends.filter(function (x) { return x.u === d.u; })[0];
        if (f) { f.nick = d.nick || f.nick; f.pub = d.pub; save(); renderContacts(); }
      }
      return;
    }
    // 私聊消息
    var m = t.match(new RegExp("^" + TOPIC + "pm/" + S.me + "/([^/]+)$"));
    if (m) { await onPm(m[1], d); return; }
    // 群消息
    var g = t.match(new RegExp("^" + TOPIC + "grp/([^/]+)$"));
    if (g) { await onGroup(g[1], d); return; }
    // 文件
    var f2 = t.match(new RegExp("^" + TOPIC + "file/" + S.me + "/([^/]+)$"));
    if (f2) { await onFile(f2[1], d); return; }
  }

  /* ================= 密钥 ================= */
  async function pmKey(peer) {
    var k = "pm:" + peer;
    if (S.keys[k]) return S.keys[k];
    var f = S.friends.filter(function (x) { return x.u === peer; })[0];
    var pub = f ? f.pub : (S.dir[peer] ? S.dir[peer].pub : null);
    if (!pub) return null;
    try {
      var key = await YaoCrypto.sharedKey(S.priv, pub);
      S.keys[k] = key;
      return key;
    } catch (e) { return null; }
  }
  async function grpKey(gid) {
    var k = "grp:" + gid;
    if (S.keys[k]) return S.keys[k];
    var g = S.groups.filter(function (x) { return x.gid === gid; })[0];
    if (!g) return null;
    var key = await YaoCrypto.groupKey(g.pass, gid);
    S.keys[k] = key;
    return key;
  }

  /* ================= 私聊 ================= */
  async function onPm(peer, d) {
    var key = await pmKey(peer);
    if (!key) { addSys("pm:" + peer, "收到来自 @" + peer + " 的消息（缺少对方公钥，请添加好友）"); return; }
    if (d.t === "msg") {
      var txt = await YaoCrypto.decrypt(key, d.text);
      addMsg("pm:" + peer, {
        me: false, who: d.nick || peer, text: txt === null ? "【无法解密：密钥不匹配】" : txt,
        ts: d.ts || ts(), enc: txt !== null
      });
    } else if (d.t === "file") {
      await recvFile('pm', peer, key, d, peer);
    }
    bump("pm:" + peer);
  }

  async function sendPm(text) {
    var peer = S.cur.id, key = await pmKey(peer);
    if (!key) { alert("缺少对方公钥，请先在「联系人」里添加该好友"); return; }
    var ct = await YaoCrypto.encrypt(key, text);
    pub(TOPIC + "pm/" + peer + "/" + S.me,
        { t: "msg", text: ct, me: S.me, nick: S.nick, ts: ts() });
    addMsg("pm:" + peer, { me: true, who: S.nick, text: text, ts: ts(), enc: true });
  }

  /* ================= 群聊 ================= */
  async function onGroup(gid, d) {
    var key = await grpKey(gid);
    if (!key) return;
    var k = "grp:" + gid;
    if (d.t === "msg") {
      if (d.me === S.me) return;            // 自己发的不重复显示
      var txt = await YaoCrypto.decrypt(key, d.text);
      addMsg(k, { me: false, who: d.nick || d.me, text: txt === null ? "【无法解密：群口令不一致】" : txt, ts: d.ts || ts() });
    } else if (d.t === "file") {
      await recvFile('grp', gid, key, d, d.me);
    }
    bump(k);
  }

  async function sendGroup(text) {
    var gid = S.cur.id, key = await grpKey(gid);
    if (!key) { alert("群密钥缺失"); return; }
    var ct = await YaoCrypto.encrypt(key, text);
    pub(TOPIC + "grp/" + gid, { t: "msg", text: ct, me: S.me, nick: S.nick, ts: ts() });
    addMsg("grp:" + gid, { me: true, who: S.nick, text: text, ts: ts() });
  }

  /* ================= 文件 ================= */
  async function sendFile(file) {
    if (file.size > MAX_FILE) {
      alert("文件太大（上限 5MB）\n\n大文件建议：上传到网盘/GitHub 后发链接。");
      return;
    }
    var key = S.cur.kind === "pm" ? await pmKey(S.cur.id) : await grpKey(S.cur.id);
    if (!key) { alert("缺少密钥，无法加密发送"); return; }
    var buf = new Uint8Array(await file.arrayBuffer());
    var enc = await YaoCrypto.encryptBytes(key, buf);
    var b64 = YaoCrypto.b64enc(enc);
    var parts = YaoCrypto.chunkB64(b64, CHUNK);
    var fid = YaoCrypto.randHex(6);
    var meta = {
      t: "file", fid: fid, name: file.name, size: file.size, parts: parts.length,
      mime: file.type || "application/octet-stream", me: S.me, nick: S.nick, ts: ts()
    };
    var topic = S.cur.kind === "pm" ? (TOPIC + "file/" + S.cur.id + "/" + S.me) : (TOPIC + "grp/" + S.cur.id);
    pub(topic, meta);
    addMsg(chatKey(S.cur.kind, S.cur.id), {
      me: true, who: S.nick, file: { name: file.name, size: file.size, sent: true }, ts: ts()
    });
    var sent = 0;
    for (var i = 0; i < parts.length; i++) {
      pub(topic, { t: "fpart", fid: fid, i: i, d: parts[i], me: S.me });
      sent++;
      $("chatStat").textContent = "正在加密发送 " + sent + "/" + parts.length + " 片…";
      await new Promise(function (r) { setTimeout(r, 60); });
    }
    $("chatStat").textContent = "已发送（E2E 加密 · " + parts.length + " 片）";
    setTimeout(function () { $("chatStat").textContent = ""; }, 3000);
  }

  async function recvFile(kind, id, key, d, from) {
    var k = chatKey(kind, id);
    if (d.t === "file") {
      S.fileRx[d.fid] = { meta: d, parts: new Array(d.parts), got: 0, from: from };
      addSys(k, "@" + (d.nick || from) + " 发来文件：" + d.name + " (" + bytes(d.size) + ") 接收中…");
      return;
    }
    if (d.t === "fpart") {
      var st = S.fileRx[d.fid];
      if (!st) return;
      if (st.parts[d.i] == null) { st.parts[d.i] = d.d; st.got++; }
      if (st.got >= st.meta.parts) {
        var all = YaoCrypto.b64dec(st.parts.join(""));
        var plain = await YaoCrypto.decryptBytes(key, all);
        delete S.fileRx[d.fid];
        if (!plain) { addSys(k, "文件解密失败（密钥不一致）"); return; }
        var blob = new Blob([plain], { type: st.meta.mime });
        var url = URL.createObjectURL(blob);
        addMsg(k, {
          me: false, who: st.meta.nick || from, ts: ts(),
          file: { name: st.meta.name, size: st.meta.size, url: url, ok: true }
        });
        bump(k);
      }
    }
  }

  /* ================= 消息渲染 ================= */
  function addMsg(k, m) { push(k, m); if (S.cur && chatKey(S.cur.kind, S.cur.id) === k) renderMsgs(); renderChatList(); }
  function addSys(k, text) { addMsg(k, { me: false, sys: true, text: text, ts: ts() }); if (S.cur && chatKey(S.cur.kind, S.cur.id) !== k) renderChatList(); }
  function bump(k) { if (!S.cur || chatKey(S.cur.kind, S.cur.id) !== k) { unread++; renderChatList(); } else renderMsgs(); }

  function bubbleHTML(m) {
    if (m.sys) return '<div class="msg"><div class="bub sys">' + esc(m.text) + "</div></div>";
    var h = '<div class="msg' + (m.me ? " me" : "") + '">';
    h += '<div class="who">' + esc(m.who) + " · " + fmt(m.ts) + (m.enc ? ' <span class="lock">🔒</span>' : "") + "</div>";
    if (m.file) {
      h += '<div class="bub"><div class="file-b"><span class="fi">📄</span><span class="fn">' + esc(m.file.name) +
           " (" + bytes(m.file.size) + ")</span>" +
           (m.file.url ? ' <a href="' + m.file.url + '" download="' + esc(m.file.name) + '">下载</a>' : " 接收中") +
           "</div></div>";
    } else {
      h += '<div class="bub">' + esc(m.text) + "</div>";
    }
    return h + "</div>";
  }

  function renderMsgs() {
    if (!S.cur) return;
    var k = chatKey(S.cur.kind, S.cur.id);
    var arr = S.msgs[k] || [];
    $("msgs").innerHTML = arr.map(bubbleHTML).join("") ||
      '<div class="empty">还没有消息<br>发第一条试试（内容会端到端加密）</div>';
    $("msgs").scrollTop = $("msgs").scrollHeight;
    $("chatName").textContent = S.cur.name;
    $("chatKind").textContent = S.cur.kind === "pm" ? "🔒 私聊加密" : "🔒 群聊加密";
  }

  function renderChatList() {
    var items = [];
    S.friends.forEach(function (f) {
      var l = lastMsg("pm:" + f.u);
      items.push({ kind: "pm", id: f.u, name: f.nick, sub: l ? (l.sys ? l.text : (l.me ? "我: " : "") + (l.file ? "[文件] " + l.file.name : l.text)) : "点开开始加密聊天", ts: l ? l.ts : 0 });
    });
    S.groups.forEach(function (g) {
      var l = lastMsg("grp:" + g.gid);
      items.push({ kind: "grp", id: g.gid, name: g.name, sub: l ? (l.sys ? l.text : (l.me ? "我: " : "") + (l.file ? "[文件] " + l.file.name : l.text)) : "群已就绪", ts: l ? l.ts : 0, g: true });
    });
    items.sort(function (a, b) { return b.ts - a.ts; });
    $("chatList").innerHTML = items.length ? items.map(function (it) {
      return '<div class="list-item" onclick="YC.open(\'' + it.kind + '\',\'' + esc(it.id) + '\',\'' + esc(it.name) + '\')">' +
        '<div class="avatar' + (it.g ? " g" : "") + '">' + esc(it.name.slice(0, 1).toUpperCase()) + "</div>" +
        '<div class="li-txt"><div class="li-t">' + esc(it.name) + ' <span class="lock">🔒</span></div>' +
        '<div class="li-d">' + esc(String(it.sub).slice(0, 40)) + "</div></div></div>";
    }).join("") : '<div class="empty">还没有聊天<br>先去「联系人」添加好友，或到「群组」建个群</div>';
    var bd = $("bd-chats");
    if (unread > 0) { bd.textContent = unread > 99 ? "99+" : unread; bd.classList.remove("hide"); }
    else bd.classList.add("hide");
  }

  function renderContacts() {
    $("friendList").innerHTML = S.friends.length ? S.friends.map(function (f) {
      return '<div class="list-item" onclick="YC.open(\'pm\',\'' + esc(f.u) + '\',\'' + esc(f.nick) + '\')">' +
        '<div class="avatar">' + esc(f.nick.slice(0, 1).toUpperCase()) + "</div>" +
        '<div class="li-txt"><div class="li-t">' + esc(f.nick) + ' <span class="lock">🔒</span></div>' +
        '<div class="li-d">@' + esc(f.u) + "</div></div>" +
        '<button class="mini ghost" onclick="event.stopPropagation();YC.del(\'' + esc(f.u) + '\')">删除</button></div>';
    }).join("") : '<div class="empty">还没有好友<br>上面搜索用户名添加</div>';
  }

  function renderGroups() {
    $("groupList").innerHTML = S.groups.length ? S.groups.map(function (g) {
      return '<div class="list-item" onclick="YC.open(\'grp\',\'' + esc(g.gid) + '\',\'' + esc(g.name) + '\')">' +
        '<div class="avatar g">' + esc(g.name.slice(0, 1)) + "</div>" +
        '<div class="li-txt"><div class="li-t">' + esc(g.name) + ' <span class="lock">🔒</span></div>' +
        '<div class="li-d">群口令加密 · 分享群名+口令给同学即可加入</div></div></div>';
    }).join("") : '<div class="empty">还没有群<br>上面输入名字和口令创建</div>';
  }
  function renderAll() { renderChatList(); renderContacts(); renderGroups(); renderMe(); }

  function renderMe() {
    $("meInfo").innerHTML = "用户名：<b>" + esc(S.me) + "</b><br>昵称：" + esc(S.nick) +
      "<br>好友 " + S.friends.length + " 人 · 群 " + S.groups.length + " 个<br>" +
      "公钥已上传（别人可通过用户名搜到你）<br>消息端到端加密：私聊 ECDH / 群聊口令";
  }

  /* ================= 好友 / 群组 ================= */
  function searchUser() {
    var u = $("f-user").value.trim().toLowerCase();
    if (!u) return;
    var box = $("f-found");
    if (u === S.me) { box.innerHTML = '<div class="tip">这是你自己~</div>'; return; }
    var f = S.friends.filter(function (x) { return x.u === u; })[0];
    if (f) { box.innerHTML = '<div class="tip">已经是好友了：' + esc(f.nick) + "</div>"; return; }
    var d = S.dir[u];
    if (!d) {
      box.innerHTML = '<div class="tip">没找到 @' + esc(u) + "<br>（用户目录刷新中，稍等几秒再搜；或确认对方已注册并上线过）</div>";
      return;
    }
    box.innerHTML = '<div class="list-item"><div class="avatar">' + esc(d.nick.slice(0, 1).toUpperCase()) +
      '</div><div class="li-txt"><div class="li-t">' + esc(d.nick) + "</div><div class=\"li-d\">@" + esc(u) +
      '</div></div><button class="mini" onclick="YC.add(\'' + esc(u) + '\')">加好友</button></div>';
  }

  function addFriend(u) {
    var d = S.dir[u];
    if (!d) return;
    S.friends.push({ u: u, nick: d.nick, pub: d.pub });
    save(); renderAll();
    $("f-msg").textContent = "已添加 " + d.nick;
    $("f-found").innerHTML = "";
  }

  function delFriend(u) {
    S.friends = S.friends.filter(function (x) { return x.u !== u; });
    delete S.keys["pm:" + u];
    save(); renderAll();
  }

  /* 确定性群 ID: 同样的「群名+口令」= 同一个群 (同学输一样就能进同一群) */
  function simpleHash(s) {
    var h = 5381;
    for (var i = 0; i < s.length; i++) h = (((h << 5) + h) + s.charCodeAt(i)) >>> 0;
    return h.toString(36);
  }
  function gidOf(name, pass) { return "g" + simpleHash(name + "|" + pass); }

  async function createGroup() {
    var name = $("g-name").value.trim();
    var pass = $("g-pass").value;
    if (!name) { $("g-msg").textContent = "请填群名称"; return; }
    if (pass.length < 4) { $("g-msg").textContent = "群口令至少 4 位（成员必须相同）"; return; }
    var gid = gidOf(name, pass);
    var exist = S.groups.filter(function (x) { return x.gid === gid; })[0];
    if (!exist) S.groups.push({ gid: gid, name: name, pass: pass });
    save();
    delete S.keys["grp:" + gid];
    if (client && client.connected) client.subscribe(TOPIC + "grp/" + gid, { qos: 1 });
    $("g-msg").textContent = "已进入群「" + name + "」（把 群名称 和 群口令 告诉同学，他们输一样的即可进入同一个群）";
    $("g-name").value = ""; $("g-pass").value = "";
    renderAll();
  }

  /* ================= 界面 ================= */
  function tab(v) {
    document.querySelectorAll(".view").forEach(function (e) { e.classList.remove("on"); });
    $("v-" + v).classList.add("on");
    document.querySelectorAll("#tabs div").forEach(function (d) {
      d.classList.toggle("on", d.dataset.v === v);
    });
    if (v === "chats") { unread = 0; renderChatList(); }
  }

  function openChat(kind, id, name) {
    S.cur = { kind: kind, id: id, name: name };
    $("chatView").classList.remove("hide");
    renderMsgs();
    unread = 0; renderChatList();
  }
  function closeChat() { S.cur = null; $("chatView").classList.add("hide"); renderChatList(); }

  async function send() {
    var el = $("msgInput"), t = el.value.trim();
    if (!t || !S.cur) return;
    el.value = "";
    if (S.cur.kind === "pm") await sendPm(t); else await sendGroup(t);
    renderMsgs(); renderChatList();
  }

  function exportAcc() {
    var blob = new Blob([JSON.stringify({ v: 2, acc: S.acc, friends: S.friends, groups: S.groups }, null, 2)],
                        { type: "application/json" });
    var a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "yaochat-account-" + S.me + ".json";
    a.click();
  }
  function importAcc(file) {
    var r = new FileReader();
    r.onload = function () {
      try {
        var d = JSON.parse(r.result);
        if (!d.acc || !d.acc.u) { alert("文件格式不对"); return; }
        S.acc = d.acc; S.friends = d.friends || []; S.groups = d.groups || [];
        save();
        alert("导入成功！请用原密码登录 @" + d.acc.u);
        location.reload();
      } catch (e) { alert("导入失败: " + e.message); }
    };
    r.readAsText(file);
  }

  function logout() {
    try { if (client) client.end(); } catch (e) {}
    S.priv = null; S.keys = {}; S.cur = null;
    $("app").classList.add("hide");
    $("chatView").classList.add("hide");
    $("auth").classList.remove("hide");
    $("authSwitch").classList.remove("hide");
    $("nickLabel").classList.add("hide"); $("au-nick").classList.add("hide");
    $("authTitle").textContent = "登录";
    btnWait(false); err(""); ok("已退出");
  }

  /* ================= 初始化 ================= */
  var isReg = false;
  function bind() {
    $("authBtn").onclick = function () { isReg ? doRegister() : doLogin(); };
    $("authSwitch").onclick = function () {
      isReg = !isReg;
      $("authTitle").textContent = isReg ? "注册" : "登录";
      $("authSwitch").textContent = isReg ? "已有账号？点这里登录" : "还没有账号？点这里注册";
      $("nickLabel").classList.toggle("hide", !isReg);
      $("au-nick").classList.toggle("hide", !isReg);
      btnWait(false); err("");
    };
    $("tabs").querySelectorAll("div").forEach(function (d) {
      d.onclick = function () { tab(d.dataset.v); };
    });
    $("f-search").onclick = searchUser;
    $("g-create").onclick = createGroup;
    $("btnSend").onclick = send;
    $("msgInput").onkeydown = function (e) { if (e.key === "Enter") send(); };
    $("chatBack").onclick = closeChat;
    $("btn-export").onclick = exportAcc;
    $("btn-import").onclick = function () { $("importFile").click(); };
    $("importFile").onchange = function () { if (this.files[0]) importAcc(this.files[0]); };
    $("btnFile").onclick = function () {
      if (!S.cur) return;
      $("fileInput").click();
    };
    $("fileInput").onchange = function () {
      if (this.files[0]) { sendFile(this.files[0]); this.value = ""; }
    };
    $("btn-logout").onclick = logout;
  }

  window.YC = {
    open: openChat, add: addFriend, del: delFriend,
    state: S, tab: tab,
    debug: function () {
      return {
        connected: !!(client && client.connected),
        subs: S.groups.map(function (g) { return g.gid; }),
        keys: Object.keys(S.keys),
        dirUsers: Object.keys(S.dir)
      };
    }
  };

  load(); bind();
  if (S.acc) { $("au-user").value = S.acc.u; ok("本机已有账号 @" + S.acc.u + "，输入密码登录"); }
})();
