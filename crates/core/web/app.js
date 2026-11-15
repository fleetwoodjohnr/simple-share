"use strict";
// The phone page. Every piece of text from the server goes in through
// textContent, never innerHTML.

const $ = (id) => document.getElementById(id);
let state = null;
let ended = false;
const queue = [];
let sending = false;

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
}

function size(n) {
  if (n < 1024) return n + " B";
  const u = ["KB", "MB", "GB", "TB"];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < u.length - 1) {
    v /= 1024;
    i++;
  }
  return (v < 10 ? v.toFixed(1) : Math.round(v)) + " " + u[i];
}

function show(id) {
  for (const s of ["wait", "denied", "gone", "ready"]) $(s).hidden = s !== id;
}

function end(title, text) {
  ended = true;
  $("peer").textContent = "Not connected";
  if (title) $("gone-title").textContent = title;
  if (text) $("gone-text").textContent = text;
  show("gone");
}

async function refresh() {
  if (ended) return;
  let r;
  try {
    r = await fetch("/api/state", { cache: "no-store" });
  } catch {
    return end();
  }
  if (r.status === 401) return end("Scan the code on the computer", "Open Simple Share on the computer, start sharing and scan its code.");
  if (!r.ok) return;
  state = await r.json();
  $("peer").textContent = "Connected to " + state.name;
  if (state.status === "pending") {
    $("wait-name").textContent = state.name;
    $("wait-code").textContent = state.code || "";
    show("wait");
  } else if (state.status === "denied") {
    show("denied");
  } else {
    $("to-name").textContent = state.name;
    $("from-name").textContent = state.name;
    $("remembered").hidden = !state.remembered;
    $("address").textContent = location.origin;
    renderOffers();
    show("ready");
  }
}

function listen() {
  const es = new EventSource("/api/events");
  es.onmessage = (e) => {
    if (e.data === "ended") {
      es.close();
      end();
    } else {
      refresh();
    }
  };
  // The browser retries on its own; if the computer is gone, refresh() notices.
  es.onerror = () => setTimeout(refresh, 1500);
}

// ---- sending to the computer ----

$("pick").addEventListener("change", (e) => {
  for (const file of e.target.files) {
    const item = { file, row: el("li"), xhr: null };
    const top = el("div", "row");
    top.append(el("span", "name", file.name));
    item.cancel = el("button", "button small", "Cancel");
    item.cancel.type = "button";
    item.cancel.addEventListener("click", () => (item.xhr ? item.xhr.abort() : finish(item, "Cancelled", "bad")));
    top.append(item.cancel);
    item.meta = el("p", "meta", size(file.size) + " · waiting");
    item.bar = el("progress");
    item.bar.max = 1;
    item.bar.value = 0;
    item.row.append(top, item.meta, item.bar);
    $("uploads").prepend(item.row);
    queue.push(item);
  }
  e.target.value = "";
  pump();
});

function finish(item, text, kind) {
  item.done = true;
  item.meta.textContent = text;
  item.meta.className = "meta " + (kind || "");
  item.bar.remove();
  item.cancel.remove();
}

async function pump() {
  if (sending) return;
  sending = true;
  while (queue.length) {
    const item = queue.shift();
    if (!item.done) await send(item);
  }
  sending = false;
}

function send(item) {
  return new Promise((resolve) => {
    if (state && item.file.size > state.maxUpload) {
      finish(item, "Too large: the computer accepts up to " + size(state.maxUpload), "bad");
      return resolve();
    }
    const xhr = new XMLHttpRequest();
    item.xhr = xhr;
    xhr.open("PUT", "/api/upload?name=" + encodeURIComponent(item.file.name));
    xhr.setRequestHeader("X-Simple-Share", "1");
    xhr.upload.onprogress = (e) => {
      if (!e.lengthComputable) return;
      item.bar.value = e.loaded / e.total;
      item.meta.textContent = size(e.loaded) + " of " + size(e.total);
    };
    xhr.onload = () => {
      if (xhr.status === 200) {
        // Only now is it on the computer's disk.
        const r = JSON.parse(xhr.responseText);
        finish(item, "Saved as " + r.name + " · SHA-256 " + r.sha256.slice(0, 16) + "…", "ok");
      } else {
        finish(item, xhr.responseText || "Failed (" + xhr.status + ")", "bad");
      }
      resolve();
    };
    xhr.onerror = () => {
      finish(item, "Connection lost", "bad");
      resolve();
    };
    xhr.onabort = () => {
      finish(item, "Cancelled", "bad");
      resolve();
    };
    xhr.send(item.file);
  });
}

// ---- receiving from the computer ----

const canShareFiles = (() => {
  try {
    return !!navigator.canShare && navigator.canShare({ files: [new File([""], "x.jpg", { type: "image/jpeg" })] });
  } catch {
    return false;
  }
})();
const prepared = new Map(); // offer id -> File, so Save works on the second tap

function renderOffers() {
  const list = $("offers");
  list.replaceChildren();
  $("no-offers").hidden = state.offers.length > 0;
  for (const o of state.offers) {
    const li = el("li");
    const top = el("div", "row");
    top.append(el("span", "name", o.name));
    li.append(top, el("p", "meta", size(o.size)));
    const actions = el("div", "actions");
    const dl = el("a", "button small", "Download");
    dl.href = "/api/files/" + encodeURIComponent(o.id);
    dl.setAttribute("download", o.name);
    actions.append(dl);
    if (canShareFiles && /^(image|video)\//.test(o.mime)) actions.append(saveButton(o));
    li.append(actions);
    list.append(li);
  }
}

// Safari only allows the share sheet straight from a tap, and fetching a big
// video takes longer than that, so: first tap fetches, second tap saves.
function saveButton(o) {
  const b = el("button", "button small primary", prepared.has(o.id) ? "Save to Photos" : "Get for Photos");
  b.type = "button";
  b.addEventListener("click", async () => {
    const file = prepared.get(o.id);
    if (file) {
      try {
        await navigator.share({ files: [file] });
      } catch {}
      return;
    }
    b.disabled = true;
    b.textContent = "Getting…";
    try {
      const r = await fetch("/api/files/" + encodeURIComponent(o.id));
      if (!r.ok) throw new Error(await r.text());
      const blob = await r.blob();
      prepared.set(o.id, new File([blob], o.name, { type: o.mime }));
      b.textContent = "Save to Photos";
    } catch (e) {
      b.textContent = "Try again";
    }
    b.disabled = false;
  });
  return b;
}

refresh().then(() => {
  if (!ended) listen();
});
