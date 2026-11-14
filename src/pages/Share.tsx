import { useEffect, useState } from "react";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import { open } from "@tauri-apps/plugin-dialog";
import { revealItemInDir } from "@tauri-apps/plugin-opener";
import { CircleCheck, CircleX, FileUp, FolderOpen, ShieldAlert, Smartphone, X } from "lucide-react";
import { api, errorText, formatBytes } from "../api";
import { useApp } from "../store";
import { Button } from "../components/ui/Button";
import { Card, PageHeader } from "../components/Section";

const STATUS = {
  pending: { text: "Waiting for you", cls: "bg-warn-soft text-warn" },
  allowed: { text: "Allowed", cls: "bg-ok-soft text-ok" },
  denied: { text: "Denied", cls: "bg-hover text-muted" },
} as const;

export function SharePage() {
  const { view, settings, transfers, sent } = useApp();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [dragging, setDragging] = useState(false);

  // Files dropped anywhere on the window are shared to phones.
  useEffect(() => {
    const off = getCurrentWebview().onDragDropEvent((e) => {
      if (e.payload.type === "enter" || e.payload.type === "over") setDragging(true);
      else setDragging(false);
      if (e.payload.type === "drop" && useApp.getState().view?.on) {
        api.offerFiles(e.payload.paths).catch((err) => setError(errorText(err)));
      }
    });
    return () => void off.then((f) => f());
  }, []);

  if (!view || !settings) return null;

  const run = async (f: () => Promise<unknown>) => {
    setBusy(true);
    setError(null);
    try {
      await f();
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  };
  const choose = async () => {
    const picked = await open({ multiple: true, directory: false });
    if (picked) await run(() => api.offerFiles(Array.isArray(picked) ? picked : [picked]));
  };
  const received = Object.entries(transfers).sort(([a], [b]) => Number(b) - Number(a));
  const devices = view.devices.filter((d) => d.status !== "denied");

  return (
    <>
      <PageHeader title="Share">Phones and other devices on your network scan a code, then send and receive files in their browser.</PageHeader>

      {error && (
        <p role="alert" className="mb-4 whitespace-pre-wrap rounded-control bg-bad-soft px-3 py-2 text-bad">
          {error}
        </p>
      )}

      {view.firewall.state === "blocked" && (
        <div role="alert" className="mb-4 flex items-center gap-3 rounded-panel border border-line bg-warn-soft p-4">
          <ShieldAlert size={18} className="shrink-0 text-warn" aria-hidden />
          <p className="flex-1">
            Your firewall blocks phones from reaching Simple Share. Allowing it opens only port {settings.port} on the “{view.firewall.zone}” network zone.
            You'll be asked for your password.
          </p>
          <Button variant="primary" disabled={busy} onClick={() => run(async () => useApp.setState({ view: await api.allowFirewall() }))}>
            Allow
          </Button>
        </div>
      )}

      {!view.on ? (
        <Card>
          <div className="flex items-center gap-4">
            <div className="flex-1">
              <p className="text-[0.9375rem] font-semibold">Sharing is off</p>
              <p className="text-muted">Nothing is listening on the network until you start. Every device needs your OK.</p>
            </div>
            <Button variant="primary" className="h-9 px-4" disabled={busy} onClick={() => run(api.startSharing)}>
              {busy ? "Starting…" : "Start sharing"}
            </Button>
          </div>
        </Card>
      ) : (
        <Card>
          <div className="flex flex-wrap items-start gap-6">
            {view.qr && (
              <img
                src={`data:image/svg+xml;charset=utf-8,${encodeURIComponent(view.qr)}`}
                alt="QR code to connect a phone"
                className="size-48 shrink-0 rounded-control bg-white p-1"
              />
            )}
            <div className="min-w-56 flex-1">
              <p className="text-[0.9375rem] font-semibold">Scan with your phone's camera</p>
              <p className="mt-1 text-muted">Or type this address in its browser:</p>
              <code className="mt-2 block break-all rounded-control bg-ink px-2.5 py-1.5 font-mono text-xs" data-selectable>
                {view.url}
              </code>
              <p className="mt-3 text-xs text-faint">
                Phones that haven't paired see a security warning once. That's expected: tap Show Details → visit this website. Pair a phone from the page it
                opens to remove the warning for good. Sharing stops after {settings.idleMinutes} minutes without activity.
              </p>
              <Button className="mt-4" disabled={busy} onClick={() => run(api.stopSharing)}>
                Stop sharing
              </Button>
            </div>
          </div>
        </Card>
      )}

      {view.on && (
        <>
          <Card title="Devices">
            {devices.length === 0 ? (
              <p className="text-muted">No devices yet.</p>
            ) : (
              <ul className="space-y-2">
                {devices.map((d) => (
                  <li key={d.id} className="flex items-center gap-3">
                    <Smartphone size={15} className="shrink-0 text-faint" aria-hidden />
                    <span className="font-medium">{d.label}</span>
                    <span className="font-mono text-xs text-muted">{d.ip}</span>
                    <span className={`ml-auto rounded-chip px-2 py-0.5 text-xs font-medium ${STATUS[d.status].cls}`}>{STATUS[d.status].text}</span>
                    {d.status === "allowed" && (
                      <Button variant="ghost" onClick={() => void api.revoke(d.id)}>
                        Remove
                      </Button>
                    )}
                  </li>
                ))}
              </ul>
            )}
          </Card>

          <Card title="Send to phones">
            <div
              className={`flex flex-col items-center gap-2 rounded-panel border-2 border-dashed p-6 text-center transition-colors ${
                dragging ? "border-accent bg-accent-soft" : "border-line"
              }`}
            >
              <FileUp size={22} className="text-faint" aria-hidden />
              <p className="text-muted">Drop files here, or</p>
              <Button onClick={choose}>Choose files…</Button>
            </div>
            {view.offers.length > 0 && (
              <ul className="mt-3 space-y-1">
                {view.offers.map((o) => (
                  <li key={o.id} className="flex items-center gap-3 rounded-control px-2 py-1.5 hover:bg-hover">
                    <span className="min-w-0 flex-1 truncate" data-selectable>
                      {o.name}
                    </span>
                    {sent[o.id] && <span className="text-xs text-ok">Sent to {sent[o.id]}</span>}
                    <span className="text-xs text-muted">{formatBytes(o.size)}</span>
                    <Button variant="ghost" aria-label={`Stop sharing ${o.name}`} onClick={() => void api.withdraw(o.id)}>
                      <X size={14} aria-hidden />
                    </Button>
                  </li>
                ))}
              </ul>
            )}
          </Card>

          <Card title="Received">
            {received.length === 0 ? (
              <p className="text-muted">Files from phones are saved to {settings.receiveDir}.</p>
            ) : (
              <ul className="space-y-2">
                {received.map(([id, t]) => (
                  <li key={id}>
                    <div className="flex items-center gap-2">
                      {t.state === "saved" && <CircleCheck size={15} className="shrink-0 text-ok" aria-label="Saved" />}
                      {t.state === "failed" && <CircleX size={15} className="shrink-0 text-bad" aria-label="Failed" />}
                      <span className="min-w-0 flex-1 truncate font-medium" data-selectable>
                        {t.name}
                      </span>
                      <span className="text-xs text-muted">
                        from {t.device}
                        {t.state !== "failed" && ` · ${formatBytes(t.total)}`}
                      </span>
                      {t.path && (
                        <Button variant="ghost" aria-label="Show in folder" onClick={() => void revealItemInDir(t.path!)}>
                          <FolderOpen size={14} aria-hidden />
                        </Button>
                      )}
                    </div>
                    {t.state === "receiving" && <progress className="mt-1 h-1.5 w-full" value={t.done} max={Math.max(t.total, 1)} />}
                    {t.error && <p className="text-xs text-bad">{t.error}</p>}
                  </li>
                ))}
              </ul>
            )}
          </Card>
        </>
      )}
    </>
  );
}
