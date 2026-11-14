import { useEffect, useState, type ReactNode } from "react";
import { Switch } from "radix-ui";
import { open } from "@tauri-apps/plugin-dialog";
import { getVersion } from "@tauri-apps/api/app";
import { useUpdates } from "../updates/store";
import { api, errorText, type Settings } from "../api";
import { useApp } from "../store";
import { Button } from "../components/ui/Button";
import { ConfirmDialog } from "../components/ui/ConfirmDialog";
import { Field, inputClass } from "../components/ui/Field";
import { Card, PageHeader } from "../components/Section";

function Row({ label, hint, children }: { label: string; hint?: string; children: ReactNode }) {
  return (
    <div className="flex items-center gap-4 border-b border-line py-3 last:border-0">
      <div className="flex-1">
        <p className="font-medium">{label}</p>
        {hint && <p className="text-xs text-faint">{hint}</p>}
      </div>
      {children}
    </div>
  );
}

function Toggle({ checked, onChange, label }: { checked: boolean; onChange: (v: boolean) => void; label: string }) {
  return (
    <Switch.Root
      checked={checked}
      onCheckedChange={onChange}
      aria-label={label}
      className="relative h-5 w-9 shrink-0 rounded-full bg-line-strong transition-colors data-[state=checked]:bg-accent"
    >
      <Switch.Thumb className="block size-4 translate-x-0.5 rounded-full bg-white transition-transform data-[state=checked]:translate-x-[18px]" />
    </Switch.Root>
  );
}

export function SettingsPage() {
  const { settings, view, saveSettings } = useApp();
  const [name, setName] = useState(settings?.deviceName ?? "");
  const [port, setPort] = useState(String(settings?.port ?? ""));
  const [fingerprint, setFingerprint] = useState("");
  const [confirmReset, setConfirmReset] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [autostart, setAutostartState] = useState(false);
  const [version, setVersion] = useState("");
  const updates = useUpdates();
  useEffect(() => {
    void api.getAutostart().then(setAutostartState, () => undefined);
    void getVersion().then(setVersion, () => undefined);
  }, []);
  useEffect(() => setName(settings?.deviceName ?? ""), [settings?.deviceName]);
  useEffect(() => setPort(String(settings?.port ?? "")), [settings?.port]);
  useEffect(() => {
    void api.fingerprint().then(setFingerprint);
  }, []);
  if (!settings) return null;

  const save = (patch: Partial<Settings>) => {
    setError(null);
    saveSettings(patch).catch((e) => setError(errorText(e)));
  };
  // Tailwind orders utilities by its own stylesheet, so w-full would beat an added w-auto.
  const select = inputClass.replace("w-full", "w-auto");
  const updating = updates.state === "downloading" || updates.state === "installing";

  return (
    <>
      <PageHeader title="Settings" />
      {error && (
        <p role="alert" className="mb-4 rounded-control bg-bad-soft px-3 py-2 text-bad">
          {error}
        </p>
      )}

      <Card title="This computer">
        <Field
          label="Name shown on phones"
          value={name}
          maxLength={63}
          onChange={(e) => setName(e.target.value)}
          onBlur={() => name !== settings.deviceName && save({ deviceName: name })}
        />
        <div className="mt-4 flex items-end gap-2">
          <Field label="Save received files to" value={settings.receiveDir} readOnly className="flex-1" />
          <Button
            onClick={async () => {
              const dir = await open({ directory: true, defaultPath: settings.receiveDir });
              if (typeof dir === "string") save({ receiveDir: dir });
            }}
          >
            Change…
          </Button>
        </div>
      </Card>

      <Card title="General">
        <Row label="Launch at login">
          <Toggle
            label="Launch at login"
            checked={autostart}
            onChange={(v) => api.setAutostart(v).then(setAutostartState, (e) => setError(errorText(e)))}
          />
        </Row>
        <Row label="Start in the tray" hint="When launched at login, stay in the tray instead of opening this window.">
          <Toggle label="Start in the tray" checked={settings.startInTray} onChange={(v) => save({ startInTray: v })} />
        </Row>
      </Card>

      <Card title="Sharing">
        <Row label="Stop sharing after" hint="Of no activity from any device. The port closes with it.">
          <select className={select} value={settings.idleMinutes} onChange={(e) => save({ idleMinutes: Number(e.target.value) })}>
            {[5, 15, 30, 60].map((m) => (
              <option key={m} value={m}>
                {m} minutes
              </option>
            ))}
          </select>
        </Row>
        <Row label="Largest file accepted">
          <select className={select} value={settings.maxUploadMb} onChange={(e) => save({ maxUploadMb: Number(e.target.value) })}>
            {[512, 2048, 4096, 16384].map((mb) => (
              <option key={mb} value={mb}>
                {mb >= 1024 ? `${mb / 1024} GB` : `${mb} MB`}
              </option>
            ))}
          </select>
        </Row>
        <Row label="Port" hint="Change it only if another program uses this one. Takes effect next time you start sharing.">
          <input
            className={`${inputClass.replace("w-full", "w-24")} font-mono`}
            inputMode="numeric"
            value={port}
            onChange={(e) => setPort(e.target.value.replace(/\D/g, ""))}
            onBlur={() => Number(port) !== settings.port && save({ port: Number(port) })}
            aria-label="Port"
          />
        </Row>
        <Row label="Notifications">
          <Toggle label="Notifications" checked={settings.notifications} onChange={(v) => save({ notifications: v })} />
        </Row>
      </Card>

      <Card title="Pairing">
        <p className="text-muted">
          Phones that install this computer's certificate get a verified connection with no warning. When installing it on an iPhone, check that the SHA-256 under
          Settings → General → VPN &amp; Device Management → the profile → More Details matches:
        </p>
        <code className="mt-3 block break-all rounded-control bg-ink px-2.5 py-2 font-mono text-xs leading-relaxed" data-selectable>
          {fingerprint}
        </code>
        <p className="mt-3 text-xs text-faint">
          The certificate can only vouch for addresses on private networks, never for websites, so installing it can't be used to spy on a phone's other
          traffic.
        </p>
        <Button className="mt-3" onClick={() => setConfirmReset(true)}>
          Reset certificate…
        </Button>
      </Card>

      {(settings.firewallRule || view?.firewall.state === "blocked") && (
        <Card title="Firewall">
          {settings.firewallRule ? (
            <div className="flex items-center gap-4">
              <p className="flex-1 text-muted">
                Port {settings.firewallRule.port} is open in the “{settings.firewallRule.zone}” zone for Simple Share.
              </p>
              <Button onClick={() => api.removeFirewallRule().then((s) => useApp.setState({ settings: s }), (e) => setError(errorText(e)))}>
                Remove firewall rule
              </Button>
            </div>
          ) : (
            <p className="text-muted">Your firewall blocks phones. Use Allow on the Share page to open only Simple Share's port.</p>
          )}
        </Card>
      )}

      <Card title="Appearance">
        <Row label="Theme">
          <select className={select} value={settings.theme} onChange={(e) => save({ theme: e.target.value as Settings["theme"] })}>
            <option value="system">Match system</option>
            <option value="light">Light</option>
            <option value="dark">Dark</option>
          </select>
        </Row>
      </Card>

      <Card title="About & updates">
        <Row label="Simple Share">
          <span className="font-mono text-muted">{version}</span>
        </Row>
        <Row label="Check for updates automatically" hint="At startup and once a day, from GitHub. Nothing installs until you choose to.">
          <Toggle label="Check for updates automatically" checked={settings.checkUpdates} onChange={(v) => save({ checkUpdates: v })} />
        </Row>
        <Row
          label={updates.update ? `Version ${updates.update.version} is available` : updates.state === "none" ? "You're up to date" : "Updates"}
          hint="Updates are installed only if their signature matches Simple Share's release key. Installing stops sharing and restarts the app."
        >
          {updates.update ? (
            <Button variant="primary" disabled={updating || updates.state === "checking"} onClick={() => void updates.install()}>
              {updates.state === "downloading" ? "Downloading…" : updates.state === "installing" ? "Installing…" : "Install and restart"}
            </Button>
          ) : (
            <Button disabled={updates.state === "checking"} onClick={() => void updates.checkNow()}>
              {updates.state === "checking" ? "Checking…" : "Check now"}
            </Button>
          )}
        </Row>
        {updates.state === "downloading" && (
          <div role="status" className="pt-2">
            <progress className="w-full" value={updates.total ? updates.downloaded : undefined} max={updates.total ?? undefined} aria-label="Update download" />
          </div>
        )}
        {updates.update?.body && <p className="whitespace-pre-wrap pt-2 text-muted">{updates.update.body}</p>}
        {updates.state === "error" && <p className="pt-2 text-bad">Update failed: {updates.error}</p>}
      </Card>

      <ConfirmDialog
        open={confirmReset}
        onOpenChange={setConfirmReset}
        title="Reset the certificate?"
        description="Sharing stops, and phones that installed the old certificate will see the security warning again until they install the new one. Remove the old Simple Share profile from them."
        confirmLabel="Reset certificate"
        onConfirm={async () => setFingerprint(await api.resetCertificate())}
      />
    </>
  );
}
