import { invoke } from "@tauri-apps/api/core";

export interface Device {
  id: number;
  label: string;
  ip: string;
  status: "pending" | "allowed" | "denied";
}
export interface Offer {
  id: string;
  name: string;
  size: number;
  mime: string;
}
export type Firewall = { state: "notManaged" } | { state: "open" } | { state: "blocked"; zone: string };
export interface View {
  on: boolean;
  url: string | null;
  qr: string | null;
  devices: Device[];
  offers: Offer[];
  firewall: Firewall;
}
export interface Settings {
  deviceName: string;
  receiveDir: string;
  port: number;
  idleMinutes: number;
  maxUploadMb: number;
  notifications: boolean;
  theme: "system" | "light" | "dark";
  startInTray: boolean;
  checkUpdates: boolean;
  firewallRule: { zone: string; port: number } | null;
}
export type ShareEvent =
  | { type: "deviceRequest"; device: Device }
  | { type: "deviceExpired"; id: number }
  | { type: "progress"; upload: number; device: string; name: string; done: number; total: number }
  | { type: "saved"; upload: number; device: string; path: string; size: number; sha256: string }
  | { type: "failed"; upload: number; device: string; name: string; error: string }
  | { type: "sent"; offer: string; device: string; name: string };
export interface HistoryEntry {
  at: number;
  direction: "received" | "sent";
  peer: string;
  files: { name: string; size: number; path: string | null; sha256: string | null }[];
  result: "saved" | "sent" | "failed";
  error: string | null;
}

export const api = {
  view: () => invoke<View>("view"),
  startSharing: () => invoke<View>("start_sharing"),
  stopSharing: () => invoke<void>("stop_sharing"),
  decide: (id: number, allow: boolean) => invoke<void>("decide", { id, allow }),
  revoke: (id: number) => invoke<void>("revoke", { id }),
  offerFiles: (paths: string[]) => invoke<void>("offer_files", { paths }),
  withdraw: (id: string) => invoke<void>("withdraw", { id }),
  getSettings: () => invoke<Settings>("get_settings"),
  saveSettings: (settings: Settings) => invoke<Settings>("save_settings", { settings }),
  history: () => invoke<HistoryEntry[]>("history"),
  clearHistory: () => invoke<void>("clear_history"),
  fingerprint: () => invoke<string>("fingerprint"),
  resetCertificate: () => invoke<string>("reset_certificate"),
  allowFirewall: () => invoke<View>("allow_firewall"),
  removeFirewallRule: () => invoke<Settings>("remove_firewall_rule"),
  getAutostart: () => invoke<boolean>("get_autostart"),
  setAutostart: (enabled: boolean) => invoke<boolean>("set_autostart", { enabled }),
};

export function errorText(e: unknown): string {
  return typeof e === "string" ? e : e instanceof Error ? e.message : String(e);
}

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v < 10 ? v.toFixed(1) : Math.round(v)} ${units[i]}`;
}
