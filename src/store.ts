import { create } from "zustand";
import { listen } from "@tauri-apps/api/event";
import { api, type HistoryEntry, type Settings, type ShareEvent, type View } from "./api";

export type Page = "share" | "history" | "settings";

export interface Transfer {
  name: string;
  device: string;
  done: number;
  total: number;
  state: "receiving" | "saved" | "failed";
  path?: string;
  error?: string;
}

interface AppState {
  page: Page;
  settings: Settings | null;
  view: View | null;
  history: HistoryEntry[];
  /** Received this session, newest first, keyed by upload id. */
  transfers: Record<number, Transfer>;
  /** Offer ids a phone has fully downloaded. */
  sent: Record<string, string>;
  setPage: (p: Page) => void;
  saveSettings: (patch: Partial<Settings>) => Promise<void>;
}

export const useApp = create<AppState>((set, get) => ({
  page: "share",
  settings: null,
  view: null,
  history: [],
  transfers: {},
  sent: {},
  setPage: (page) => set({ page }),
  saveSettings: async (patch) => {
    const current = get().settings;
    if (!current) return;
    set({ settings: await api.saveSettings({ ...current, ...patch }) });
  },
}));

function onEvent(ev: ShareEvent) {
  useApp.setState((s) => {
    const t = { ...s.transfers };
    switch (ev.type) {
      case "progress":
        t[ev.upload] = { name: ev.name, device: ev.device, done: ev.done, total: ev.total, state: "receiving" };
        return { transfers: t };
      case "saved":
        t[ev.upload] = { name: ev.path.split(/[\\/]/).pop() ?? "", device: ev.device, done: ev.size, total: ev.size, state: "saved", path: ev.path };
        return { transfers: t };
      case "failed":
        t[ev.upload] = { name: ev.name, device: ev.device, done: 0, total: 0, state: "failed", error: ev.error };
        return { transfers: t };
      case "sent":
        return { sent: { ...s.sent, [ev.offer]: ev.device } };
      default:
        return {};
    }
  });
}

let started = false;
/** Load everything once and keep it in sync with the backend's events. */
export async function startBridge() {
  if (started) return;
  started = true;
  const [settings, view, history] = await Promise.all([api.getSettings(), api.view(), api.history()]);
  useApp.setState({ settings, view, history });
  await listen<View>("view", (e) => {
    useApp.setState({ view: e.payload });
    if (!e.payload.on) useApp.setState({ transfers: {}, sent: {} });
  });
  await listen<ShareEvent>("share-event", (e) => onEvent(e.payload));
  await listen("history", async () => useApp.setState({ history: await api.history() }));
}
