import { useEffect } from "react";
import { isTauri } from "@tauri-apps/api/core";
import { Tooltip } from "radix-ui";
import { ArrowUpDown, History as HistoryIcon, Settings as SettingsIcon } from "lucide-react";
import { startBridge, useApp, type Page } from "./store";
import { DeviceDialog } from "./DeviceDialog";
import { SharePage } from "./pages/Share";
import { History } from "./pages/History";
import { SettingsPage } from "./pages/Settings";
import { scheduleUpdateChecks, useUpdates } from "./updates/store";
import { UpdateNotice } from "./updates/UpdateNotice";

const NAV: { id: Page; label: string; icon: typeof ArrowUpDown }[] = [
  { id: "share", label: "Share", icon: ArrowUpDown },
  { id: "history", label: "History", icon: HistoryIcon },
  { id: "settings", label: "Settings", icon: SettingsIcon },
];

function useTheme(theme: string | undefined) {
  useEffect(() => {
    const media = window.matchMedia("(prefers-color-scheme: dark)");
    const apply = () => {
      document.documentElement.dataset.theme = theme === "light" || theme === "dark" ? theme : media.matches ? "dark" : "light";
    };
    apply();
    media.addEventListener("change", apply);
    return () => media.removeEventListener("change", apply);
  }, [theme]);
}

export default function App() {
  const { page, setPage, settings, view } = useApp();
  useTheme(settings?.theme);
  useEffect(() => {
    void startBridge();
  }, []);
  // Release builds only: checks GitHub at startup and daily. Installing always asks.
  const autoCheck = settings?.checkUpdates;
  useEffect(() => {
    if (!autoCheck || !import.meta.env.PROD || !isTauri()) return;
    return scheduleUpdateChecks(() => void useUpdates.getState().checkNow());
  }, [autoCheck]);

  return (
    <Tooltip.Provider delayDuration={400}>
      <div className="flex h-full">
        <nav aria-label="Main" className="flex w-56 shrink-0 flex-col border-r border-line bg-panel p-3">
          <div className="mb-5 flex items-center gap-2.5 px-2 pt-1">
            <img src="/icon.svg" alt="" className="size-7" />
            <span className="text-[0.9375rem] font-semibold">Simple Share</span>
          </div>
          <ul className="flex flex-col gap-0.5">
            {NAV.map(({ id, label, icon: Icon }) => (
              <li key={id}>
                <button
                  type="button"
                  aria-current={page === id ? "page" : undefined}
                  onClick={() => setPage(id)}
                  className={`flex h-9 w-full items-center gap-2.5 rounded-control px-2.5 font-medium transition-colors ${
                    page === id ? "bg-accent-soft text-accent" : "text-muted hover:bg-hover hover:text-text"
                  }`}
                >
                  <Icon size={16} aria-hidden />
                  {label}
                </button>
              </li>
            ))}
          </ul>
          <p className="mt-auto flex items-center gap-2 px-2 text-xs text-muted" role="status">
            <span className={`size-2 rounded-full ${view?.on ? "bg-ok" : "bg-faint"}`} aria-hidden />
            {view?.on ? "Sharing on" : "Sharing off"}
          </p>
        </nav>
        <main className="min-w-0 flex-1 overflow-y-auto">
          <div className="mx-auto max-w-3xl px-8 py-7">
            {page === "share" && <SharePage />}
            {page === "history" && <History />}
            {page === "settings" && <SettingsPage />}
          </div>
        </main>
      </div>
      <DeviceDialog />
      <UpdateNotice onReview={() => setPage("settings")} />
    </Tooltip.Provider>
  );
}
