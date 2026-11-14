import { useState } from "react";
import { revealItemInDir } from "@tauri-apps/plugin-opener";
import { ArrowDownLeft, ArrowUpRight, FolderOpen } from "lucide-react";
import { api, formatBytes, type HistoryEntry } from "../api";
import { useApp } from "../store";
import { Button } from "../components/ui/Button";
import { ConfirmDialog } from "../components/ui/ConfirmDialog";
import { PageHeader } from "../components/Section";

const RESULT: Record<HistoryEntry["result"], string> = {
  saved: "bg-ok-soft text-ok",
  sent: "bg-ok-soft text-ok",
  failed: "bg-bad-soft text-bad",
};

export function History() {
  const history = useApp((s) => s.history);
  const [confirm, setConfirm] = useState(false);

  return (
    <>
      <div className="flex items-start">
        <PageHeader title="History">Recent transfers on this computer.</PageHeader>
        {history.length > 0 && (
          <Button variant="ghost" className="ml-auto" onClick={() => setConfirm(true)}>
            Clear
          </Button>
        )}
      </div>
      {history.length === 0 ? (
        <p className="rounded-panel border border-dashed border-line p-8 text-center text-muted">Nothing yet. Files you send and receive will appear here.</p>
      ) : (
        <ul className="overflow-hidden rounded-panel border border-line bg-panel">
          {history.map((h, i) => {
            const Dir = h.direction === "received" ? ArrowDownLeft : ArrowUpRight;
            const size = h.files.reduce((n, f) => n + f.size, 0);
            const first = h.files.find((f) => f.path)?.path;
            return (
              <li key={i} className="flex items-center gap-3 border-b border-line px-4 py-3 last:border-0">
                <Dir size={16} className="shrink-0 text-faint" aria-label={h.direction} />
                <div className="min-w-0 flex-1">
                  <p className="truncate font-medium" data-selectable>
                    {h.files.length ? h.files.map((f) => f.name).join(", ") : h.direction === "received" ? "Incoming transfer" : "Transfer"}
                  </p>
                  <p className="truncate text-xs text-muted">
                    {h.direction === "received" ? "From" : "To"} “{h.peer || "unknown"}” · {new Date(h.at * 1000).toLocaleString()}
                    {size > 0 && ` · ${formatBytes(size)}`}
                    {h.error && ` · ${h.error}`}
                  </p>
                </div>
                <span className={`rounded-chip px-2 py-0.5 text-xs font-medium ${RESULT[h.result]}`}>{h.result}</span>
                {first && (
                  <Button variant="ghost" aria-label="Show in folder" onClick={() => void revealItemInDir(first)}>
                    <FolderOpen size={15} aria-hidden />
                  </Button>
                )}
              </li>
            );
          })}
        </ul>
      )}
      <ConfirmDialog
        open={confirm}
        onOpenChange={setConfirm}
        title="Clear history?"
        description="This removes the list only. Received files stay where they are."
        confirmLabel="Clear history"
        onConfirm={async () => {
          await api.clearHistory();
          useApp.setState({ history: [] });
        }}
      />
    </>
  );
}
