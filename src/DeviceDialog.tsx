import { useEffect, useState } from "react";
import { AlertDialog } from "radix-ui";
import { Smartphone } from "lucide-react";
import { api } from "./api";
import { useApp } from "./store";
import { Button } from "./components/ui/Button";

const TIMEOUT_S = 120;

/** "Allow this device?" Deny has the initial focus. */
export function DeviceDialog() {
  const pending = useApp((s) => s.view?.devices.find((d) => d.status === "pending"));
  const [left, setLeft] = useState(TIMEOUT_S);
  useEffect(() => {
    if (!pending) return;
    setLeft(TIMEOUT_S);
    const t = setInterval(() => setLeft((n) => Math.max(0, n - 1)), 1000);
    return () => clearInterval(t);
  }, [pending?.id]);
  if (!pending) return null;

  const answer = (allow: boolean) => void api.decide(pending.id, allow);

  return (
    // Controlled: the dialog closes when the device stops being pending, and
    // each button sends exactly one answer.
    <AlertDialog.Root open>
      <AlertDialog.Portal>
        <AlertDialog.Overlay className="fixed inset-0 z-40 bg-black/45" />
        <AlertDialog.Content onEscapeKeyDown={() => answer(false)} className="animate-pop fixed left-1/2 top-1/2 z-50 w-[min(440px,92vw)] -translate-x-1/2 -translate-y-1/2 rounded-panel bg-raised p-5 shadow-pop">
          <div className="flex items-start gap-3">
            <div className="grid size-10 shrink-0 place-items-center rounded-full bg-accent-soft text-accent">
              <Smartphone size={20} aria-hidden />
            </div>
            <div>
              <AlertDialog.Title className="text-base font-semibold">Allow this {pending.label}?</AlertDialog.Title>
              <AlertDialog.Description className="mt-1 text-muted">
                A device at <span className="font-mono text-text" data-selectable>{pending.ip}</span> scanned your code. Once allowed, it can send you files and
                download what you share until sharing stops.
              </AlertDialog.Description>
            </div>
          </div>
          <p className="mt-3 text-xs text-faint">Only allow a device you can see in front of you. If you don't recognise it, deny it.</p>
          <div className="mt-5 flex items-center gap-2">
            <span className="flex-1 text-xs text-faint">Denied automatically in {left}s</span>
            <AlertDialog.Cancel asChild>
              <Button onClick={() => answer(false)}>Deny</Button>
            </AlertDialog.Cancel>
            <AlertDialog.Action asChild>
              <Button variant="primary" onClick={() => answer(true)}>
                Allow
              </Button>
            </AlertDialog.Action>
          </div>
        </AlertDialog.Content>
      </AlertDialog.Portal>
    </AlertDialog.Root>
  );
}
