"use client";

import { Ban, BellOff, Lock, ShieldCheck, ShieldOff } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { post, type ActionOption } from "@/lib/api";

const ICONS: Record<string, React.ComponentType<{ className?: string }>> = {
  quarantine_device: ShieldOff,
  block_domain: Ban,
  block_ip: Ban,
  trust_device: ShieldCheck,
  snooze: BellOff,
};

/**
 * M5 response actions. Dry run only: the confirm dialog shows the exact command that would run,
 * and confirming just records the request on the Pi. Nothing is executed.
 */
export function ActionButtons({ alertId, actions, onRequested }: { alertId: number; actions: ActionOption[]; onRequested?: () => void }) {
  const [selected, setSelected] = useState<ActionOption | null>(null);
  const [busy, setBusy] = useState(false);

  async function confirm() {
    if (!selected) return;
    setBusy(true);
    try {
      await post(`/api/alerts/${alertId}/actions`, { action: selected.action });
      toast.info(`${selected.label}: recorded`, { description: "Dry run: nothing executed." });
      onRequested?.();
      setSelected(null);
    } catch (e) {
      toast.error("Could not record the request", { description: e instanceof Error ? e.message : String(e) });
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <div className="flex flex-wrap gap-2">
        {actions.map((a) => {
          const Icon = ICONS[a.action] ?? Lock;
          return (
            <Button
              key={a.action}
              variant={a.action === "quarantine_device" ? "destructive" : "outline"}
              size="sm"
              onClick={() => setSelected(a)}
            >
              <Icon className="size-4" />
              {a.label}
            </Button>
          );
        })}
      </div>

      <Dialog open={!!selected} onOpenChange={(o) => !o && setSelected(null)}>
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>{selected?.label}</DialogTitle>
            <DialogDescription>
              Target: <span className="font-mono">{selected?.target}</span>. Dry run: command not executed.
            </DialogDescription>
          </DialogHeader>
          <pre className="overflow-x-auto rounded-md bg-muted p-3 font-mono text-xs leading-relaxed">{selected?.command_preview}</pre>
          <DialogFooter>
            <DialogClose asChild>
              <Button variant="ghost">Cancel</Button>
            </DialogClose>
            <Button onClick={confirm} disabled={busy}>
              Record (dry run)
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
