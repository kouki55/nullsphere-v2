import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ScrollText, Filter } from "lucide-react";
import { useState } from "react";

const typeConfig: Record<string, { label: string; color: string }> = {
  ebpf_hook: { label: "eBPF Hook", color: "bg-purple-500/20 text-purple-400 border-purple-500/30" },
  vm_transfer: { label: "VM Transfer", color: "bg-cyan-500/20 text-cyan-400 border-cyan-500/30" },
  decoy_access: { label: "Decoy Access", color: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30" },
  block: { label: "Block", color: "bg-red-500/20 text-red-400 border-red-500/30" },
  alert: { label: "Alert", color: "bg-orange-500/20 text-orange-400 border-orange-500/30" },
  system: { label: "System", color: "bg-green-500/20 text-green-400 border-green-500/30" },
  trace: { label: "Trace", color: "bg-blue-500/20 text-blue-400 border-blue-500/30" },
};

const severityIcon: Record<string, string> = {
  critical: "border-l-red-500",
  high: "border-l-orange-500",
  medium: "border-l-yellow-500",
  low: "border-l-blue-500",
  info: "border-l-green-500",
};

type EventType = "ebpf_hook" | "vm_transfer" | "decoy_access" | "block" | "alert" | "system" | "trace";

export default function Events() {
  const [filter, setFilter] = useState<EventType | undefined>(undefined);
  const { data: eventList } = trpc.events.list.useQuery(filter ? { type: filter, limit: 50 } : { limit: 50 });

  const filterTypes: (EventType | undefined)[] = [undefined, "ebpf_hook", "vm_transfer", "decoy_access", "block", "alert", "system", "trace"];

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Event Log Viewer</h1>
          <p className="text-sm text-muted-foreground mt-1">
            eBPFフック、VM転送、デコイアクセス等のセキュリティイベントをリアルタイム表示
          </p>
        </div>
        <div className="flex items-center gap-1.5">
          <div className="h-2 w-2 rounded-full bg-green-400 ns-pulse" />
          <span className="text-[10px] ns-mono text-muted-foreground">LIVE</span>
        </div>
      </div>

      {/* Filters */}
      <div className="flex items-center gap-2 flex-wrap">
        <Filter className="h-4 w-4 text-muted-foreground" />
        {filterTypes.map((t) => (
          <Button
            key={t ?? "all"}
            variant={filter === t ? "default" : "outline"}
            size="sm"
            className="h-7 text-[11px] ns-mono"
            onClick={() => setFilter(t)}
          >
            {t ? typeConfig[t]?.label : "All"}
          </Button>
        ))}
      </div>

      {/* Event Stream */}
      <Card className="border-border/50 bg-card/80">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium flex items-center gap-2">
            <ScrollText className="h-4 w-4 text-primary" />
            Security Events ({eventList?.length ?? 0})
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-1">
            {eventList?.map((e) => {
              const tc = typeConfig[e.type];
              return (
                <div
                  key={e.id}
                  className={`p-3 rounded-lg border border-border/30 bg-background/30 border-l-2 ${severityIcon[e.severity] ?? "border-l-gray-500"} hover:bg-background/60 transition-colors`}
                >
                  <div className="flex items-start gap-3">
                    <div className="flex flex-col items-center gap-1 shrink-0 pt-0.5">
                      <Badge variant="outline" className={`text-[9px] ns-mono ${tc?.color ?? ""}`}>
                        {tc?.label ?? e.type}
                      </Badge>
                      <Badge variant="outline" className="text-[9px] ns-mono">
                        {e.severity}
                      </Badge>
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="text-sm leading-relaxed">{e.message}</p>
                      <div className="flex items-center gap-3 mt-1.5 text-[10px] text-muted-foreground ns-mono">
                        <span>{e.source}</span>
                        {e.threatId && <span className="text-primary">{e.threatId}</span>}
                        <span>{new Date(e.createdAt).toLocaleString("ja-JP")}</span>
                      </div>
                      {e.details != null && (
                        <details className="mt-2">
                          <summary className="text-[10px] text-muted-foreground cursor-pointer hover:text-foreground ns-mono">
                            Details
                          </summary>
                          <pre className="mt-1 p-2 rounded bg-background/80 border border-border/30 text-[10px] ns-mono text-muted-foreground overflow-x-auto">
                            {JSON.stringify(typeof e.details === "string" ? JSON.parse(e.details as string) : e.details, null, 2)}
                          </pre>
                        </details>
                      )}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
