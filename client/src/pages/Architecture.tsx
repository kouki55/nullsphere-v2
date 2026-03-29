import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Shield, Box, Crosshair, Monitor, ArrowDown, Cpu, HardDrive, Wifi } from "lucide-react";

const componentConfig = [
  {
    key: "engine",
    icon: Shield,
    badge: "KERNEL",
    badgeClass: "bg-purple-500/20 text-purple-400 border-purple-500/30",
    techs: ["eBPF", "kprobe", "tracepoint", "XDP", "C", "libbpf"],
    description: "カーネル空間でシステムコールをフックし、不正なプロセスを即座にKill。本番環境を一切汚染しない。",
  },
  {
    key: "void",
    icon: Box,
    badge: "MICRO-VM",
    badgeClass: "bg-cyan-500/20 text-cyan-400 border-cyan-500/30",
    techs: ["Firecracker", "gVisor", "containerd", "QEMU", "virtio"],
    description: "攻撃者を閉じ込める使い捨て仮想マシン。本番と同一に見えるが完全に隔離された環境。",
  },
  {
    key: "horizon",
    icon: Crosshair,
    badge: "DECEPTION",
    badgeClass: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
    techs: ["Honeypot", "Decoy Generator", "Network Tracer", "GeoIP"],
    description: "偽の機密データを自動生成し、攻撃者を欺瞞。同時にネットワーク逆探知でプロファイリング。",
  },
  {
    key: "controlNode",
    icon: Monitor,
    badge: "CONTROL",
    badgeClass: "bg-green-500/20 text-green-400 border-green-500/30",
    techs: ["React", "tRPC", "Google Maps", "WebSocket", "LLM"],
    description: "CISO/SOC向けのリアルタイム可視化UI。隔離状況とハッカーの正体をマップ上に描画する。",
  },
];

export default function Architecture() {
  const { data: health } = trpc.dashboard.componentHealth.useQuery();
  const { data: vmStats } = trpc.dashboard.stats.useQuery();

  const healthMap = health
    ? { engine: health.engine, void: health.void, horizon: health.horizon, controlNode: health.controlNode }
    : {};

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">System Architecture</h1>
        <p className="text-sm text-muted-foreground mt-1">
          NullSphere V2 — 4-Component Defense Architecture
        </p>
      </div>

      {/* Attacker Entry Point */}
      <div className="text-center">
        <div className="inline-flex items-center gap-2 px-6 py-3 rounded-lg border border-red-500/50 bg-red-500/10">
          <div className="h-2 w-2 rounded-full bg-red-400 ns-pulse" />
          <span className="text-sm font-medium text-red-400">Attacker / Threat Actor</span>
          <span className="text-[10px] ns-mono text-muted-foreground">External Network</span>
        </div>
      </div>

      {/* Flow */}
      <div className="space-y-3">
        {componentConfig.map((comp, idx) => {
          const h = healthMap[comp.key as keyof typeof healthMap];
          return (
            <div key={comp.key}>
              {/* Arrow */}
              <div className="flex flex-col items-center py-1">
                <div className="w-0.5 h-4 bg-muted-foreground/30" />
                <ArrowDown className="h-4 w-4 text-muted-foreground/50" />
              </div>

              {/* Component Card */}
              <Card className="border-border/50 bg-card/80 overflow-hidden">
                <CardHeader className="pb-2 flex flex-row items-center gap-3">
                  <div className={`p-2 rounded-lg ${comp.badgeClass.replace("text-", "bg-").split(" ")[0]}`}>
                    <comp.icon className={`h-5 w-5 ${comp.badgeClass.split(" ")[1]}`} />
                  </div>
                  <div className="flex-1">
                    <div className="flex items-center gap-2">
                      <CardTitle className="text-base">{h?.name ?? comp.key}</CardTitle>
                      <Badge variant="outline" className={`text-[10px] ns-mono ${comp.badgeClass}`}>
                        {comp.badge}
                      </Badge>
                    </div>
                    {h && (
                      <div className="flex items-center gap-1.5 mt-1">
                        <div className={`h-1.5 w-1.5 rounded-full ${h.status === "operational" ? "bg-green-400" : "bg-yellow-400"} ns-pulse`} />
                        <span className="text-[10px] ns-mono text-muted-foreground">{h.status} · uptime {h.uptime}%</span>
                      </div>
                    )}
                  </div>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                      <div className="text-[10px] ns-mono text-muted-foreground uppercase tracking-wider mb-2">Technologies</div>
                      <div className="flex flex-wrap gap-1.5">
                        {comp.techs.map((t) => (
                          <span key={t} className="text-[11px] ns-mono px-2 py-0.5 rounded border border-border/50 bg-background/50 text-muted-foreground">
                            {t}
                          </span>
                        ))}
                      </div>
                    </div>
                    <div>
                      <div className="text-[10px] ns-mono text-muted-foreground uppercase tracking-wider mb-2">Role</div>
                      <p className="text-sm text-muted-foreground leading-relaxed">{comp.description}</p>
                    </div>
                  </div>

                  {/* VM stats for The Void */}
                  {comp.key === "void" && vmStats && (
                    <div className="mt-4 grid grid-cols-3 gap-3">
                      <div className="p-2 rounded border border-border/30 bg-background/30 text-center">
                        <Cpu className="h-4 w-4 mx-auto text-cyan-400 mb-1" />
                        <div className="text-lg font-bold ns-mono">{vmStats.vms?.running ?? 0}/{vmStats.vms?.total ?? 0}</div>
                        <div className="text-[10px] text-muted-foreground">VMs Running</div>
                      </div>
                      <div className="p-2 rounded border border-border/30 bg-background/30 text-center">
                        <HardDrive className="h-4 w-4 mx-auto text-purple-400 mb-1" />
                        <div className="text-lg font-bold ns-mono">{Math.round(vmStats.vms?.avgCpu ?? 0)}%</div>
                        <div className="text-[10px] text-muted-foreground">Avg CPU</div>
                      </div>
                      <div className="p-2 rounded border border-border/30 bg-background/30 text-center">
                        <Wifi className="h-4 w-4 mx-auto text-green-400 mb-1" />
                        <div className="text-lg font-bold ns-mono">{Math.round(vmStats.vms?.avgMemory ?? 0)}%</div>
                        <div className="text-[10px] text-muted-foreground">Avg Memory</div>
                      </div>
                    </div>
                  )}
                </CardContent>
              </Card>
            </div>
          );
        })}
      </div>
    </div>
  );
}
