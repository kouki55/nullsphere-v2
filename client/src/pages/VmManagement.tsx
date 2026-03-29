import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Server, Play, Square, Cpu, HardDrive, Wifi, Clock } from "lucide-react";

const statusConfig: Record<string, { color: string; label: string }> = {
  running: { color: "bg-green-500/20 text-green-400 border-green-500/30", label: "Running" },
  stopped: { color: "bg-gray-500/20 text-gray-400 border-gray-500/30", label: "Stopped" },
  spawning: { color: "bg-cyan-500/20 text-cyan-400 border-cyan-500/30", label: "Spawning" },
  destroying: { color: "bg-red-500/20 text-red-400 border-red-500/30", label: "Destroying" },
  error: { color: "bg-red-500/20 text-red-400 border-red-500/30", label: "Error" },
};

function formatUptime(seconds: number): string {
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  return `${h}h ${m}m`;
}

export default function VmManagement() {
  const { data: vmList, refetch } = trpc.vms.list.useQuery();
  const updateStatus = trpc.vms.updateStatus.useMutation({ onSuccess: () => refetch() });

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">VM Management — The Void</h1>
        <p className="text-sm text-muted-foreground mt-1">
          アクティブなMicro-VMの起動・停止・リソース使用状況を管理
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {vmList?.map((vm) => {
          const sc = statusConfig[vm.status] ?? statusConfig.error;
          return (
            <Card key={vm.id} className="border-border/50 bg-card/80">
              <CardHeader className="pb-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Server className={`h-4 w-4 ${vm.status === "running" ? "text-green-400" : "text-muted-foreground"}`} />
                    <CardTitle className="text-sm">{vm.name}</CardTitle>
                  </div>
                  <Badge variant="outline" className={`text-[10px] ns-mono ${sc.color}`}>
                    {sc.label}
                  </Badge>
                </div>
                <div className="text-[10px] ns-mono text-muted-foreground">{vm.vmId}</div>
              </CardHeader>
              <CardContent className="space-y-3">
                {/* Resource Usage */}
                <div className="space-y-2">
                  <div className="flex items-center justify-between text-xs">
                    <div className="flex items-center gap-1.5 text-muted-foreground">
                      <Cpu className="h-3 w-3" /> CPU
                    </div>
                    <span className="ns-mono">{vm.cpuUsage}%</span>
                  </div>
                  <Progress value={vm.cpuUsage ?? 0} className="h-1.5" />

                  <div className="flex items-center justify-between text-xs">
                    <div className="flex items-center gap-1.5 text-muted-foreground">
                      <HardDrive className="h-3 w-3" /> Memory
                    </div>
                    <span className="ns-mono">{vm.memoryUsage}%</span>
                  </div>
                  <Progress value={vm.memoryUsage ?? 0} className="h-1.5" />

                  <div className="flex items-center justify-between text-xs">
                    <div className="flex items-center gap-1.5 text-muted-foreground">
                      <HardDrive className="h-3 w-3" /> Disk
                    </div>
                    <span className="ns-mono">{vm.diskUsage}%</span>
                  </div>
                  <Progress value={vm.diskUsage ?? 0} className="h-1.5" />
                </div>

                {/* Network */}
                <div className="flex items-center gap-4 text-[10px] ns-mono text-muted-foreground">
                  <div className="flex items-center gap-1">
                    <Wifi className="h-3 w-3 text-green-400" />
                    <span>IN: {vm.networkIn} KB/s</span>
                  </div>
                  <div className="flex items-center gap-1">
                    <Wifi className="h-3 w-3 text-red-400" />
                    <span>OUT: {vm.networkOut} KB/s</span>
                  </div>
                </div>

                {/* Assigned Threat */}
                {vm.assignedThreatId && (
                  <div className="p-2 rounded border border-border/30 bg-background/30 text-[11px]">
                    <span className="text-muted-foreground">Threat: </span>
                    <span className="ns-mono text-primary">{vm.assignedThreatId}</span>
                    {vm.attackerIp && (
                      <>
                        <span className="text-muted-foreground"> · Attacker: </span>
                        <span className="ns-mono">{vm.attackerIp}</span>
                      </>
                    )}
                  </div>
                )}

                {/* Uptime */}
                <div className="flex items-center gap-1.5 text-[10px] text-muted-foreground">
                  <Clock className="h-3 w-3" />
                  <span>Uptime: {formatUptime(vm.uptime ?? 0)}</span>
                </div>

                {/* Controls */}
                <div className="flex gap-2">
                  {vm.status === "stopped" ? (
                    <Button
                      size="sm"
                      variant="outline"
                      className="flex-1 h-8 text-xs gap-1.5 text-green-400 border-green-500/30 hover:bg-green-500/10"
                      onClick={() => updateStatus.mutate({ id: vm.id, status: "running" })}
                      disabled={updateStatus.isPending}
                    >
                      <Play className="h-3 w-3" /> Start
                    </Button>
                  ) : vm.status === "running" ? (
                    <Button
                      size="sm"
                      variant="outline"
                      className="flex-1 h-8 text-xs gap-1.5 text-red-400 border-red-500/30 hover:bg-red-500/10"
                      onClick={() => updateStatus.mutate({ id: vm.id, status: "stopped" })}
                      disabled={updateStatus.isPending}
                    >
                      <Square className="h-3 w-3" /> Stop
                    </Button>
                  ) : null}
                </div>
              </CardContent>
            </Card>
          );
        })}
      </div>
    </div>
  );
}
