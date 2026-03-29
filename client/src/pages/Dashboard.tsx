import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  Shield,
  AlertTriangle,
  Server,
  Eye,
  Box,
  Bell,
  Activity,
  Zap,
} from "lucide-react";

const severityColor: Record<string, string> = {
  critical: "bg-red-500/20 text-red-400 border-red-500/30",
  high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  low: "bg-blue-500/20 text-blue-400 border-blue-500/30",
};

const statusColor: Record<string, string> = {
  detected: "bg-red-500/20 text-red-400",
  blocked: "bg-orange-500/20 text-orange-400",
  isolated: "bg-purple-500/20 text-purple-400",
  deceived: "bg-yellow-500/20 text-yellow-400",
  traced: "bg-cyan-500/20 text-cyan-400",
  resolved: "bg-green-500/20 text-green-400",
};

export default function Dashboard() {
  const { data: stats } = trpc.dashboard.stats.useQuery();
  const { data: health } = trpc.dashboard.componentHealth.useQuery();
  const { data: recentThreats } = trpc.threats.list.useQuery();
  const { data: recentEvents } = trpc.events.list.useQuery({ limit: 8 });

  const statCards = [
    {
      label: "Active Threats",
      value: stats?.threats?.active ?? 0,
      icon: AlertTriangle,
      color: "text-red-400",
      bg: "bg-red-500/10",
    },
    {
      label: "Blocked",
      value: stats?.threats?.blocked ?? 0,
      icon: Shield,
      color: "text-ns-cyan",
      bg: "bg-cyan-500/10",
    },
    {
      label: "Isolated VMs",
      value: stats?.vms?.running ?? 0,
      icon: Server,
      color: "text-ns-purple",
      bg: "bg-purple-500/10",
    },
    {
      label: "Active Decoys",
      value: stats?.decoys?.active ?? 0,
      icon: Eye,
      color: "text-ns-green",
      bg: "bg-green-500/10",
    },
    {
      label: "Attackers Tracked",
      value: stats?.attackers?.active ?? 0,
      icon: Zap,
      color: "text-ns-yellow",
      bg: "bg-yellow-500/10",
    },
    {
      label: "Unread Alerts",
      value: stats?.unreadNotifications ?? 0,
      icon: Bell,
      color: "text-orange-400",
      bg: "bg-orange-500/10",
    },
  ];

  const components = health
    ? [health.engine, health.void, health.horizon, health.controlNode]
    : [];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">
            Threat Detection Dashboard
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            NullSphere V2 — Real-time Security Operations Center
          </p>
        </div>
        <div className="flex items-center gap-2">
          <div className="h-2 w-2 rounded-full bg-green-400 ns-pulse" />
          <span className="text-xs text-muted-foreground ns-mono">
            SYSTEM OPERATIONAL
          </span>
        </div>
      </div>

      {/* Stat Cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
        {statCards.map((s) => (
          <Card
            key={s.label}
            className="border-border/50 bg-card/80 backdrop-blur"
          >
            <CardContent className="p-4">
              <div className="flex items-center justify-between mb-2">
                <div className={`p-2 rounded-lg ${s.bg}`}>
                  <s.icon className={`h-4 w-4 ${s.color}`} />
                </div>
              </div>
              <div className="text-2xl font-bold ns-mono">{s.value}</div>
              <div className="text-[11px] text-muted-foreground mt-1">
                {s.label}
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Component Health */}
      <Card className="border-border/50 bg-card/80">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium flex items-center gap-2">
            <Activity className="h-4 w-4 text-primary" />
            System Components
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
            {components.map((c) => (
              <div
                key={c.name}
                className="p-3 rounded-lg border border-border/50 bg-background/50"
              >
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm font-medium">{c.name}</span>
                  <div className="flex items-center gap-1.5">
                    <div
                      className={`h-2 w-2 rounded-full ${c.status === "operational" ? "bg-green-400" : "bg-yellow-400"} ns-pulse`}
                    />
                    <span className="text-[10px] ns-mono text-muted-foreground uppercase">
                      {c.status}
                    </span>
                  </div>
                </div>
                <p className="text-xs text-muted-foreground">
                  {c.description}
                </p>
                <div className="mt-2 flex items-center gap-1">
                  <div className="flex-1 h-1 rounded-full bg-muted overflow-hidden">
                    <div
                      className="h-full bg-green-400 rounded-full"
                      style={{ width: `${c.uptime}%` }}
                    />
                  </div>
                  <span className="text-[10px] ns-mono text-muted-foreground">
                    {c.uptime}%
                  </span>
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Recent Threats */}
        <Card className="border-border/50 bg-card/80">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-red-400" />
              Recent Threats
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {recentThreats?.slice(0, 6).map((t) => (
                <div
                  key={t.id}
                  className="flex items-center gap-3 p-2.5 rounded-lg border border-border/30 bg-background/30 hover:bg-background/60 transition-colors"
                >
                  <Badge
                    variant="outline"
                    className={`text-[10px] ns-mono ${severityColor[t.severity]}`}
                  >
                    {t.severity}
                  </Badge>
                  <div className="flex-1 min-w-0">
                    <div className="text-sm truncate">{t.description?.slice(0, 60)}...</div>
                    <div className="text-[10px] text-muted-foreground ns-mono mt-0.5">
                      {t.sourceIp} → {t.targetHost}
                    </div>
                  </div>
                  <Badge
                    variant="outline"
                    className={`text-[10px] ${statusColor[t.status]}`}
                  >
                    {t.status}
                  </Badge>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        {/* Recent Events */}
        <Card className="border-border/50 bg-card/80">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <ScrollIcon className="h-4 w-4 text-primary" />
              Event Stream
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {recentEvents?.slice(0, 6).map((e) => (
                <div
                  key={e.id}
                  className="flex items-start gap-3 p-2.5 rounded-lg border border-border/30 bg-background/30"
                >
                  <Badge
                    variant="outline"
                    className={`text-[10px] ns-mono shrink-0 ${severityColor[e.severity] ?? "bg-blue-500/20 text-blue-400"}`}
                  >
                    {e.type}
                  </Badge>
                  <div className="flex-1 min-w-0">
                    <div className="text-sm leading-snug">{e.message.slice(0, 80)}...</div>
                    <div className="text-[10px] text-muted-foreground ns-mono mt-1">
                      {e.source} · {new Date(e.createdAt).toLocaleTimeString("ja-JP")}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

function ScrollIcon(props: React.SVGProps<SVGSVGElement>) {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      width="24"
      height="24"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      {...props}
    >
      <path d="M8 21h12a2 2 0 0 0 2-2v-2H10v2a2 2 0 1 1-4 0V5a2 2 0 1 0-4 0v3h4" />
      <path d="M19 17V5a2 2 0 0 0-2-2H4" />
    </svg>
  );
}
