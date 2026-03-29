import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Users, MapPin, Terminal, Clock, Wifi } from "lucide-react";
import { useState } from "react";

const threatLevelColor: Record<string, string> = {
  critical: "bg-red-500/20 text-red-400 border-red-500/30",
  high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  low: "bg-blue-500/20 text-blue-400 border-blue-500/30",
};

export default function Attackers() {
  const { data: attackerList } = trpc.attackers.list.useQuery();
  const [selectedId, setSelectedId] = useState<number | null>(null);

  const selected = attackerList?.find((a) => a.id === selectedId);

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Attacker Profiling</h1>
        <p className="text-sm text-muted-foreground mt-1">
          IP、OS、位置情報、実行コマンド履歴、脅威レベルの詳細プロファイル
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Attacker List */}
        <div className="lg:col-span-2">
          <Card className="border-border/50 bg-card/80">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium flex items-center gap-2">
                <Users className="h-4 w-4 text-primary" />
                Tracked Attackers ({attackerList?.length ?? 0})
              </CardTitle>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="text-[10px] ns-mono">ID</TableHead>
                    <TableHead className="text-[10px] ns-mono">IP</TableHead>
                    <TableHead className="text-[10px] ns-mono">Location</TableHead>
                    <TableHead className="text-[10px] ns-mono">OS</TableHead>
                    <TableHead className="text-[10px] ns-mono">Level</TableHead>
                    <TableHead className="text-[10px] ns-mono">Status</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {attackerList?.map((a) => (
                    <TableRow
                      key={a.id}
                      className={`cursor-pointer transition-colors ${selectedId === a.id ? "bg-primary/10" : "hover:bg-muted/30"}`}
                      onClick={() => setSelectedId(a.id)}
                    >
                      <TableCell className="text-xs ns-mono text-primary">{a.attackerId}</TableCell>
                      <TableCell className="text-xs ns-mono">{a.ip}</TableCell>
                      <TableCell className="text-xs">{String(a.city ?? "")}, {String(a.country ?? "")}</TableCell>
                      <TableCell className="text-xs">{String(a.os ?? "").split(" ")[0]}</TableCell>
                      <TableCell>
                        <Badge variant="outline" className={`text-[10px] ns-mono ${threatLevelColor[a.threatLevel]}`}>
                          {a.threatLevel}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center gap-1.5">
                          <div className={`h-1.5 w-1.5 rounded-full ${a.isActive ? "bg-red-400 ns-pulse" : "bg-gray-500"}`} />
                          <span className="text-[10px] ns-mono">{a.isActive ? "ACTIVE" : "INACTIVE"}</span>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </div>

        {/* Detail Panel */}
        <div>
          {selected ? (
            <Card className="border-border/50 bg-card/80 sticky top-4">
              <CardHeader className="pb-3">
                <div className="flex items-center justify-between">
                  <CardTitle className="text-sm font-medium">{selected.attackerId}</CardTitle>
                  <Badge variant="outline" className={`text-[10px] ns-mono ${threatLevelColor[selected.threatLevel]}`}>
                    {selected.threatLevel}
                  </Badge>
                </div>
              </CardHeader>
              <CardContent className="space-y-4">
                {/* IP & ISP */}
                <div className="space-y-2">
                  <div className="flex items-center gap-2 text-xs text-muted-foreground">
                    <Wifi className="h-3.5 w-3.5" />
                    <span className="ns-mono">{selected.ip}</span>
                  </div>
                  <div className="text-xs text-muted-foreground">{String(selected.isp ?? "")}</div>
                </div>

                {/* Location */}
                <div className="p-3 rounded-lg border border-border/30 bg-background/30">
                  <div className="flex items-center gap-2 mb-2">
                    <MapPin className="h-3.5 w-3.5 text-primary" />
                    <span className="text-xs font-medium">Location</span>
                  </div>
                  <div className="text-sm">{String(selected.city ?? "")}, {String(selected.country ?? "")}</div>
                  <div className="text-[10px] ns-mono text-muted-foreground mt-1">
                    {String(selected.lat ?? "")}, {String(selected.lng ?? "")}
                  </div>
                </div>

                {/* OS & Browser */}
                <div className="p-3 rounded-lg border border-border/30 bg-background/30">
                  <div className="text-xs font-medium mb-2">System Info</div>
                  <div className="space-y-1 text-xs text-muted-foreground">
                    <div><span className="text-foreground">OS:</span> {String(selected.os ?? "")}</div>
                    <div><span className="text-foreground">Agent:</span> {String(selected.browser ?? "")}</div>
                  </div>
                </div>

                {/* Command History */}
                <div className="p-3 rounded-lg border border-border/30 bg-background/30">
                  <div className="flex items-center gap-2 mb-2">
                    <Terminal className="h-3.5 w-3.5 text-primary" />
                    <span className="text-xs font-medium">Command History</span>
                  </div>
                  <div className="space-y-1">
                    {(Array.isArray(selected.commandHistory) ? (selected.commandHistory as string[]) : JSON.parse(String(selected.commandHistory || "[]"))).map((cmd: string, i: number) => (
                      <div key={i} className="text-[11px] ns-mono text-muted-foreground p-1 rounded bg-background/50">
                        <span className="text-primary">$</span> {cmd}
                      </div>
                    ))}
                  </div>
                </div>

                {/* Profile Data */}
                {selected.profileData != null && (
                  <div className="p-3 rounded-lg border border-border/30 bg-background/30">
                    <div className="text-xs font-medium mb-2">Threat Profile</div>
                    <div className="space-y-1 text-xs text-muted-foreground">
                      {(() => {
                        const pd = typeof selected.profileData === "string" ? JSON.parse(selected.profileData) : (selected.profileData as Record<string, unknown>);
                        return (
                          <>
                            {pd.group && <div><span className="text-foreground">Group:</span> {String(pd.group)}</div>}
                            {Array.isArray(pd.ttps) && (
                              <div className="flex flex-wrap gap-1 mt-1">
                                {(pd.ttps as string[]).map((t: string) => (
                                  <span key={t} className="text-[10px] ns-mono px-1.5 py-0.5 rounded bg-red-500/10 text-red-400 border border-red-500/20">
                                    {t}
                                  </span>
                                ))}
                              </div>
                            )}
                          </>
                        );
                      })()}
                    </div>
                  </div>
                )}

                {/* Timeline */}
                <div className="flex items-center gap-2 text-[10px] text-muted-foreground">
                  <Clock className="h-3 w-3" />
                  <span>First seen: {new Date(selected.firstSeen).toLocaleString("ja-JP")}</span>
                </div>
              </CardContent>
            </Card>
          ) : (
            <Card className="border-border/50 bg-card/80">
              <CardContent className="p-8 text-center">
                <Users className="h-8 w-8 text-muted-foreground/30 mx-auto mb-3" />
                <p className="text-sm text-muted-foreground">攻撃者を選択してプロファイルを表示</p>
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
}
