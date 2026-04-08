import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Textarea } from "@/components/ui/textarea";
import { Box, Plus, Eye, FileKey, Database, Key, FileText, Shield, Award } from "lucide-react";
import { useState } from "react";
import { useAuth } from "@/_core/hooks/useAuth";

const typeConfig: Record<string, { label: string; icon: typeof FileKey }> = {
  password_file: { label: "Password File", icon: FileKey },
  database: { label: "Database", icon: Database },
  ssh_key: { label: "SSH Key", icon: Key },
  config_file: { label: "Config File", icon: FileText },
  api_key: { label: "API Key", icon: Shield },
  certificate: { label: "Certificate", icon: Award },
};

const statusColor: Record<string, string> = {
  active: "bg-green-500/20 text-green-400 border-green-500/30",
  inactive: "bg-gray-500/20 text-gray-400 border-gray-500/30",
  triggered: "bg-red-500/20 text-red-400 border-red-500/30",
  expired: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
};

export default function DecoyControl() {
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";
  
  const { data: decoyList, refetch } = trpc.decoys.list.useQuery();
  const createDecoy = trpc.decoys.create.useMutation({ onSuccess: () => { refetch(); setOpen(false); } });
  const [open, setOpen] = useState(false);
  const [newDecoy, setNewDecoy] = useState({ type: "password_file" as const, name: "", content: "", vmId: "" });

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Decoy Control — NullHorizon</h1>
          <p className="text-sm text-muted-foreground mt-1">
            偽パスワードファイル、囮DB等の欺瞞データ生成設定
          </p>
        </div>
        {isAdmin && (
        <Dialog open={open} onOpenChange={setOpen}>
          <DialogTrigger asChild>
            <Button size="sm" className="gap-1.5">
              <Plus className="h-3.5 w-3.5" /> New Decoy
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Create New Decoy</DialogTitle>
            </DialogHeader>
            <div className="space-y-4 mt-4">
              <div>
                <label className="text-xs text-muted-foreground mb-1 block">Type</label>
                <Select value={newDecoy.type} onValueChange={(v: string) => setNewDecoy({ ...newDecoy, type: v as typeof newDecoy.type })}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {Object.entries(typeConfig).map(([k, v]) => (
                      <SelectItem key={k} value={k}>{v.label}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div>
                <label className="text-xs text-muted-foreground mb-1 block">Name</label>
                <Input
                  placeholder="/etc/shadow (fake)"
                  value={newDecoy.name}
                  onChange={(e) => setNewDecoy({ ...newDecoy, name: e.target.value })}
                />
              </div>
              <div>
                <label className="text-xs text-muted-foreground mb-1 block">Content (optional)</label>
                <Textarea
                  placeholder="Decoy content..."
                  value={newDecoy.content}
                  onChange={(e) => setNewDecoy({ ...newDecoy, content: e.target.value })}
                  rows={4}
                />
              </div>
              <div>
                <label className="text-xs text-muted-foreground mb-1 block">Assign to VM (optional)</label>
                <Input
                  placeholder="VM-001"
                  value={newDecoy.vmId}
                  onChange={(e) => setNewDecoy({ ...newDecoy, vmId: e.target.value })}
                />
              </div>
              <Button
                className="w-full"
                onClick={() => createDecoy.mutate(newDecoy)}
                disabled={!newDecoy.name || createDecoy.isPending}
              >
                {createDecoy.isPending ? "Creating..." : "Create Decoy"}
              </Button>
            </div>
          </DialogContent>
        </Dialog>
        )}
      </div>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-3">
        {["active", "triggered", "inactive", "expired"].map((s) => {
          const count = decoyList?.filter((d) => d.status === s).length ?? 0;
          return (
            <Card key={s} className="border-border/50 bg-card/80">
              <CardContent className="p-3 text-center">
                <div className="text-xl font-bold ns-mono">{count}</div>
                <div className="text-[10px] text-muted-foreground capitalize">{s}</div>
              </CardContent>
            </Card>
          );
        })}
      </div>

      {/* Decoy Table */}
      <Card className="border-border/50 bg-card/80">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium flex items-center gap-2">
            <Box className="h-4 w-4 text-primary" />
            Deployed Decoys ({decoyList?.length ?? 0})
          </CardTitle>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="text-[10px] ns-mono">ID</TableHead>
                <TableHead className="text-[10px] ns-mono">Type</TableHead>
                <TableHead className="text-[10px] ns-mono">Name</TableHead>
                <TableHead className="text-[10px] ns-mono">Status</TableHead>
                <TableHead className="text-[10px] ns-mono">Access</TableHead>
                <TableHead className="text-[10px] ns-mono">Last Accessed By</TableHead>
                <TableHead className="text-[10px] ns-mono">VM</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {decoyList?.map((d) => {
                const tc = typeConfig[d.type];
                return (
                  <TableRow key={d.id}>
                    <TableCell className="text-xs ns-mono text-primary">{d.decoyId}</TableCell>
                    <TableCell>
                      <Badge variant="outline" className="text-[10px] ns-mono">{tc?.label ?? d.type}</Badge>
                    </TableCell>
                    <TableCell className="text-xs">{d.name}</TableCell>
                    <TableCell>
                      <Badge variant="outline" className={`text-[10px] ns-mono ${statusColor[d.status]}`}>
                        {d.status}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-xs ns-mono">{d.accessCount}</TableCell>
                    <TableCell className="text-xs ns-mono">{d.lastAccessedBy ?? "—"}</TableCell>
                    <TableCell className="text-xs ns-mono">{d.vmId ?? "—"}</TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}
