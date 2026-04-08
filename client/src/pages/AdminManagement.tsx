import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { AlertCircle, Shield, User } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";
import { trpc } from "@/lib/trpc";
import { useAuth } from "@/_core/hooks/useAuth";

export default function AdminManagement() {
  const { user: currentUser } = useAuth();
  const isAdmin = currentUser?.role === "admin";

  const { data: users, refetch, isLoading, error } = trpc.admin.listUsers.useQuery(undefined, {
    enabled: isAdmin,
  });
  const promoteUser = trpc.admin.promoteUser.useMutation({ onSuccess: () => refetch() });
  const demoteUser = trpc.admin.demoteUser.useMutation({ onSuccess: () => refetch() });

  const [selectedUserId, setSelectedUserId] = useState<number | null>(null);
  const [confirmAction, setConfirmAction] = useState<{
    userId: number;
    action: "promote" | "demote";
    userName: string;
  } | null>(null);

  const handlePromote = async (userId: number) => {
    try {
      await promoteUser.mutateAsync({ userId });
      toast.success("User promoted to admin");
      setConfirmAction(null);
    } catch (error: any) {
      toast.error(error.message || "Failed to promote user");
    }
  };

  const handleDemote = async (userId: number) => {
    try {
      await demoteUser.mutateAsync({ userId });
      toast.success("User demoted to regular user");
      setConfirmAction(null);
    } catch (error: any) {
      toast.error(error.message || "Failed to demote user");
    }
  };

  // 非admin ユーザーのアクセスを制限
  if (!isAdmin) {
    return (
      <div className="space-y-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Admin Management</h1>
          <p className="text-sm text-muted-foreground mt-1">
            ユーザーの権限を管理し、管理者権限を付与・取り消し
          </p>
        </div>
        <Card className="border-red-500/30 bg-red-500/10">
          <CardContent className="pt-6">
            <div className="flex gap-3">
              <AlertCircle className="h-5 w-5 text-red-400 flex-shrink-0 mt-0.5" />
              <div>
                <p className="font-medium text-red-400">Access Denied</p>
                <p className="text-sm text-red-400/80 mt-1">
                  This page is only accessible to administrators.
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    );
  }

  // ローディング状態
  if (isLoading) {
    return (
      <div className="space-y-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Admin Management</h1>
          <p className="text-sm text-muted-foreground mt-1">
            ユーザーの権限を管理し、管理者権限を付与・取り消し
          </p>
        </div>
        <Card className="border-border/50 bg-card/80">
          <CardContent className="pt-6">
            <div className="flex items-center justify-center h-32">
              <div className="flex flex-col items-center gap-2">
                <div className="h-6 w-6 border-2 border-primary border-t-transparent rounded-full animate-spin" />
                <span className="text-xs text-muted-foreground ns-mono">LOADING...</span>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    );
  }

  // エラー状態
  if (error) {
    return (
      <div className="space-y-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Admin Management</h1>
          <p className="text-sm text-muted-foreground mt-1">
            ユーザーの権限を管理し、管理者権限を付与・取り消し
          </p>
        </div>
        <Card className="border-red-500/30 bg-red-500/10">
          <CardContent className="pt-6">
            <div className="flex gap-3">
              <AlertCircle className="h-5 w-5 text-red-400 flex-shrink-0 mt-0.5" />
              <div>
                <p className="font-medium text-red-400">Error Loading Users</p>
                <p className="text-sm text-red-400/80 mt-1">
                  {error.message || "Failed to load user list"}
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Admin Management</h1>
        <p className="text-sm text-muted-foreground mt-1">
          ユーザーの権限を管理し、管理者権限を付与・取り消し
        </p>
      </div>

      <Card className="border-border/50 bg-card/80">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium flex items-center gap-2">
            <Shield className="h-4 w-4 text-primary" />
            User List ({users?.length ?? 0})
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="text-[10px] ns-mono">ID</TableHead>
                  <TableHead className="text-[10px] ns-mono">Name</TableHead>
                  <TableHead className="text-[10px] ns-mono">Email</TableHead>
                  <TableHead className="text-[10px] ns-mono">Role</TableHead>
                  <TableHead className="text-[10px] ns-mono">Last Signed In</TableHead>
                  <TableHead className="text-[10px] ns-mono">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {users?.map((u) => {
                  const isCurrentUser = u.id === currentUser?.id;
                  const isUserAdmin = u.role === "admin";

                  return (
                    <TableRow key={u.id}>
                      <TableCell className="text-xs ns-mono text-primary">{u.id}</TableCell>
                      <TableCell className="text-xs">{u.name}</TableCell>
                      <TableCell className="text-xs text-muted-foreground">{u.email}</TableCell>
                      <TableCell>
                        <div className={`inline-flex items-center gap-1 px-2 py-1 rounded text-[10px] font-medium ${
                          isUserAdmin
                            ? "bg-red-500/20 text-red-400 border border-red-500/30"
                            : "bg-blue-500/20 text-blue-400 border border-blue-500/30"
                        }`}>
                          {isUserAdmin ? <Shield className="h-3 w-3" /> : <User className="h-3 w-3" />}
                          {isUserAdmin ? "Admin" : "User"}
                        </div>
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">
                        {u.lastSignedIn ? new Date(u.lastSignedIn).toLocaleString() : "Never"}
                      </TableCell>
                      <TableCell>
                        <div className="flex gap-2">
                          {isCurrentUser ? (
                            <span className="text-[10px] text-muted-foreground italic">You</span>
                          ) : (
                            <>
                              {isUserAdmin ? (
                                <Dialog>
                                  <DialogTrigger asChild>
                                    <Button
                                      size="sm"
                                      variant="outline"
                                      className="h-6 text-[10px] text-yellow-400 border-yellow-500/30 hover:bg-yellow-500/10"
                                      onClick={() =>
                                        setConfirmAction({
                                          userId: u.id,
                                          action: "demote",
                                          userName: u.name || `User ${u.id}`,
                                        })
                                      }
                                    >
                                      Demote
                                    </Button>
                                  </DialogTrigger>
                                  <DialogContent>
                                    <DialogHeader>
                                      <DialogTitle>Confirm Demotion</DialogTitle>
                                    </DialogHeader>
                                    <div className="space-y-4">
                                      <div className="flex gap-2 p-3 rounded bg-yellow-500/10 border border-yellow-500/30">
                                        <AlertCircle className="h-4 w-4 text-yellow-400 flex-shrink-0 mt-0.5" />
                                        <p className="text-sm text-yellow-400">
                                          Are you sure you want to demote <strong>{u.name}</strong> from admin to regular user?
                                        </p>
                                      </div>
                                      <div className="flex gap-2 justify-end">
                                        <Button
                                          variant="outline"
                                          onClick={() => setConfirmAction(null)}
                                        >
                                          Cancel
                                        </Button>
                                        <Button
                                          variant="destructive"
                                          onClick={() => handleDemote(u.id)}
                                          disabled={demoteUser.isPending}
                                        >
                                          {demoteUser.isPending ? "Demoting..." : "Demote"}
                                        </Button>
                                      </div>
                                    </div>
                                  </DialogContent>
                                </Dialog>
                              ) : (
                                <Dialog>
                                  <DialogTrigger asChild>
                                    <Button
                                      size="sm"
                                      variant="outline"
                                      className="h-6 text-[10px] text-green-400 border-green-500/30 hover:bg-green-500/10"
                                      onClick={() =>
                                        setConfirmAction({
                                          userId: u.id,
                                          action: "promote",
                                          userName: u.name || `User ${u.id}`,
                                        })
                                      }
                                    >
                                      Promote
                                    </Button>
                                  </DialogTrigger>
                                  <DialogContent>
                                    <DialogHeader>
                                      <DialogTitle>Confirm Promotion</DialogTitle>
                                    </DialogHeader>
                                    <div className="space-y-4">
                                      <div className="flex gap-2 p-3 rounded bg-green-500/10 border border-green-500/30">
                                        <AlertCircle className="h-4 w-4 text-green-400 flex-shrink-0 mt-0.5" />
                                        <p className="text-sm text-green-400">
                                          Are you sure you want to promote <strong>{u.name}</strong> to admin? They will have access to all admin features.
                                        </p>
                                      </div>
                                      <div className="flex gap-2 justify-end">
                                        <Button
                                          variant="outline"
                                          onClick={() => setConfirmAction(null)}
                                        >
                                          Cancel
                                        </Button>
                                        <Button
                                          className="bg-green-600 hover:bg-green-700"
                                          onClick={() => handlePromote(u.id)}
                                          disabled={promoteUser.isPending}
                                        >
                                          {promoteUser.isPending ? "Promoting..." : "Promote"}
                                        </Button>
                                      </div>
                                    </div>
                                  </DialogContent>
                                </Dialog>
                              )}
                            </>
                          )}
                        </div>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
