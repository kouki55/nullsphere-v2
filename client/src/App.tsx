import { Toaster } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import NotFound from "@/pages/NotFound";
import { Route, Switch } from "wouter";
import ErrorBoundary from "./components/ErrorBoundary";
import DashboardLayout from "./components/DashboardLayout";
import { ThemeProvider } from "./contexts/ThemeContext";
import { lazy, Suspense } from "react";
import { SocketProvider } from "./_core/hooks/useSocket";

const Dashboard = lazy(() => import("./pages/Dashboard"));
const Architecture = lazy(() => import("./pages/Architecture"));
const DataFlow = lazy(() => import("./pages/DataFlow"));
const ThreatMap = lazy(() => import("./pages/ThreatMap"));
const Attackers = lazy(() => import("./pages/Attackers"));
const Events = lazy(() => import("./pages/Events"));
const VmManagement = lazy(() => import("./pages/VmManagement"));
const DecoyControl = lazy(() => import("./pages/DecoyControl"));
const Notifications = lazy(() => import("./pages/Notifications"));
const Analysis = lazy(() => import("./pages/Analysis"));
const AdminManagement = lazy(() => import("./pages/AdminManagement"));
const AuditLog = lazy(() => import("./pages/AuditLog"));
const AuditLogEnhanced = lazy(() => import("./pages/AuditLogEnhanced"));
const PermissionRequest = lazy(() => import("./pages/PermissionRequest"));
const PermissionRequestAdmin = lazy(() => import("./pages/PermissionRequestAdmin"));
const AuditLogExport = lazy(() => import("./pages/AuditLogExport"));

function PageLoader() {
  return (
    <div className="flex items-center justify-center h-64">
      <div className="flex flex-col items-center gap-3">
        <div className="h-8 w-8 border-2 border-primary border-t-transparent rounded-full animate-spin" />
        <span className="text-xs text-muted-foreground ns-mono">LOADING MODULE...</span>
      </div>
    </div>
  );
}

function Router() {
  return (
    <DashboardLayout>
      <Suspense fallback={<PageLoader />}>
        <Switch>
          <Route path="/" component={Dashboard} />
          <Route path="/architecture" component={Architecture} />
          <Route path="/dataflow" component={DataFlow} />
          <Route path="/threat-map" component={ThreatMap} />
          <Route path="/attackers" component={Attackers} />
          <Route path="/events" component={Events} />
          <Route path="/vms" component={VmManagement} />
          <Route path="/decoys" component={DecoyControl} />
          <Route path="/notifications" component={Notifications} />
          <Route path="/analysis" component={Analysis} />
          <Route path="/admin" component={AdminManagement} />
          <Route path="/audit" component={AuditLog} />
          <Route path="/permission-request" component={PermissionRequest} />
          <Route path="/permission-request-admin" component={PermissionRequestAdmin} />
          <Route path="/audit-export" component={AuditLogExport} />
          <Route path="/404" component={NotFound} />
          <Route component={NotFound} />
        </Switch>
      </Suspense>
    </DashboardLayout>
  );
}

function App() {
  return (
    <ErrorBoundary>
      <ThemeProvider defaultTheme="dark">
        <SocketProvider>
          <TooltipProvider>
            <Toaster />
            <Router />
          </TooltipProvider>
        </SocketProvider>
      </ThemeProvider>
    </ErrorBoundary>
  );
}

export default App;
