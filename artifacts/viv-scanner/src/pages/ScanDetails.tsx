import { useEffect, useState } from "react";
import { useParams, Link } from "wouter";
import { 
  useGetFirmware, getGetFirmwareQueryKey,
  useGetScanResults, getGetScanResultsQueryKey,
  useGetExtractedFiles, getGetExtractedFilesQueryKey,
  useGetCveMatches, getGetCveMatchesQueryKey
} from "@workspace/api-client-react";
import type { ScanResult } from "@workspace/api-client-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Search, ChevronLeft, File, Folder, HardDrive, ShieldAlert, Cpu, Hash, Clock, Bug, Fingerprint, FileText, ExternalLink, Loader2 } from "lucide-react";
import { motion } from "framer-motion";
import { Button } from "@/components/ui/button";
import { useQueryClient } from "@tanstack/react-query";

const POLL_INTERVAL_MS = 3000;

export default function ScanDetails() {
  const params = useParams();
  const firmwareId = parseInt(params.firmwareId || "0", 10);

  const queryClient = useQueryClient();
  const [showDebug, setShowDebug] = useState(false);

  const { data: firmware, isLoading: loadingFw } = useGetFirmware(firmwareId, {
    query: { enabled: !!firmwareId, queryKey: getGetFirmwareQueryKey(firmwareId) }
  });

  const { data: scanResults, isLoading: loadingScan } = useGetScanResults(firmwareId, {
    query: {
      enabled: !!firmwareId,
      queryKey: getGetScanResultsQueryKey(firmwareId),
      // Poll every 3s while a scan is actively running; stop when done
      refetchInterval: (query): number | false => {
        const data = query.state.data as ScanResult[] | undefined;
        const latest = Array.isArray(data) ? data[0] : undefined;
        return latest?.status === "running" ? POLL_INTERVAL_MS : false;
      },
    }
  });

  const { data: files, isLoading: loadingFiles } = useGetExtractedFiles(firmwareId, {
    query: { enabled: !!firmwareId, queryKey: getGetExtractedFilesQueryKey(firmwareId) }
  });

  const { data: cves, isLoading: loadingCves } = useGetCveMatches(firmwareId, {
    query: { enabled: !!firmwareId, queryKey: getGetCveMatchesQueryKey(firmwareId) }
  });

  if (!firmwareId) return <div>Invalid ID</div>;

  const latestScan = scanResults?.[0];
  const isRunning = latestScan?.status === "running";
  const isCompleted = latestScan?.status === "completed";
  const isFailed = latestScan?.status === "failed";

  useEffect(() => {
    if (!firmwareId) return;
    if (latestScan?.status === "completed" || latestScan?.status === "failed") {
      queryClient.invalidateQueries({ queryKey: getGetFirmwareQueryKey(firmwareId) });
    }
  }, [firmwareId, latestScan?.status, queryClient]);

  const subPages = [
    { href: `/security/${firmwareId}`, label: "Security Analysis",  icon: ShieldAlert, color: "text-orange-500 border-orange-500/30 bg-orange-500/10 hover:bg-orange-500/20" },
    { href: `/cve/${firmwareId}`,      label: "CVE Intelligence",   icon: Bug,         color: "text-red-500 border-red-500/30 bg-red-500/10 hover:bg-red-500/20" },
    { href: `/malware/${firmwareId}`,  label: "Malware Detection",  icon: Fingerprint, color: "text-purple-500 border-purple-500/30 bg-purple-500/10 hover:bg-purple-500/20" },
    { href: `/reports/${firmwareId}`,  label: "Reports & AI",       icon: FileText,    color: "text-primary border-primary/30 bg-primary/10 hover:bg-primary/20" },
  ];

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-4 mb-2">
        <Link href="/firmware">
          <Button variant="ghost" size="icon" className="h-8 w-8 rounded-full">
            <ChevronLeft className="w-4 h-4" />
          </Button>
        </Link>
        <motion.h1 
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          className="text-3xl font-bold font-mono text-primary flex items-center drop-shadow-[0_0_8px_rgba(0,255,255,0.5)]"
        >
          <Search className="mr-3 text-primary" />
          SCAN_TELEMETRY
        </motion.h1>
      </div>

      <div className="grid md:grid-cols-3 gap-6">
        <Card className="border-border bg-card/80 backdrop-blur-md shadow-lg md:col-span-2">
          <CardHeader className="border-b border-border/50 bg-muted/5">
            <div className="flex justify-between items-start">
              <div>
                <CardTitle className="font-mono text-lg text-foreground flex items-center">
                  {loadingFw ? <Skeleton className="h-6 w-48" /> : firmware?.name}
                </CardTitle>
                <CardDescription className="font-mono text-xs mt-1 text-muted-foreground flex items-center">
                  <Hash className="w-3 h-3 mr-1 inline" />
                  {loadingFw ? <Skeleton className="h-4 w-64 inline-block" /> : firmware?.hashValue}
                </CardDescription>
              </div>
              <div>
                {loadingFw ? <Skeleton className="h-6 w-24" /> : (
                  <Badge variant="outline" className={`font-mono ${firmware?.status === 'completed' ? 'border-primary/50 text-primary' : firmware?.status === 'scanning' ? 'border-blue-500/50 text-blue-400 animate-pulse' : firmware?.status === 'failed' ? 'border-destructive/50 text-destructive' : ''}`}>
                    {firmware?.status.toUpperCase()}
                  </Badge>
                )}
              </div>

                <div>
                  <div className="mt-4">
                    <Button variant="ghost" onClick={() => setShowDebug(s => !s)}>
                      {showDebug ? "Hide Raw JSON" : "Show Raw JSON"}
                    </Button>
                  </div>

                  {showDebug && (
                    <Card className="mt-4">
                      <CardHeader>
                        <CardTitle className="font-mono text-sm">Raw API Data</CardTitle>
                      </CardHeader>
                      <CardContent>
                        <pre className="text-xs overflow-auto max-h-96">
          {JSON.stringify({ firmware, scanResults, files, cves }, null, 2)}
                        </pre>
                      </CardContent>
                    </Card>
                  )}
                </div>
            </div>
          </CardHeader>
          <CardContent className="p-6">
            <div className="grid grid-cols-2 md:grid-cols-4 gap-6">
              <div className="space-y-1">
                <p className="text-xs font-mono text-muted-foreground uppercase">Architecture</p>
                <p className="font-mono text-sm flex items-center">
                  <Cpu className="w-3 h-3 mr-1 text-primary" />
                  {loadingFw ? <Skeleton className="h-4 w-16" /> : firmware?.architecture}
                </p>
              </div>
              <div className="space-y-1">
                <p className="text-xs font-mono text-muted-foreground uppercase">Size</p>
                <p className="font-mono text-sm flex items-center">
                  <HardDrive className="w-3 h-3 mr-1 text-primary" />
                  {loadingFw ? <Skeleton className="h-4 w-16" /> : `${((firmware?.fileSize || 0) / 1024 / 1024).toFixed(2)} MB`}
                </p>
              </div>
              <div className="space-y-1">
                <p className="text-xs font-mono text-muted-foreground uppercase">Vendor</p>
                <p className="font-mono text-sm">
                  {loadingFw ? <Skeleton className="h-4 w-20" /> : firmware?.vendor || 'Unknown'}
                </p>
              </div>
              <div className="space-y-1">
                <p className="text-xs font-mono text-muted-foreground uppercase">Upload Time</p>
                <p className="font-mono text-sm flex items-center">
                  <Clock className="w-3 h-3 mr-1 text-primary" />
                  {loadingFw ? <Skeleton className="h-4 w-24" /> : new Date(firmware?.uploadedAt || '').toLocaleDateString()}
                </p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="border-primary/20 bg-card/80 backdrop-blur-md shadow-[0_0_15px_rgba(0,255,255,0.05)] md:col-span-1">
          <CardHeader>
            <CardTitle className="font-mono text-sm uppercase text-primary border-b border-border/50 pb-2 flex items-center gap-2">
              {isRunning && <Loader2 className="w-4 h-4 animate-spin text-blue-400" />}
              Analysis Status
            </CardTitle>
          </CardHeader>
          <CardContent>
            {loadingScan ? (
              <div className="space-y-4">
                <Skeleton className="h-4 w-full" />
                <Skeleton className="h-2 w-full" />
                <div className="grid grid-cols-2 gap-4 mt-4">
                  <Skeleton className="h-12 w-full" />
                  <Skeleton className="h-12 w-full" />
                </div>
              </div>
            ) : latestScan ? (
              <div className="space-y-6">
                <div>
                  <div className="flex justify-between text-xs font-mono mb-2">
                    <span className="text-muted-foreground">
                      {isRunning ? "Scanning…" : isCompleted ? "Completed" : isFailed ? "Failed" : "Progress"}
                    </span>
                    <span className={isRunning ? "text-blue-400" : isCompleted ? "text-primary" : isFailed ? "text-destructive" : "text-primary"}>
                      {latestScan.progress}%
                    </span>
                  </div>
                  <Progress
                    value={latestScan.progress}
                    className={`h-2 bg-muted [&>div]:${isRunning ? "bg-blue-400 [&>div]:shadow-[0_0_10px_rgba(96,165,250,0.8)]" : isCompleted ? "bg-primary [&>div]:shadow-[0_0_10px_rgba(0,255,255,0.8)]" : isFailed ? "bg-destructive" : "bg-primary"}`}
                  />
                  {isRunning && (
                    <p className="text-[10px] text-muted-foreground font-mono mt-1 animate-pulse">
                      Auto-refreshing every 3s…
                    </p>
                  )}
                </div>
                
                <div className="grid grid-cols-2 gap-4">
                  <div className="bg-background/50 border border-border/50 p-3 rounded-md text-center">
                    <p className="text-xs font-mono text-muted-foreground mb-1 uppercase">Files Extracted</p>
                    <p className="text-2xl font-mono text-foreground">
                      {isRunning ? <Loader2 className="w-5 h-5 animate-spin mx-auto text-muted-foreground" /> : (latestScan.totalFiles ?? 0)}
                    </p>
                  </div>
                  <div className={`bg-background/50 border ${latestScan.vulnerabilitiesFound ? 'border-destructive/30' : 'border-border/50'} p-3 rounded-md text-center`}>
                    <p className="text-xs font-mono text-muted-foreground mb-1 uppercase">Vulns Found</p>
                    <p className={`text-2xl font-mono ${latestScan.vulnerabilitiesFound ? 'text-destructive drop-shadow-[0_0_5px_rgba(255,0,0,0.5)]' : 'text-foreground'}`}>
                      {isRunning ? <Loader2 className="w-5 h-5 animate-spin mx-auto text-muted-foreground" /> : (latestScan.vulnerabilitiesFound ?? 0)}
                    </p>
                  </div>
                </div>

                {latestScan.riskLevel && !isRunning && (
                  <div className="text-center">
                    <p className="text-xs font-mono text-muted-foreground uppercase mb-1">Risk Level</p>
                    <Badge variant="outline" className={`font-mono uppercase text-sm px-4 py-1 ${
                      latestScan.riskLevel === 'critical' ? 'bg-destructive/10 text-destructive border-destructive/30' :
                      latestScan.riskLevel === 'high' ? 'bg-orange-500/10 text-orange-500 border-orange-500/30' :
                      latestScan.riskLevel === 'medium' ? 'bg-yellow-500/10 text-yellow-500 border-yellow-500/30' :
                      'bg-green-500/10 text-green-500 border-green-500/30'
                    }`}>
                      {latestScan.riskLevel}
                    </Badge>
                  </div>
                )}
              </div>
            ) : (
              <div className="text-center p-4 text-muted-foreground font-mono text-sm">
                No scan data available.
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Analysis sub-page navigation — shown only when scan is completed */}
      {isCompleted && (
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
        >
          <Card className="border-primary/20 bg-card/80 backdrop-blur-md shadow-[0_0_15px_rgba(0,255,255,0.05)]">
            <CardHeader>
              <CardTitle className="font-mono text-sm uppercase text-primary border-b border-border/50 pb-2 flex items-center gap-2">
                <ExternalLink className="w-4 h-4" />
                Deep Analysis Modules
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                {subPages.map(({ href, label, icon: Icon, color }) => (
                  <Link key={href} href={href}>
                    <div className={`flex flex-col items-center gap-2 p-3 rounded-md border cursor-pointer transition-all duration-200 ${color}`}>
                      <Icon className="w-5 h-5" />
                      <span className="font-mono text-[10px] uppercase text-center leading-tight">{label}</span>
                    </div>
                  </Link>
                ))}
              </div>
            </CardContent>
          </Card>
        </motion.div>
      )}

      <Card className="border-border bg-card/80 backdrop-blur-md shadow-lg">
        <CardHeader>
          <CardTitle className="font-mono text-sm uppercase text-primary border-b border-border/50 pb-2">Extracted File System</CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          {loadingFiles ? (
            <div className="p-6 space-y-2">
              {[1,2,3,4,5].map(i => <Skeleton key={i} className="h-8 w-full bg-muted/20" />)}
            </div>
          ) : files && files.length > 0 ? (
            <div className="max-h-[500px] overflow-auto custom-scrollbar">
              <Table>
                <TableHeader className="sticky top-0 bg-card z-10 shadow-sm">
                  <TableRow className="border-border/50">
                    <TableHead className="font-mono text-xs uppercase text-muted-foreground w-1/2">Path</TableHead>
                    <TableHead className="font-mono text-xs uppercase text-muted-foreground">Type</TableHead>
                    <TableHead className="font-mono text-xs uppercase text-muted-foreground">Size</TableHead>
                    <TableHead className="font-mono text-xs uppercase text-muted-foreground">Perms</TableHead>
                    <TableHead className="font-mono text-xs uppercase text-muted-foreground text-right">Flags</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {files.map((file) => (
                    <TableRow key={file.id} className={`border-border/20 hover:bg-muted/10 transition-colors ${file.isSuspicious ? 'bg-destructive/5' : ''}`}>
                      <TableCell className="font-mono text-xs">
                        <div className="flex items-center truncate">
                          {file.type.includes('dir') ? 
                            <Folder className="w-3 h-3 mr-2 text-primary" /> : 
                            <File className="w-3 h-3 mr-2 text-muted-foreground" />
                          }
                          <span className={file.isSuspicious ? 'text-destructive' : 'text-foreground'}>{file.path}</span>
                        </div>
                      </TableCell>
                      <TableCell className="font-mono text-xs text-muted-foreground">{file.type}</TableCell>
                      <TableCell className="font-mono text-xs text-muted-foreground">{(file.size / 1024).toFixed(1)} KB</TableCell>
                      <TableCell className="font-mono text-xs text-muted-foreground">{file.permissions || '-'}</TableCell>
                      <TableCell className="text-right">
                        {file.isSuspicious && (
                          <Badge variant="outline" className="bg-destructive/10 text-destructive border-destructive/30 text-[10px] py-0 h-4">SUSPICIOUS</Badge>
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          ) : isRunning ? (
            <div className="p-8 text-center text-muted-foreground font-mono flex flex-col items-center gap-3">
              <Loader2 className="w-8 h-8 animate-spin text-blue-400" />
              <span>Extraction in progress…</span>
            </div>
          ) : (
            <div className="p-8 text-center text-muted-foreground font-mono">No files extracted yet.</div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
