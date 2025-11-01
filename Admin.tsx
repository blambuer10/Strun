import { useEffect, useState } from "react";
import { supabase } from "@/integrations/supabase/client";
import { useAuth } from "@/contexts/AuthContext";
import { useWallet } from "@/hooks/useWallet";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Badge } from "@/components/ui/badge";
import { useToast } from "@/hooks/use-toast";
import { Loader2, RefreshCw, Share2, Eye, Rocket } from "lucide-react";

interface Task {
  id: string;
  city: string;
  title: string;
  description: string;
  type: string;
  coordinates: { lat: number; lon: number };
  radius_m: number;
  xp_reward: number;
  sol_reward: number | null;
  max_participants: number;
  status: string;
  meta?: any;
}

interface Job {
  id: string;
  city: string;
  mode: string;
  status: string;
  created_at: string;
}

export default function Admin() {
  const { user } = useAuth();
  const { publicKey } = useWallet();
  const { toast } = useToast();

  const [city, setCity] = useState("Istanbul, Turkey");
  const [mode, setMode] = useState("mix");
  const [sponsorId, setSponsorId] = useState("");
  const [count, setCount] = useState(20);
  const [jobs, setJobs] = useState<Job[]>([]);
  const [pendingTasks, setPendingTasks] = useState<Task[]>([]);
  const [publishedTasks, setPublishedTasks] = useState<Task[]>([]);
  const [loading, setLoading] = useState(false);
  const [selectedTask, setSelectedTask] = useState<Task | null>(null);

  useEffect(() => {
    fetchPending();
    fetchPublished();
    fetchJobs();
  }, []);

  async function fetchJobs() {
    try {
      const { data, error } = await supabase
        .from("task_generation_jobs")
        .select("*")
        .order("created_at", { ascending: false })
        .limit(10);
      
      if (error) throw error;
      setJobs(data || []);
    } catch (e: any) {
      console.error("Fetch jobs error:", e);
    }
  }

  async function enqueueGenerate() {
    setLoading(true);
    try {
      const { data, error } = await supabase.functions.invoke("admin-generate-tasks", {
        body: { 
          city, 
          mode, 
          sponsor_id: sponsorId || null, 
          count: Number(count) 
        }
      });

      if (error) throw error;
      
      toast({
        title: "Task generation enqueued",
        description: `Job ID: ${data.jobId}`,
      });

      fetchJobs();
    } catch (e: any) {
      console.error(e);
      toast({
        title: "Error",
        description: e.message || "Enqueue failed",
        variant: "destructive",
      });
    }
    setLoading(false);
  }

  async function fetchPending() {
    try {
      const { data, error } = await supabase.functions.invoke("get-tasks", {
        body: { status: "pending" }
      });

      if (error) throw error;
      setPendingTasks(data?.tasks || []);
    } catch (e: any) {
      console.error("Fetch pending error:", e);
    }
  }

  async function fetchPublished() {
    try {
      const { data, error } = await supabase.functions.invoke("get-tasks", {
        body: { city, status: "published" }
      });

      if (error) throw error;
      setPublishedTasks(data?.tasks || []);
    } catch (e: any) {
      console.error("Fetch published error:", e);
    }
  }

  async function publishTask(taskId: string) {
    setLoading(true);
    try {
      const { data, error } = await supabase.functions.invoke(`admin-publish-task/${taskId}`, {
        method: "POST"
      });

      if (error) throw error;

      toast({
        title: "Task published",
        description: "Task is now live",
      });

      fetchPending();
      fetchPublished();
    } catch (e: any) {
      console.error(e);
      toast({
        title: "Error",
        description: e.message || "Publish failed",
        variant: "destructive",
      });
    }
    setLoading(false);
  }

  async function getShare(task: Task) {
    try {
      const { data, error } = await supabase.functions.invoke(`get-task-share/${task.id}`, {
        method: "GET"
      });

      if (error) throw error;

      if (data.xIntent) {
        window.open(data.xIntent, "_blank");
      } else {
        navigator.clipboard.writeText(data.shareText || "");
        toast({
          title: "Share text copied",
          description: "Paste it anywhere to share",
        });
      }
    } catch (e: any) {
      console.error(e);
      toast({
        title: "Error",
        description: e.message || "Share failed",
        variant: "destructive",
      });
    }
  }

  return (
    <div className="min-h-screen bg-background p-4 pb-20">
      <div className="max-w-7xl mx-auto">
        <header className="flex items-center justify-between mb-6">
          <div>
            <h1 className="text-2xl font-bold">Task Admin</h1>
            <p className="text-sm text-muted-foreground">AI-powered task generation</p>
          </div>
          <div className="flex items-center gap-3">
            <div className="text-sm text-muted-foreground">
              {publicKey ? (
                <span className="font-mono text-xs">
                  {publicKey.slice(0, 6)}...{publicKey.slice(-6)}
                </span>
              ) : (
                "Wallet not connected"
              )}
            </div>
          </div>
        </header>

        <div className="grid grid-cols-1 md:grid-cols-12 gap-6">
          <aside className="md:col-span-4 space-y-4">
            <div className="bg-card p-4 rounded-lg border">
              <h2 className="font-semibold mb-4">Generate Tasks</h2>
              
              <div className="space-y-4">
                <div>
                  <label className="text-xs text-muted-foreground">City</label>
                  <Input 
                    value={city} 
                    onChange={(e) => setCity(e.target.value)} 
                    className="mt-1"
                  />
                </div>

                <div>
                  <label className="text-xs text-muted-foreground">Mode</label>
                  <Select value={mode} onValueChange={setMode}>
                    <SelectTrigger className="mt-1">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="mix">Mix</SelectItem>
                      <SelectItem value="sponsored">Sponsored</SelectItem>
                      <SelectItem value="organic">Organic</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                <div>
                  <label className="text-xs text-muted-foreground">Sponsor ID (optional)</label>
                  <Input 
                    value={sponsorId} 
                    onChange={(e) => setSponsorId(e.target.value)} 
                    className="mt-1"
                    placeholder="Leave empty for organic"
                  />
                </div>

                <div>
                  <label className="text-xs text-muted-foreground">POI count</label>
                  <Input 
                    type="number" 
                    value={count} 
                    onChange={(e) => setCount(Number(e.target.value))} 
                    className="mt-1"
                  />
                </div>

                <div className="flex gap-2">
                  <Button 
                    onClick={enqueueGenerate} 
                    disabled={loading} 
                    className="flex-1"
                  >
                    {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Rocket className="h-4 w-4" />}
                    <span className="ml-2">Generate</span>
                  </Button>
                  <Button 
                    onClick={() => { fetchPending(); fetchPublished(); fetchJobs(); }} 
                    variant="outline"
                    size="icon"
                  >
                    <RefreshCw className="h-4 w-4" />
                  </Button>
                </div>
              </div>
            </div>

            <div className="bg-card p-4 rounded-lg border">
              <h3 className="text-sm font-semibold mb-2">Recent Jobs</h3>
              <div className="space-y-2 max-h-60 overflow-auto">
                {jobs.length === 0 && (
                  <p className="text-xs text-muted-foreground">No jobs yet</p>
                )}
                {jobs.map((j) => (
                  <div key={j.id} className="p-2 border rounded flex justify-between items-center">
                    <div>
                      <div className="text-sm font-medium">{j.city}</div>
                      <div className="text-xs text-muted-foreground">{j.mode}</div>
                    </div>
                    <Badge variant={j.status === "completed" ? "default" : "secondary"}>
                      {j.status}
                    </Badge>
                  </div>
                ))}
              </div>
            </div>
          </aside>

          <main className="md:col-span-8 space-y-6">
            <div className="bg-card p-4 rounded-lg border">
              <h2 className="font-semibold mb-4">Pending Tasks</h2>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {pendingTasks.length === 0 && (
                  <p className="text-sm text-muted-foreground">No pending tasks</p>
                )}
                {pendingTasks.map((t) => (
                  <div key={t.id} className="border rounded-lg p-3 space-y-2">
                    <div className="flex items-start justify-between">
                      <div>
                        <div className="font-medium">{t.title}</div>
                        <div className="text-xs text-muted-foreground">
                          {t.city} · {t.type}
                        </div>
                      </div>
                      {t.sol_reward && (
                        <Badge variant="secondary">{t.sol_reward} SOL</Badge>
                      )}
                    </div>
                    <p className="text-sm text-muted-foreground line-clamp-2">
                      {t.description}
                    </p>
                    <div className="flex gap-2">
                      <Button 
                        onClick={() => publishTask(t.id)} 
                        size="sm"
                        className="flex-1"
                      >
                        Publish
                      </Button>
                      <Button 
                        onClick={() => setSelectedTask(t)} 
                        size="sm"
                        variant="outline"
                      >
                        <Eye className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div className="bg-card p-4 rounded-lg border">
              <h2 className="font-semibold mb-4">Published Tasks</h2>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {publishedTasks.length === 0 && (
                  <p className="text-sm text-muted-foreground">No published tasks</p>
                )}
                {publishedTasks.map((t) => (
                  <div key={t.id} className="border rounded-lg p-3 flex justify-between items-start">
                    <div>
                      <div className="font-medium">{t.title}</div>
                      <div className="text-xs text-muted-foreground">
                        {t.city} · {t.type} · {t.radius_m}m
                      </div>
                    </div>
                    <div className="flex flex-col gap-2">
                      <Button onClick={() => getShare(t)} size="sm" variant="outline">
                        <Share2 className="h-4 w-4" />
                      </Button>
                      <Button onClick={() => setSelectedTask(t)} size="sm" variant="outline">
                        <Eye className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </main>
        </div>

        <Dialog open={!!selectedTask} onOpenChange={() => setSelectedTask(null)}>
          <DialogContent className="max-w-2xl">
            <DialogHeader>
              <DialogTitle>Task Details</DialogTitle>
            </DialogHeader>
            {selectedTask && (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-3">
                  <div>
                    <div className="text-sm text-muted-foreground">Title</div>
                    <div className="font-medium">{selectedTask.title}</div>
                  </div>
                  <div>
                    <div className="text-sm text-muted-foreground">Description</div>
                    <div className="text-sm">{selectedTask.description}</div>
                  </div>
                  <div>
                    <div className="text-sm text-muted-foreground">Location</div>
                    <div className="text-sm">
                      {selectedTask.coordinates.lat.toFixed(4)}, {selectedTask.coordinates.lon.toFixed(4)}
                    </div>
                  </div>
                </div>
                <div className="space-y-3">
                  <div>
                    <div className="text-sm text-muted-foreground">Rewards</div>
                    <div className="text-sm">
                      {selectedTask.xp_reward} XP
                      {selectedTask.sol_reward && ` + ${selectedTask.sol_reward} SOL`}
                    </div>
                  </div>
                  <div>
                    <div className="text-sm text-muted-foreground">Meta</div>
                    <pre className="text-xs bg-muted p-2 rounded overflow-auto max-h-32">
                      {JSON.stringify(selectedTask.meta || {}, null, 2)}
                    </pre>
                  </div>
                  <div className="flex gap-2">
                    {selectedTask.status === "pending" && (
                      <Button onClick={() => publishTask(selectedTask.id)} className="flex-1">
                        Publish
                      </Button>
                    )}
                    <Button onClick={() => getShare(selectedTask)} variant="outline" className="flex-1">
                      <Share2 className="h-4 w-4 mr-2" />
                      Share
                    </Button>
                  </div>
                </div>
              </div>
            )}
          </DialogContent>
        </Dialog>
      </div>
    </div>
  );
}
