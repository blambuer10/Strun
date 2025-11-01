import { useEffect, useState, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useAuth } from "@/contexts/AuthContext";
import { supabase } from "@/integrations/supabase/client";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import BottomNav from "@/components/BottomNav";
import { TaskProofDialog } from "@/components/TaskProofDialog";
import { useToast } from "@/hooks/use-toast";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { Activity, MapPin, Zap, LogOut, Award, Trophy, Users, Coins, CheckCircle2, Clock, MessageSquare, ThumbsUp, Upload, Eye, Target, Wallet, Copy, Camera, Edit2, Check, X, User, ArrowUpRight, ArrowDownLeft, HelpCircle } from "lucide-react";
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from "recharts";
import strunLogo from "@/assets/strun-logo.jpg";
import { RewardsSection } from "@/components/RewardsSection";
import { formatDistanceToNow } from "date-fns";
import { useWallet } from "@/hooks/useWallet";
import { FloatingMascot } from "@/components/FloatingMascot";
import runnyMascot from "@/assets/runny-mascot.png";
const Dashboard = () => {
  const {
    user,
    signOut,
    loading: authLoading
  } = useAuth();
  const navigate = useNavigate();
  const {
    toast
  } = useToast();
  const queryClient = useQueryClient();
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [showProofDialog, setShowProofDialog] = useState(false);
  const [selectedProofTask, setSelectedProofTask] = useState<any>(null);
  const [selectedProofUserTaskId, setSelectedProofUserTaskId] = useState<string | null>(null);
  const [isEditingUsername, setIsEditingUsername] = useState(false);
  const [newUsername, setNewUsername] = useState("");
  const [uploading, setUploading] = useState(false);
  const [updating, setUpdating] = useState(false);
  const [walletBalance, setWalletBalance] = useState({ sol: 0, xp: 0 });
  const [nftCount, setNftCount] = useState(0);
  const [transactions, setTransactions] = useState<any[]>([]);
  const { publicKey, loading: walletLoading } = useWallet();
  useEffect(() => {
    if (!authLoading && !user) navigate("/");
  }, [user, authLoading, navigate]);

  useEffect(() => {
    if (user) {
      fetchWalletBalance();
      fetchNFTCount();
      fetchTransactions();
    }
  }, [user]);

  const fetchWalletBalance = async () => {
    try {
      const { data: profile } = await supabase
        .from("profiles")
        .select("xp")
        .eq("id", user?.id)
        .single();

      if (profile) {
        setWalletBalance({
          sol: 0,
          xp: profile.xp,
        });
      }
    } catch (error) {
      console.error("Error fetching balance:", error);
    }
  };

  const fetchNFTCount = async () => {
    try {
      const { count } = await supabase
        .from("land_nfts")
        .select("*", { count: "exact", head: true })
        .eq("user_id", user?.id);

      setNftCount(count || 0);
    } catch (error) {
      console.error("Error fetching NFT count:", error);
    }
  };

  const fetchTransactions = async () => {
    try {
      const { data, error } = await supabase
        .from("transactions")
        .select("*")
        .eq("user_id", user?.id)
        .order("created_at", { ascending: false });

      if (error) throw error;

      setTransactions(data || []);
    } catch (error) {
      console.error("Error fetching transactions:", error);
    }
  };

  const copyWalletAddress = () => {
    if (publicKey) {
      navigator.clipboard.writeText(publicKey);
      toast({
        title: "Copied!",
        description: "Wallet address copied to clipboard",
      });
    }
  };

  const formatAddress = (address: string) => {
    return `${address.slice(0, 6)}...${address.slice(-4)}`;
  };

  // Fetch profile data
  const {
    data: profile
  } = useQuery({
    queryKey: ["profile", user?.id],
    queryFn: async () => {
      if (!user?.id) return null;
      const {
        data
      } = await supabase.from("profiles").select("*").eq("id", user.id).single();
      return data;
    },
    enabled: !!user?.id
  });

  // Fetch task statistics
  const {
    data: taskStats
  } = useQuery({
    queryKey: ["task-stats", user?.id],
    queryFn: async () => {
      if (!user?.id) return {
        total: 0,
        completed: 0,
        pending: 0,
        totalXP: 0,
        totalSOL: 0
      };
      const {
        data
      } = await supabase.from("user_tasks").select("status, xp_awarded, sol_awarded").eq("user_id", user.id);
      return {
        total: data?.length || 0,
        completed: data?.filter(t => t.status === "completed").length || 0,
        pending: data?.filter(t => t.status === "pending").length || 0,
        totalXP: data?.reduce((sum, t) => sum + (t.xp_awarded || 0), 0) || 0,
        totalSOL: data?.reduce((sum, t) => sum + Number(t.sol_awarded || 0), 0) || 0
      };
    },
    enabled: !!user?.id
  });

  // Fetch user's task proofs
  const {
    data: myProofs
  } = useQuery({
    queryKey: ["my-proofs", user?.id],
    queryFn: async () => {
      if (!user?.id) return [];
      const {
        data
      } = await supabase.from("task_proofs").select("*").eq("user_id", user.id).order("created_at", {
        ascending: false
      });
      return data;
    },
    enabled: !!user?.id
  });

  // Fetch user's groups
  const {
    data: myGroups
  } = useQuery({
    queryKey: ["groups-user", user?.id],
    queryFn: async () => {
      if (!user?.id) return [];
      const {
        data
      } = await supabase.from("group_members").select("*, groups(*)").eq("user_id", user.id);
      return data;
    },
    enabled: !!user?.id
  });

  // Fetch leaderboard data (top 50 + current user)
  const { data: leaderboardData } = useQuery({
    queryKey: ["leaderboard"],
    queryFn: async () => {
      const { data: profiles, error } = await supabase
        .from("profiles")
        .select("id, username, email, xp, avatar_url, level")
        .order("xp", { ascending: false })
        .limit(50);
      
      if (error) throw error;

      const enrichedProfiles = await Promise.all(
        (profiles || []).map(async (profile) => {
          const { data: runs } = await supabase
            .from("runs")
            .select("distance, xp_earned")
            .eq("user_id", profile.id);

          const totalDistance = runs?.reduce((sum, run) => sum + parseFloat(String(run.distance || 0)), 0) || 0;
          const totalRuns = runs?.length || 0;

          return {
            ...profile,
            totalDistance,
            totalRuns,
          };
        })
      );
      
      return enrichedProfiles;
    },
  });

  // Get current user's rank
  const { data: userRank } = useQuery({
    queryKey: ["user-rank", user?.id],
    queryFn: async () => {
      if (!user?.id) return null;
      
      const { data: allProfiles } = await supabase
        .from("profiles")
        .select("id, xp")
        .order("xp", { ascending: false });
      
      const rank = (allProfiles || []).findIndex(p => p.id === user.id) + 1;
      return rank > 0 ? rank : null;
    },
    enabled: !!user?.id,
  });
  const {
    data: myTasks
  } = useQuery({
    queryKey: ["my-tasks", user?.id],
    queryFn: async () => {
      if (!user?.id) return [];
      const {
        data
      } = await supabase.from("user_tasks").select("*, tasks(*)").eq("user_id", user.id).order("joined_at", {
        ascending: false
      }).limit(10);
      return data;
    },
    enabled: !!user?.id
  });
  // Use level from database (auto-calculated by increment_xp function)
  const xp = profile?.xp || 0;
  const level = profile?.level || 1;
  
  // Calculate XP needed for current and next level
  // Formula: level = floor(sqrt(xp / 100)) + 1
  // Reversed: xp_for_level = ((level - 1) ^ 2) * 100
  const currentLevelXP = Math.pow(level - 1, 2) * 100;
  const nextLevelXP = Math.pow(level, 2) * 100;
  const xpInLevel = xp - currentLevelXP;
  const xpNeededForNextLevel = nextLevelXP - currentLevelXP;
  const progressPercent = (xpInLevel / xpNeededForNextLevel) * 100;
  const avatarUrl = profile?.avatar_url || null;
  const userName = profile?.username || "Runner";
  useEffect(() => {
    if (profile?.username) {
      setNewUsername(profile.username);
    }
  }, [profile?.username]);
  const handleAvatarClick = () => {
    fileInputRef.current?.click();
  };
  const handleAvatarUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
    try {
      const file = event.target.files?.[0];
      if (!file) return;
      if (!file.type.startsWith('image/')) {
        toast({
          title: "Invalid File",
          description: "Please upload an image file",
          variant: "destructive"
        });
        return;
      }
      if (file.size > 5 * 1024 * 1024) {
        toast({
          title: "File Too Large",
          description: "Please upload an image smaller than 5MB",
          variant: "destructive"
        });
        return;
      }
      setUploading(true);
      if (avatarUrl) {
        const oldPath = avatarUrl.split('/').pop();
        if (oldPath) {
          await supabase.storage.from('avatars').remove([`${user?.id}/${oldPath}`]);
        }
      }
      const fileExt = file.name.split('.').pop();
      const fileName = `${Date.now()}.${fileExt}`;
      const filePath = `${user?.id}/${fileName}`;
      const {
        error: uploadError
      } = await supabase.storage.from('avatars').upload(filePath, file);
      if (uploadError) throw uploadError;
      const {
        data: {
          publicUrl
        }
      } = supabase.storage.from('avatars').getPublicUrl(filePath);
      const {
        error: updateError
      } = await supabase.from('profiles').update({
        avatar_url: publicUrl
      }).eq('id', user?.id);
      if (updateError) throw updateError;
      queryClient.invalidateQueries({
        queryKey: ['profile', user?.id]
      });
      toast({
        title: "Success! Avatar Updated",
        description: "Your profile photo has been updated successfully"
      });
    } catch (error) {
      toast({
        title: "Upload Failed",
        description: "Failed to upload avatar. Please try again.",
        variant: "destructive"
      });
    } finally {
      setUploading(false);
    }
  };
  const handleSaveUsername = async () => {
    if (!newUsername.trim()) {
      toast({
        title: "Invalid Username",
        description: "Username cannot be empty",
        variant: "destructive"
      });
      return;
    }
    try {
      setUpdating(true);
      const {
        error
      } = await supabase.from('profiles').update({
        username: newUsername.trim()
      }).eq('id', user?.id);
      if (error) throw error;
      queryClient.invalidateQueries({
        queryKey: ['profile', user?.id]
      });
      setIsEditingUsername(false);
      toast({
        title: "Success! Username Updated",
        description: "Your username has been updated successfully"
      });
    } catch (error) {
      toast({
        title: "Update Failed",
        description: "Failed to update username. Please try again.",
        variant: "destructive"
      });
    } finally {
      setUpdating(false);
    }
  };
  const handleCancelEdit = () => {
    setNewUsername(profile?.username || "");
    setIsEditingUsername(false);
  };
  const taskStatusData = [{
    name: "Completed",
    value: taskStats?.completed || 0,
    color: "hsl(var(--success))"
  }, {
    name: "Pending",
    value: taskStats?.pending || 0,
    color: "hsl(var(--primary))"
  }];
  if (authLoading || !profile) {
    return <div className="min-h-screen bg-background flex items-center justify-center">
        <Activity className="w-12 h-12 text-accent animate-pulse" />
      </div>;
  }
  return <div className="min-h-screen bg-background">
      <header className="border-b bg-card/50 backdrop-blur-lg sticky top-0 z-50">
        <div className="container mx-auto px-4 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <img src={strunLogo} alt="Strun" className="h-10" />
            <p className="text-xs text-muted-foreground">{profile?.email}</p>
          </div>
          <Button variant="ghost" size="icon" onClick={signOut}>
            <LogOut className="w-5 h-5" />
          </Button>
        </div>
      </header>

      <div className="container mx-auto px-4 py-6 space-y-6 pb-24">
        {/* Quick Actions */}
        <div className="grid grid-cols-2 gap-3">
          <Button variant="cyan" className="h-20 flex-col gap-2" onClick={() => navigate("/tasks")}>
            <MapPin className="w-6 h-6" />
            <span className="text-xs">Tasks</span>
          </Button>
          <Button variant="accent" className="h-20 flex-col gap-2" onClick={() => navigate("/run")}>
            <Activity className="w-6 h-6" />
            <span className="text-xs">Start Run</span>
          </Button>
        </div>

        <Card className="p-6 glass">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-3">
              <div className="bg-primary/20 p-2 rounded-lg">
                <Trophy className="w-6 h-6 text-primary" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <h2 className="text-3xl font-bold gradient-text">{xp.toLocaleString()} XP</h2>
                  <Popover>
                    <PopoverTrigger asChild>
                      <button className="text-muted-foreground hover:text-primary transition-colors">
                        <HelpCircle className="w-4 h-4" />
                      </button>
                    </PopoverTrigger>
                    <PopoverContent className="w-72">
                      <div className="space-y-2">
                        <h4 className="font-semibold text-sm">XP & Level System</h4>
                        <p className="text-xs text-muted-foreground">
                          Earn XP by completing tasks and running. Your level is calculated as: <strong>Level = √(XP/100) + 1</strong>
                        </p>
                        <div className="pt-2 border-t space-y-1 text-xs">
                          <div>• <strong>Running:</strong> Earn XP based on distance</div>
                          <div>• <strong>Tasks:</strong> Complete challenges for XP rewards</div>
                          <div>• <strong>Level Up:</strong> Each level requires more XP than the last</div>
                        </div>
                      </div>
                    </PopoverContent>
                  </Popover>
                </div>
                <p className="text-[10px] text-muted-foreground/80 font-light mt-0.5">Level {level}</p>
              </div>
            </div>
          </div>
          <Progress value={progressPercent} className="h-2 mb-2" />
          <p className="text-xs text-muted-foreground text-right">
            {xpInLevel.toLocaleString()} / {xpNeededForNextLevel.toLocaleString()} XP to Level {level + 1}
          </p>
        </Card>

        <Tabs defaultValue="overview" className="w-full">
          <TabsList className="grid w-full grid-cols-5 bg-card/50 backdrop-blur-lg">
            <TabsTrigger value="overview" className="text-xs">Overview</TabsTrigger>
            <TabsTrigger value="tasks" className="text-xs">Tasks</TabsTrigger>
            <TabsTrigger value="wallet" className="text-xs">Wallet</TabsTrigger>
            <TabsTrigger value="leaderboard" className="text-xs">Leaderboard</TabsTrigger>
            <TabsTrigger value="rewards" className="text-xs">Rewards</TabsTrigger>
          </TabsList>

          <TabsContent value="overview" className="space-y-4">
            {/* Runny Welcome Card */}
            <Card className="p-4 glass bg-gradient-to-r from-primary/10 to-accent/10 border-primary/30">
              <div className="flex items-center gap-4">
                <div className="flex-shrink-0 w-16 h-16 rounded-full bg-gradient-to-br from-primary via-secondary to-accent p-1">
                  <div className="w-full h-full rounded-full bg-card flex items-center justify-center">
                    <img src={runnyMascot} alt="Runny" className="w-14 h-14 object-contain" />
                  </div>
                </div>
                <div className="flex-1">
                  <h3 className="font-bold text-lg gradient-text mb-1">Meet Runny!</h3>
                  <p className="text-xs text-muted-foreground">
                    Your AI fitness & task assistant. I'll help you stay motivated, complete challenges, and earn rewards!
                  </p>
                </div>
              </div>
            </Card>

            {/* Profile Edit Card */}
            

            <div className="grid grid-cols-2 gap-3">
              <Card className="p-4 glass hover-lift">
                <Zap className="w-5 h-5 mb-2 text-primary" />
                <div className="text-2xl font-bold gradient-text">{xp.toLocaleString()}</div>
                <div className="text-xs text-muted-foreground">Total XP</div>
              </Card>
              <Card className="p-4 glass hover-lift">
                <CheckCircle2 className="w-5 h-5 mb-2 text-success" />
                <div className="text-2xl font-bold gradient-text">{taskStats?.completed || 0}</div>
                <div className="text-xs text-muted-foreground">Tasks Done</div>
              </Card>
              <Card className="p-4 glass hover-lift">
                <Coins className="w-5 h-5 mb-2 text-secondary" />
                <div className="text-2xl font-bold gradient-text">{taskStats?.totalSOL.toFixed(2) || "0.00"}</div>
                <div className="text-xs text-muted-foreground">SOL Earned</div>
              </Card>
              <Card className="p-4 glass hover-lift">
                <Users className="w-5 h-5 mb-2 text-accent" />
                <div className="text-2xl font-bold gradient-text">{myGroups?.length || 0}</div>
                <div className="text-xs text-muted-foreground">Groups</div>
              </Card>
            </div>
            
            <Card className="p-6 glass">
              <h3 className="font-bold mb-4 flex items-center gap-2">
                <Target className="w-5 h-5 text-primary" />
                Task Status
              </h3>
              <ResponsiveContainer width="100%" height={200}>
                <PieChart>
                  <Pie data={taskStatusData} cx="50%" cy="50%" innerRadius={50} outerRadius={80} dataKey="value" label={entry => `${entry.name}: ${entry.value}`}>
                    {taskStatusData.map((entry, index) => <Cell key={`cell-${index}`} fill={entry.color} />)}
                  </Pie>
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
            </Card>
          </TabsContent>

          <TabsContent value="tasks" className="space-y-4">
            <div className="grid grid-cols-2 gap-3">
              <Card className="p-4 glass hover-lift">
                <CheckCircle2 className="w-5 h-5 mb-2 text-success" />
                <div className="text-2xl font-bold gradient-text">{taskStats?.completed || 0}</div>
                <div className="text-xs text-muted-foreground">Completed</div>
              </Card>
              <Card className="p-4 glass hover-lift">
                <Clock className="w-5 h-5 mb-2 text-primary" />
                <div className="text-2xl font-bold gradient-text">{taskStats?.pending || 0}</div>
                <div className="text-xs text-muted-foreground">Pending</div>
              </Card>
            </div>

            <Card className="p-6 glass">
              <h3 className="font-bold mb-4 flex items-center gap-2">
                <Target className="w-5 h-5 text-primary" />
                My Tasks
              </h3>
              <div className="space-y-3">
                {myTasks && myTasks.length > 0 ? myTasks.map(ut => <div key={ut.id} className={`flex items-center justify-between p-3 glass rounded-lg ${ut.status === "pending" ? "cursor-pointer hover-lift" : ""}`} onClick={() => {
                if (ut.status === "pending" && ut.tasks) {
                  setSelectedProofTask(ut.tasks);
                  setSelectedProofUserTaskId(ut.id);
                  setShowProofDialog(true);
                }
              }}>
                      <div className="flex-1">
                        <div className="font-medium text-foreground">{ut.tasks?.title || ut.tasks?.name}</div>
                        <div className="text-xs text-muted-foreground">
                          {ut.status === "completed" ? "✓ Completed" : "⏱ In Progress"} • <span className="text-primary font-bold">+{ut.xp_awarded || ut.tasks?.xp_reward || 0} XP</span>
                        </div>
                      </div>
                      <Badge variant={ut.status === "completed" ? "default" : "outline"} className="text-xs">
                        {ut.status}
                      </Badge>
                    </div>) : <p className="text-center text-muted-foreground py-8">No tasks accepted yet</p>}
              </div>
              {myTasks && myTasks.length > 0 && <Button variant="outline" className="w-full mt-4" onClick={() => navigate("/tasks")}>
                  View All Tasks →
                </Button>}
            </Card>

            <Card className="p-6 glass">
              <h3 className="font-bold mb-4 flex items-center gap-2">
                <Upload className="w-5 h-5 text-primary" />
                My Proofs
              </h3>
              <div className="space-y-3">
                {myProofs && myProofs.length > 0 ? myProofs.slice(0, 5).map(proof => <div key={proof.id} className="flex justify-between p-3 glass rounded-lg hover-lift">
                      <div className="flex-1">
                        <div className="font-medium line-clamp-1 text-foreground">{proof.content}</div>
                        <div className="text-xs text-muted-foreground">
                          {new Date(proof.created_at).toLocaleDateString()}
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <ThumbsUp className="w-4 h-4 text-success" />
                        <span className="font-bold text-success">{proof.upvotes}</span>
                      </div>
                    </div>) : <p className="text-center text-muted-foreground py-8">No proofs submitted yet</p>}
              </div>
            </Card>
          </TabsContent>

          <TabsContent value="wallet" className="space-y-4">
            {/* Wallet Address */}
            {walletLoading ? (
              <Card className="p-6 bg-gradient-to-br from-accent/10 via-card to-primary/5 border-accent/30">
                <div className="text-center">
                  <p className="text-muted-foreground">Loading wallet...</p>
                </div>
              </Card>
            ) : publicKey ? (
              <Card className="p-6 bg-gradient-to-br from-accent/10 via-card to-primary/5 border-accent/30">
                <div className="flex items-center justify-between">
                  <div className="flex-1">
                    <p className="text-sm text-muted-foreground mb-1">Wallet Address</p>
                    <p className="font-mono text-base font-bold">{formatAddress(publicKey)}</p>
                  </div>
                  <Button variant="ghost" size="icon" onClick={copyWalletAddress}>
                    <Copy className="w-5 h-5" />
                  </Button>
                </div>
              </Card>
            ) : (
              <Card className="p-6 bg-gradient-to-br from-warning/10 via-card to-primary/5 border-warning/30">
                <div className="text-center">
                  <Wallet className="w-12 h-12 mx-auto mb-3 text-warning" />
                  <p className="text-muted-foreground">No wallet found</p>
                </div>
              </Card>
            )}

            {/* Wallet Balance */}
            <Card className="p-8 bg-gradient-to-br from-primary/20 via-card to-secondary/20 relative overflow-hidden">
              <div className="absolute inset-0 bg-[radial-gradient(circle_at_50%_50%,hsl(220_70%_50%/0.2),transparent)]" />
              <div className="relative z-10 text-center space-y-4">
                <div className="inline-flex w-24 h-24 rounded-full bg-gradient-to-br from-accent via-primary to-accent-glow items-center justify-center mx-auto relative">
                  <div className="absolute inset-0 bg-accent/30 blur-2xl rounded-full" />
                  <Wallet className="w-12 h-12 text-foreground relative" />
                </div>
                
                <div>
                  <h2 className="text-sm text-muted-foreground mb-1">Strun Wallet</h2>
                  <div className="text-4xl font-bold text-gradient mb-1">{walletBalance.sol.toFixed(2)} SOL</div>
                  <p className="text-sm text-muted-foreground">Balance</p>
                </div>
              </div>
            </Card>

            {/* Tokens */}
            <Card className="p-6 bg-card/95">
              <h3 className="text-lg font-bold mb-4">Tokens</h3>
              <div className="space-y-3">
                <div className="flex items-center justify-between p-4 bg-primary/5 rounded-xl">
                  <div className="flex items-center gap-3">
                    <div className="w-10 h-10 rounded-full bg-primary/20 flex items-center justify-center">
                      <Wallet className="w-5 h-5 text-primary" />
                    </div>
                    <div>
                      <div className="font-bold">SOL</div>
                      <div className="text-sm text-muted-foreground">{walletBalance.sol.toFixed(2)} SOL</div>
                    </div>
                  </div>
                  <ArrowUpRight className="w-5 h-5 text-muted-foreground" />
                </div>
                
                <div className="flex items-center justify-between p-4 bg-accent/5 rounded-xl">
                  <div className="flex items-center gap-3">
                    <div className="w-10 h-10 rounded-full bg-accent/20 flex items-center justify-center">
                      <Zap className="w-5 h-5 text-accent" />
                    </div>
                    <div>
                      <div className="font-bold">XP</div>
                      <div className="text-sm text-muted-foreground">{walletBalance.xp.toLocaleString()} XP</div>
                    </div>
                  </div>
                  <ArrowUpRight className="w-5 h-5 text-muted-foreground" />
                </div>
              </div>
            </Card>

            {/* LandNFTs */}
            <Card className="p-6 bg-card/95">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-bold">LandNFTs</h3>
                <div className="flex items-center gap-2">
                  <span className="text-sm text-muted-foreground">Owned</span>
                  <span className="font-bold text-accent">{nftCount} NFTs</span>
                </div>
              </div>
              <Button variant="outline" className="w-full" onClick={() => navigate("/profile")}>
                <MapPin className="w-4 h-4 mr-2" />
                View Collection
                <ArrowUpRight className="w-4 h-4 ml-auto" />
              </Button>
            </Card>

            {/* Transaction History */}
            <Card className="p-6 bg-card/95">
              <h3 className="text-lg font-bold mb-4">Transaction History</h3>
              
              <Tabs defaultValue="all" className="w-full">
                <TabsList className="w-full mb-4">
                  <TabsTrigger value="all" className="flex-1">All</TabsTrigger>
                  <TabsTrigger value="sends" className="flex-1">Sends</TabsTrigger>
                  <TabsTrigger value="receives" className="flex-1">Receives</TabsTrigger>
                </TabsList>

                <TabsContent value="all" className="space-y-3 m-0">
                  {transactions.length > 0 ? (
                    transactions.map((tx) => (
                      <div key={tx.id} className="flex items-center justify-between p-4 bg-background/50 rounded-xl">
                        <div className="flex items-center gap-3">
                          <div className={`w-10 h-10 rounded-full flex items-center justify-center ${
                            tx.type === "earn" || tx.type === "receive" || tx.type === "reward"
                              ? "bg-accent/20" 
                              : "bg-warning/20"
                          }`}>
                            {tx.type === "earn" || tx.type === "receive" || tx.type === "reward" ? (
                              <ArrowDownLeft className="w-5 h-5 text-accent" />
                            ) : (
                              <ArrowUpRight className="w-5 h-5 text-warning" />
                            )}
                          </div>
                          <div>
                            <div className="font-bold">{tx.amount} {tx.currency}</div>
                            <div className="text-sm text-muted-foreground capitalize">{tx.description || tx.type}</div>
                          </div>
                        </div>
                        <div className="text-right">
                          <div className="text-sm text-muted-foreground">
                            {formatDistanceToNow(new Date(tx.created_at), { addSuffix: true })}
                          </div>
                        </div>
                      </div>
                    ))
                  ) : (
                    <div className="text-center py-8 text-muted-foreground">
                      <p>No transactions yet</p>
                    </div>
                  )}
                </TabsContent>

                <TabsContent value="sends" className="space-y-3 m-0">
                  {transactions.filter(tx => tx.type === "send" || tx.type === "transfer").length > 0 ? (
                    transactions.filter(tx => tx.type === "send" || tx.type === "transfer").map((tx) => (
                      <div key={tx.id} className="flex items-center justify-between p-4 bg-background/50 rounded-xl">
                        <div className="flex items-center gap-3">
                          <div className="w-10 h-10 rounded-full flex items-center justify-center bg-warning/20">
                            <ArrowUpRight className="w-5 h-5 text-warning" />
                          </div>
                          <div>
                            <div className="font-bold">{tx.amount} {tx.currency}</div>
                            <div className="text-sm text-muted-foreground capitalize">{tx.description || tx.type}</div>
                          </div>
                        </div>
                        <div className="text-right">
                          <div className="text-sm text-muted-foreground">
                            {formatDistanceToNow(new Date(tx.created_at), { addSuffix: true })}
                          </div>
                        </div>
                      </div>
                    ))
                  ) : (
                    <div className="text-center py-8 text-muted-foreground">
                      <p>No send transactions</p>
                    </div>
                  )}
                </TabsContent>

                <TabsContent value="receives" className="space-y-3 m-0">
                  {transactions.filter(tx => tx.type === "earn" || tx.type === "receive" || tx.type === "reward").length > 0 ? (
                    transactions.filter(tx => tx.type === "earn" || tx.type === "receive" || tx.type === "reward").map((tx) => (
                      <div key={tx.id} className="flex items-center justify-between p-4 bg-background/50 rounded-xl">
                        <div className="flex items-center gap-3">
                          <div className="w-10 h-10 rounded-full flex items-center justify-center bg-accent/20">
                            <ArrowDownLeft className="w-5 h-5 text-accent" />
                          </div>
                          <div>
                            <div className="font-bold">{tx.amount} {tx.currency}</div>
                            <div className="text-sm text-muted-foreground capitalize">{tx.description || tx.type}</div>
                          </div>
                        </div>
                        <div className="text-right">
                          <div className="text-sm text-muted-foreground">
                            {formatDistanceToNow(new Date(tx.created_at), { addSuffix: true })}
                          </div>
                        </div>
                      </div>
                    ))
                  ) : (
                    <div className="text-center py-8 text-muted-foreground">
                      <p>No receive transactions</p>
                    </div>
                  )}
                </TabsContent>
              </Tabs>
            </Card>

            {/* Action Buttons */}
            <div className="grid grid-cols-2 gap-3 pb-6">
              <Button 
                variant="default" 
                size="lg" 
                className="h-14"
                onClick={() => {
                  toast({
                    title: "Send Feature",
                    description: "Send SOL/XP feature coming soon!",
                  });
                }}
              >
                <ArrowUpRight className="w-5 h-5 mr-2" />
                Send
              </Button>
              <Button 
                variant="accent" 
                size="lg" 
                className="h-14"
                onClick={() => {
                  if (publicKey) {
                    navigator.clipboard.writeText(publicKey);
                    toast({
                      title: "Wallet Address Copied",
                      description: "Share this address to receive SOL/XP",
                    });
                  }
                }}
              >
                <ArrowDownLeft className="w-5 h-5 mr-2" />
                Receive
              </Button>
            </div>
          </TabsContent>

          <TabsContent value="leaderboard" className="space-y-3">
            {/* Current User Position (if not in top 50) */}
            {userRank && userRank > 50 && profile && (
              <Card className="p-4 bg-accent/20 border border-accent/30 mb-4">
                <div className="flex items-center gap-4">
                  <div className="w-10 h-10 rounded-full flex items-center justify-center font-bold text-lg bg-accent/30">
                    #{userRank}
                  </div>
                  <div className="text-3xl">👤</div>
                  <div className="flex-1">
                    <div className="font-bold">You</div>
                    <div className="text-sm text-muted-foreground">
                      Level {profile.level || 1} • {profile.xp.toLocaleString()} XP
                    </div>
                  </div>
                </div>
              </Card>
            )}

            {leaderboardData?.map((player, index) => {
              const isCurrentUser = player.id === user?.id;
              return (
                <div
                  key={player.id}
                  className={`p-4 rounded-xl flex items-center gap-4 ${
                    isCurrentUser ? "bg-accent/20 border border-accent/30" : "bg-card"
                  }`}
                >
                  <div
                    className={`w-10 h-10 rounded-full flex items-center justify-center font-bold text-lg ${
                      index === 0
                        ? "bg-warning text-warning-foreground"
                        : index === 1
                          ? "bg-muted text-foreground"
                          : index === 2
                            ? "bg-warning/50 text-warning-foreground"
                            : "bg-muted/50 text-muted-foreground"
                    }`}
                  >
                    {index + 1}
                  </div>
                  <div className="text-3xl">
                    {isCurrentUser ? "👤" : ["🏃", "👑", "🗺️", "🌙", "⚡", "🔥", "💪", "🎯", "🌟", "🏆"][index % 10]}
                  </div>
                  <div className="flex-1">
                    <div className="font-bold">{isCurrentUser ? "You" : (player.username || player.email?.split('@')[0] || "Anonymous")}</div>
                    <div className="text-sm text-muted-foreground">
                      Level {player.level || 1} • {player.xp.toLocaleString()} XP
                    </div>
                    <div className="text-xs text-muted-foreground mt-1">
                      {player.totalRuns} runs • {player.totalDistance?.toFixed(1) || 0} km
                    </div>
                  </div>
                </div>
              );
            })}
          </TabsContent>

          <TabsContent value="rewards" className="space-y-4">
            <div className="flex items-center gap-2 mb-4">
              <h3 className="text-xl font-bold">Rewards & Badges</h3>
              <Popover>
                <PopoverTrigger asChild>
                  <button className="text-muted-foreground hover:text-primary transition-colors">
                    <HelpCircle className="w-5 h-5" />
                  </button>
                </PopoverTrigger>
                <PopoverContent className="w-80">
                  <div className="space-y-2">
                    <h4 className="font-semibold text-sm">Rewards & Badges System</h4>
                    <p className="text-xs text-muted-foreground">
                      Unlock exclusive badges and rewards as you level up and complete milestones!
                    </p>
                    <div className="pt-2 border-t space-y-1 text-xs">
                      <div>• <strong>Level Badges:</strong> Unlock new badges every 5 levels</div>
                      <div>• <strong>Achievement Badges:</strong> Complete special challenges</div>
                      <div>• <strong>NFTs:</strong> Mint Land NFTs for runs over 0.5km</div>
                      <div>• <strong>SOL Rewards:</strong> Earn crypto by completing sponsored tasks</div>
                    </div>
                  </div>
                </PopoverContent>
              </Popover>
            </div>
            <div className="container mx-auto px-4 py-6">
              {user?.id && <RewardsSection userLevel={level} />}
            </div>
          </TabsContent>
        </Tabs>
      </div>

      {/* Proof Dialog */}
      {selectedProofTask && selectedProofUserTaskId && <TaskProofDialog open={showProofDialog} onOpenChange={setShowProofDialog} taskId={selectedProofTask.id} userTaskId={selectedProofUserTaskId} taskLocation={{
      lat: selectedProofTask.lat,
      lon: selectedProofTask.lon,
      radius_m: selectedProofTask.radius_m || 50
    }} onProofSubmitted={() => {
      setShowProofDialog(false);
      window.location.reload();
    }} />}

      {/* Runny - AI Fitness Assistant */}
      <FloatingMascot 
        mood={level > 5 ? "cheering" : "hype"}
        message={level === 1 ? "Hey! I'm Runny, your AI fitness buddy! Let's get moving!" : level > 10 ? "You're crushing it! Keep going!" : "Ready for today's challenge?"}
      />

      <BottomNav />
    </div>;
};
export default Dashboard;