import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { supabase } from "@/integrations/supabase/client";
import { useAuth } from "@/contexts/AuthContext";
import { useToast } from "@/hooks/use-toast";
import TasksMap from "@/components/TasksMap";
import BottomNav from "@/components/BottomNav";
import { TaskVerificationDialog } from "@/components/TaskVerificationDialog";
import { CreateSponsoredTaskDialog } from "@/components/CreateSponsoredTaskDialog";
import { TaskProofDialog } from "@/components/TaskProofDialog";
import { TaskProofsList } from "@/components/TaskProofsList";
import { MapPin, Camera, Share2, CheckCircle2, Clock, Zap, Coins, Navigation, X as XIcon, Loader2, Sparkles, Award, Filter, Search, Upload, Twitter, Facebook, Linkedin, RefreshCw, Store, HelpCircle } from "lucide-react";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { FloatingMascot } from "@/components/FloatingMascot";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { RentPaymentDialog } from "@/components/RentPaymentDialog";
import { useParcelInfo } from "@/hooks/useParcelInfo";

const Tasks = () => {
  const navigate = useNavigate();
  const { user } = useAuth();
  const { toast } = useToast();
  const [loading, setLoading] = useState(false);
  const [myPersonalTasks, setMyPersonalTasks] = useState<any[]>([]);
  const [myAcceptedTasks, setMyAcceptedTasks] = useState<any[]>([]);
  const [marketplaceTasks, setMarketplaceTasks] = useState<any[]>([]);
  const [filteredTasks, setFilteredTasks] = useState<any[]>([]);
  const [dailyTasksRemaining, setDailyTasksRemaining] = useState(3);
  const [dailyTasksCompleted, setDailyTasksCompleted] = useState(0);
  const [totalXP, setTotalXP] = useState(0);
  const [totalSOL, setTotalSOL] = useState(0);
  const [selectedTask, setSelectedTask] = useState<any>(null);
  const [selectedTaskDetail, setSelectedTaskDetail] = useState<any>(null);
  const [verifyingTask, setVerifyingTask] = useState<any>(null);
  const [verifyingUserTaskId, setVerifyingUserTaskId] = useState<string | null>(null);
  const [checkingIn, setCheckingIn] = useState(false);
  const [generatingTasks, setGeneratingTasks] = useState(false);
  const [showProofDialog, setShowProofDialog] = useState(false);
  const [selectedProofTask, setSelectedProofTask] = useState<any>(null);
  const [selectedProofUserTaskId, setSelectedProofUserTaskId] = useState<string | null>(null);
  const [isGenerateDialogOpen, setIsGenerateDialogOpen] = useState(false);
  const [showRentDialog, setShowRentDialog] = useState(false);
  const [rentTaskInfo, setRentTaskInfo] = useState<any>(null);
  
  // Marketplace state
  const [cityFilter, setCityFilter] = useState<string>("all");
  const [typeFilter, setTypeFilter] = useState<string>("all");
  const [rewardFilter, setRewardFilter] = useState<string>("all");
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [availableCities, setAvailableCities] = useState<string[]>([]);

  const loadMyPersonalTasks = async () => {
    if (!user) return;
    const { data, error } = await supabase
      .from("tasks")
      .select("*, pools(*)")
      .eq("creator_id", user.id)
      .is("pool_id", null)
      .order("created_at", { ascending: false });
    
    if (error) {
      console.error("Error loading personal tasks:", error);
      return;
    }
    setMyPersonalTasks(data || []);
  };

  const loadMyAcceptedTasks = async () => {
    if (!user) return;
    const { data, error } = await supabase
      .from("user_tasks")
      .select("*, tasks(*)")
      .eq("user_id", user.id)
      .order("joined_at", { ascending: false });
    
    if (error) {
      console.error("Error loading accepted tasks:", error);
      return;
    }
    
    console.log("My Accepted Tasks loaded:", data);
    setMyAcceptedTasks(data || []);
    
    // Calculate completed today
    const today = new Date().toISOString().split("T")[0];
    const completedToday = (data || []).filter(
      (t: any) => t.status === "completed" && t.completed_at?.startsWith(today)
    ).length;
    setDailyTasksCompleted(completedToday);
  };

  const loadMarketplaceTasks = async () => {
    if (!user) return;

    // Get tasks that user has accepted
    const { data: acceptedTaskIds } = await supabase
      .from("user_tasks")
      .select("task_id")
      .eq("user_id", user.id);

    const acceptedIds = acceptedTaskIds?.map(ut => ut.task_id) || [];

    // Get all marketplace tasks (sponsored or shared to community)
    const { data, error } = await supabase
      .from("tasks")
      .select("*, pools(*)")
      .eq("status", "published")
      .or(`pool_id.not.is.null,is_shared_to_community.eq.true`)
      .order("created_at", { ascending: false });

    if (error) {
      console.error("Error loading marketplace tasks:", error);
      return;
    }

    // Filter out tasks user has already accepted
    const marketplace = data?.filter(task => !acceptedIds.includes(task.id)) || [];
    setMarketplaceTasks(marketplace);
    setFilteredTasks(marketplace);

    const cities = [...new Set(marketplace.map(t => t.city).filter(Boolean))];
    setAvailableCities(cities as string[]);
  };

  // Filter tasks based on selected filters
  useEffect(() => {
    let filtered = [...marketplaceTasks];
    
    // City filter
    if (cityFilter !== "all") {
      filtered = filtered.filter(t => t.city === cityFilter);
    }
    
    // Type filter
    if (typeFilter !== "all") {
      filtered = filtered.filter(t => t.type === typeFilter);
    }
    
    // Reward filter
    if (rewardFilter === "sol") {
      filtered = filtered.filter(t => (t.sol_reward || 0) > 0);
    } else if (rewardFilter === "xp") {
      filtered = filtered.filter(t => (t.xp_reward || 0) > 0);
    }
    
    // Search filter
    if (searchQuery) {
      filtered = filtered.filter(t => 
        t.title?.toLowerCase().includes(searchQuery.toLowerCase()) ||
        t.name?.toLowerCase().includes(searchQuery.toLowerCase()) ||
        t.description?.toLowerCase().includes(searchQuery.toLowerCase()) ||
        t.city?.toLowerCase().includes(searchQuery.toLowerCase())
      );
    }
    
    setFilteredTasks(filtered);
  }, [cityFilter, typeFilter, rewardFilter, searchQuery, marketplaceTasks]);

  const loadDailyLimit = async () => {
    if (!user) return;
    const { data } = await supabase
      .from("profiles")
      .select("daily_task_count, last_task_date")
      .eq("id", user.id)
      .single();
    
    const today = new Date().toISOString().split("T")[0];
    const remaining = data?.last_task_date === today ? 3 - (data?.daily_task_count || 0) : 3;
    setDailyTasksRemaining(remaining);
  };

  const loadStats = async () => {
    if (!user) return;
    const { data: profile } = await supabase
      .from("profiles")
      .select("xp")
      .eq("id", user.id)
      .single();
    
    setTotalXP(profile?.xp || 0);
    
    // Calculate total SOL earned
    const { data: tasks } = await supabase
      .from("user_tasks")
      .select("sol_awarded")
      .eq("user_id", user.id)
      .eq("status", "completed");
    
    const solTotal = (tasks || []).reduce((sum: number, t: any) => sum + (t.sol_awarded || 0), 0);
    setTotalSOL(solTotal);
  };

  useEffect(() => { 
    if (user) {
      loadMyPersonalTasks();
      loadMyAcceptedTasks();
      loadMarketplaceTasks();
      loadDailyLimit();
      loadStats();
    }
  }, [user]);

  const handleTaskSelect = async (task: any) => {
    setSelectedTask(task);
    setSelectedTaskDetail(task);
  };

  const handleCloseTaskModal = () => {
    setSelectedTask(null);
    setSelectedTaskDetail(null);
  };

  const handleGenerateTasks = async () => {
    if (!user) {
      toast({ title: "Login Required", description: "Please log in to generate tasks", variant: "destructive" });
      return;
    }

    if (dailyTasksRemaining <= 0) {
      toast({ 
        title: "Daily Limit Reached", 
        description: "You've used all 3 task generation slots today. Come back tomorrow!",
        variant: "destructive" 
      });
      return;
    }

    setGeneratingTasks(true);
    try {
      // Get user's current location
      const position = await new Promise<GeolocationPosition>((resolve, reject) => {
        navigator.geolocation.getCurrentPosition(resolve, reject, {
          enableHighAccuracy: true,
          timeout: 10000,
          maximumAge: 0
        });
      });

      const { data, error } = await supabase.functions.invoke("generate-location-task", {
        body: { 
          userId: user.id, 
          lat: position.coords.latitude, 
          lon: position.coords.longitude, 
          count: 3 
        }
      });

      if (error) throw error;

      if (data.limit_reached) {
        toast({ 
          title: "Daily Limit Reached", 
          description: "You can only generate tasks 3 times per day",
          variant: "destructive" 
        });
        return;
      }

      toast({
        title: "Tasks Generated! 🎯",
        description: `${data.tasks?.length || 0} new AI tasks created in ${data.city}!`,
      });

      setIsGenerateDialogOpen(false);
      loadMyPersonalTasks();
      loadDailyLimit();
    } catch (error: any) {
      if (error.code === 1) {
        toast({
          title: "Location Permission Denied",
          description: "Please enable location access to generate tasks",
          variant: "destructive"
        });
      } else {
        toast({
          title: "Generation Failed",
          description: error.message || "Failed to generate tasks",
          variant: "destructive"
        });
      }
    } finally {
      setGeneratingTasks(false);
    }
  };

  const handleAcceptTask = async (task: any, bypassRentDialog = false) => {
    if (!user) {
      toast({ title: "Login Required", description: "Please log in to accept tasks", variant: "destructive" });
      return;
    }

    // Check if task requires rent and we haven't bypassed the dialog
    if (task.requires_rent && task.parcel_id && !bypassRentDialog) {
      setRentTaskInfo(task);
      setShowRentDialog(true);
      return;
    }

    setLoading(true);
    try {
      const { data, error } = await supabase.functions.invoke("join-task", {
        body: { userId: user.id, taskId: task.id },
      });

      if (error) throw error;

      if (data.limit_reached) {
        toast({ 
          title: "Daily Limit Reached", 
          description: "You can only accept 3 tasks per day",
          variant: "destructive" 
        });
        return;
      }

      toast({ 
        title: "Task Accepted! 🎯", 
        description: `Task added to My Tasks. ${data.remaining_today} remaining today`,
      });
      
      loadMyAcceptedTasks();
      loadMarketplaceTasks();
      loadDailyLimit();
      handleCloseTaskModal();
    } catch (error: any) {
      toast({ title: "Error", description: error.message, variant: "destructive" });
    } finally {
      setLoading(false);
    }
  };

  const handleCheckIn = async (task: any, userTaskId: string) => {
    if (!user) return;
    
    setCheckingIn(true);
    try {
      // Get user's current location
      const position = await new Promise<GeolocationPosition>((resolve, reject) => {
        navigator.geolocation.getCurrentPosition(resolve, reject, {
          enableHighAccuracy: true,
          timeout: 10000,
          maximumAge: 0
        });
      });

      const userLat = position.coords.latitude;
      const userLon = position.coords.longitude;
      const taskLat = task.lat;
      const taskLon = task.lon;
      
      // Calculate distance using Haversine formula
      const R = 6371e3; // Earth's radius in meters
      const φ1 = (userLat * Math.PI) / 180;
      const φ2 = (taskLat * Math.PI) / 180;
      const Δφ = ((taskLat - userLat) * Math.PI) / 180;
      const Δλ = ((taskLon - userLon) * Math.PI) / 180;

      const a = Math.sin(Δφ / 2) * Math.sin(Δφ / 2) +
                Math.cos(φ1) * Math.cos(φ2) *
                Math.sin(Δλ / 2) * Math.sin(Δλ / 2);
      const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
      const distance = R * c;

      const radiusM = task.radius_m || 30;

      if (distance > radiusM) {
        toast({
          title: "Too Far! 📍",
          description: `You're ${Math.round(distance)}m away. Get within ${radiusM}m to check-in.`,
          variant: "destructive"
        });
        return;
      }

      // Update task as completed
      const { error } = await supabase
        .from("user_tasks")
        .update({ 
          status: "completed",
          completed_at: new Date().toISOString(),
          geo_meta: { lat: userLat, lon: userLon, distance: Math.round(distance) }
        })
        .eq("id", userTaskId);

      if (error) throw error;

      // Award XP
      await supabase.rpc("increment_xp", {
        user_id: user.id,
        xp_amount: task.xp_reward || 0
      });

      toast({
        title: "Check-in Successful! ✅",
        description: `Earned ${task.xp_reward} XP! You were ${Math.round(distance)}m away.`,
      });

      loadMyAcceptedTasks();
      loadStats();
      handleCloseTaskModal();
    } catch (error: any) {
      if (error.code === 1) {
        toast({
          title: "Location Permission Denied",
          description: "Please enable location access to check-in",
          variant: "destructive"
        });
      } else {
        toast({
          title: "Check-in Failed",
          description: error.message,
          variant: "destructive"
        });
      }
    } finally {
      setCheckingIn(false);
    }
  };

  const handleCancelTask = async (userTaskId: string) => {
    if (!user) return;
    
    try {
      const { error } = await supabase
        .from("user_tasks")
        .delete()
        .eq("id", userTaskId);

      if (error) throw error;

      toast({ 
        title: "Task Cancelled", 
        description: "Task removed from your list",
      });

      loadMyAcceptedTasks();
      loadMarketplaceTasks();
      handleCloseTaskModal();
    } catch (error: any) {
      toast({ title: "Error", description: error.message, variant: "destructive" });
    }
  };

  const handleShareTask = async (userTaskData: any) => {
    const task = userTaskData.tasks;
    navigate(`/share/${task.id}`);
  };

  const handleShareToSocial = (platform: string, task: any, userTask?: any) => {
    const appUrl = window.location.origin;
    const taskUrl = `${appUrl}/share/${task.id}`;
    const text = userTask 
      ? `I just completed "${task.name || task.title}" and earned ${userTask.xp_awarded || task.xp_reward} XP! 🎯` 
      : `Check out this task: "${task.name || task.title}" - Earn ${task.xp_reward} XP! 🎯`;
    
    let shareUrl = '';
    
    switch(platform) {
      case 'twitter':
        shareUrl = `https://twitter.com/intent/tweet?text=${encodeURIComponent(text)}&url=${encodeURIComponent(taskUrl)}`;
        break;
      case 'facebook':
        shareUrl = `https://www.facebook.com/sharer/sharer.php?u=${encodeURIComponent(taskUrl)}`;
        break;
      case 'linkedin':
        shareUrl = `https://www.linkedin.com/sharing/share-offsite/?url=${encodeURIComponent(taskUrl)}`;
        break;
    }
    
    if (shareUrl) {
      window.open(shareUrl, '_blank', 'width=600,height=400');
    }
  };

  const isTaskAccepted = (taskId: string) => {
    return myAcceptedTasks.some(ut => ut.task_id === taskId);
  };

  return (
    <div className="min-h-screen bg-background pb-20">
      <div className="container max-w-7xl mx-auto p-4 space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <h1 className="text-3xl font-bold text-foreground">
            Tasks
          </h1>
        </div>

        {/* Stats Cards */}
        <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
          <Card className="bg-card border border-border p-4">
            <div className="flex items-center gap-2 mb-1">
              <Clock className="w-4 h-4 text-primary" />
              <span className="text-xs text-muted-foreground">Daily Progress</span>
            </div>
            <div className="text-2xl font-bold">{dailyTasksCompleted}/3</div>
            <Badge variant={dailyTasksRemaining > 0 ? "default" : "destructive"} className="mt-1">
              {dailyTasksRemaining} left
            </Badge>
          </Card>

          <Card className="bg-card border border-border p-4">
            <div className="flex items-center gap-2 mb-1">
              <Zap className="w-4 h-4 text-primary" />
              <span className="text-xs text-muted-foreground">Total XP</span>
            </div>
            <div className="text-2xl font-bold text-primary">{totalXP}</div>
          </Card>

          <Card className="bg-card border border-border p-4">
            <div className="flex items-center gap-2 mb-1">
              <Coins className="w-4 h-4 text-yellow-500" />
              <span className="text-xs text-muted-foreground">Total SOL</span>
            </div>
            <div className="text-2xl font-bold text-yellow-500">{totalSOL.toFixed(2)}</div>
          </Card>
        </div>

        {/* Tabs */}
        <Tabs defaultValue="personal" className="w-full">
          <TabsList className="grid w-full grid-cols-2 bg-muted">
            <TabsTrigger value="personal" className="data-[state=active]:bg-background">
              <Sparkles className="mr-2 h-4 w-4" />
              My AI Tasks
            </TabsTrigger>
            <TabsTrigger value="marketplace" className="data-[state=active]:bg-background">
              <Store className="mr-2 h-4 w-4" />
              Marketplace
            </TabsTrigger>
          </TabsList>

          {/* Personal Tasks Tab */}
          <TabsContent value="personal" className="space-y-4 mt-4">
            {/* Generate AI Tasks */}
            <Card className="bg-card border border-border p-6">
              <Dialog open={isGenerateDialogOpen} onOpenChange={setIsGenerateDialogOpen}>
                <DialogTrigger asChild>
                  <Button className="w-full bg-primary hover:bg-primary/90 h-12" disabled={dailyTasksRemaining === 0}>
                    <Sparkles className="mr-2 h-5 w-5" />
                    Generate AI Tasks ({dailyTasksRemaining}/3)
                  </Button>
                </DialogTrigger>
                <DialogContent className="bg-background border border-border">
                  <DialogHeader>
                    <DialogTitle>Generate AI Tasks</DialogTitle>
                  </DialogHeader>
                  <div className="space-y-4">
                    <p className="text-sm text-muted-foreground">
                      AI will generate 3 personalized tasks based on your current location.
                    </p>
                    <Button 
                      onClick={handleGenerateTasks} 
                      disabled={generatingTasks}
                      className="w-full bg-primary hover:bg-primary/90"
                    >
                      {generatingTasks ? (
                        <>
                          <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                          Generating...
                        </>
                      ) : (
                        <>
                          <Sparkles className="mr-2 h-4 w-4" />
                          Generate Now
                        </>
                      )}
                    </Button>
                  </div>
                </DialogContent>
              </Dialog>
            </Card>

            {/* My AI Generated Tasks */}
            <Card className="bg-card border border-border p-6">
              <div className="flex items-center gap-2 mb-4">
                <Sparkles className="h-5 w-5 text-primary" />
                <h2 className="text-xl font-bold">
                  My AI Generated Tasks ({myPersonalTasks.length})
                </h2>
                <Popover>
                  <PopoverTrigger asChild>
                    <button className="text-muted-foreground hover:text-primary transition-colors">
                      <HelpCircle className="w-5 h-5" />
                    </button>
                  </PopoverTrigger>
                  <PopoverContent className="w-80">
                    <div className="space-y-2">
                      <h4 className="font-semibold text-sm">My AI Tasks System</h4>
                      <p className="text-xs text-muted-foreground">
                        Generate personalized AI tasks based on your location. These tasks are private to you unless you share them.
                      </p>
                      <div className="pt-2 border-t space-y-1 text-xs">
                        <div>• <strong>Daily Limit:</strong> Generate up to 3 times per day</div>
                        <div>• <strong>Location-Based:</strong> Tasks are created for nearby points of interest</div>
                        <div>• <strong>AI-Powered:</strong> Each task is uniquely generated for you</div>
                        <div>• <strong>Share Option:</strong> Share your tasks with the community</div>
                      </div>
                    </div>
                  </PopoverContent>
                </Popover>
              </div>
              {myPersonalTasks.length === 0 ? (
                <div className="text-center py-8">
                  <Sparkles className="w-12 h-12 mx-auto mb-3 opacity-30" />
                  <p className="text-muted-foreground">No AI tasks yet</p>
                  <p className="text-xs text-muted-foreground mt-1">Generate some tasks to get started!</p>
                </div>
              ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {myPersonalTasks.map((task) => (
                    <Card key={task.id} className="p-4 bg-background border border-border hover:border-primary transition-colors cursor-pointer" onClick={() => handleTaskSelect(task)}>
                      <h3 className="font-semibold text-lg">{task.title}</h3>
                      <p className="text-sm text-muted-foreground mt-1 line-clamp-2">{task.description}</p>
                      <div className="flex items-center gap-2 mt-3">
                        <Badge variant="secondary" className="flex items-center gap-1">
                          <MapPin className="h-3 w-3" />
                          {task.location_name || task.city}
                        </Badge>
                        <Badge className="bg-primary text-primary-foreground">{task.xp_reward} XP</Badge>
                      </div>
                    </Card>
                  ))}
                </div>
              )}
            </Card>

            {/* Accepted Tasks */}
            <Card className="bg-card border border-border p-6">
              <h2 className="text-xl font-bold mb-4 flex items-center gap-2">
                <CheckCircle2 className="h-5 w-5 text-green-500" />
                Accepted Tasks ({myAcceptedTasks.length})
              </h2>
              {myAcceptedTasks.length === 0 ? (
                <div className="text-center py-8">
                  <CheckCircle2 className="w-12 h-12 mx-auto mb-3 opacity-30" />
                  <p className="text-muted-foreground">No accepted tasks yet</p>
                  <p className="text-xs text-muted-foreground mt-1">Check the marketplace to accept tasks!</p>
                </div>
              ) : (
                <div className="space-y-3">
                  {myAcceptedTasks.map((ut) => {
                    const task = ut.tasks;
                    if (!task) return null;
                    const isPending = ut.status === 'pending';
                    const isCompleted = ut.status === 'completed';
                    
                    return (
                      <Card 
                        key={ut.id} 
                        className={`p-4 bg-background transition-all ${
                          isPending ? 'border-2 border-yellow-500' : 
                          isCompleted ? 'border-2 border-green-500' : 'border border-border'
                        }`}
                      >
                        <div className="flex gap-3">
                          <div className={`p-3 rounded-lg ${
                            isCompleted ? 'bg-green-500/20' : 
                            isPending ? 'bg-yellow-500/20' : 'bg-muted'
                          }`}>
                            {isCompleted ? (
                              <CheckCircle2 className="w-6 h-6 text-green-500" />
                            ) : isPending ? (
                              <Clock className="w-6 h-6 text-yellow-500" />
                            ) : (
                              <Clock className="w-6 h-6" />
                            )}
                          </div>
                          <div className="flex-1">
                            <h4 className="font-bold">{task.name || task.title}</h4>
                            {task.location_name && (
                              <p className="text-xs text-muted-foreground flex items-center gap-1 mt-1">
                                <MapPin className="w-3 h-3" />
                                {task.location_name}
                              </p>
                            )}
                            <div className="flex gap-2 mt-2">
                              <Badge variant={isCompleted ? "default" : "outline"}>
                                {ut.status}
                              </Badge>
                              <Badge className="bg-accent">
                                +{ut.xp_awarded || task.xp_reward} XP
                              </Badge>
                              {(ut.sol_awarded || task.sol_reward) > 0 && (
                                <Badge className="bg-yellow-400 text-black">
                                  {ut.sol_awarded || task.sol_reward} SOL
                                </Badge>
                              )}
                            </div>
                            
                            <div className="flex gap-2 mt-4">
                              {isPending && task.type === 'qr_checkin' && (
                                <Button 
                                  onClick={() => handleCheckIn(task, ut.id)}
                                  disabled={checkingIn}
                                  className="flex-1"
                                >
                                  {checkingIn ? (
                                    <><Loader2 className="w-4 h-4 mr-2 animate-spin" />Checking...</>
                                  ) : (
                                    <><Navigation className="w-4 h-4 mr-2" />Check-in</>
                                  )}
                                </Button>
                              )}
                              
                              {isPending && task.type !== 'qr_checkin' && (
                                <>
                                  <Button 
                                    onClick={() => {
                                      setSelectedProofTask(task);
                                      setSelectedProofUserTaskId(ut.id);
                                      setShowProofDialog(true);
                                    }} 
                                    className="flex-1 bg-primary hover:bg-primary/90"
                                  >
                                    <Upload className="w-4 h-4 mr-2" />
                                    Submit Proof
                                  </Button>
                                  <Button
                                    onClick={() => handleCancelTask(ut.id)}
                                    variant="outline"
                                    size="icon"
                                  >
                                    <XIcon className="w-4 h-4" />
                                  </Button>
                                </>
                              )}
                              
                              {isCompleted && (
                                <div className="flex gap-2 w-full">
                                  <Button 
                                    onClick={() => handleShareToSocial('twitter', task, ut)}
                                    variant="outline" 
                                    size="icon"
                                  >
                                    <Twitter className="w-4 h-4" />
                                  </Button>
                                  <Button 
                                    onClick={() => {
                                      setSelectedProofTask(task);
                                      setSelectedProofUserTaskId(ut.id);
                                      setShowProofDialog(true);
                                    }} 
                                    variant="secondary"
                                    className="flex-1"
                                  >
                                    <Upload className="w-4 h-4 mr-2" />
                                    Add Proof
                                  </Button>
                                </div>
                              )}
                            </div>
                          </div>
                        </div>
                      </Card>
                    );
                  })}
                </div>
              )}
            </Card>
          </TabsContent>

          {/* Marketplace Tab */}
          <TabsContent value="marketplace" className="space-y-4 mt-4">
            {/* Create Sponsored Task */}
            <Card className="bg-card border border-border p-6">
              <CreateSponsoredTaskDialog />
            </Card>

            {/* Filters */}
            <Card className="bg-card border border-border p-4">
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                <div className="relative">
                  <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                  <Input
                    placeholder="Search tasks..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    className="pl-10"
                  />
                </div>
                
                <Select value={cityFilter} onValueChange={setCityFilter}>
                  <SelectTrigger>
                    <SelectValue placeholder="All Cities" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Cities</SelectItem>
                    {availableCities.map((city) => (
                      <SelectItem key={city} value={city}>{city}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>

                <Select value={typeFilter} onValueChange={setTypeFilter}>
                  <SelectTrigger>
                    <SelectValue placeholder="All Types" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Types</SelectItem>
                    <SelectItem value="photo_task">Photo</SelectItem>
                    <SelectItem value="selfie">Selfie</SelectItem>
                    <SelectItem value="qr_checkin">QR Check-in</SelectItem>
                  </SelectContent>
                </Select>

                <Select value={rewardFilter} onValueChange={setRewardFilter}>
                  <SelectTrigger>
                    <SelectValue placeholder="All Rewards" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Rewards</SelectItem>
                    <SelectItem value="sol">SOL Only</SelectItem>
                    <SelectItem value="xp">XP Only</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </Card>

            {/* Marketplace Tasks */}
            <Card className="bg-card border border-border p-6">
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-2">
                  <Store className="h-5 w-5 text-primary" />
                  <h2 className="text-xl font-bold">
                    Community Marketplace ({filteredTasks.length})
                  </h2>
                  <Popover>
                    <PopoverTrigger asChild>
                      <button className="text-muted-foreground hover:text-primary transition-colors">
                        <HelpCircle className="w-5 h-5" />
                      </button>
                    </PopoverTrigger>
                    <PopoverContent className="w-80">
                      <div className="space-y-2">
                        <h4 className="font-semibold text-sm">Marketplace System</h4>
                        <p className="text-xs text-muted-foreground">
                          Accept public tasks from the community and sponsors. Complete them to earn XP and SOL rewards!
                        </p>
                        <div className="pt-2 border-t space-y-1 text-xs">
                          <div>• <strong>Daily Limit:</strong> Accept up to 3 tasks per day</div>
                          <div>• <strong>Sponsored Tasks:</strong> Earn real SOL cryptocurrency</div>
                          <div>• <strong>Community Tasks:</strong> Tasks shared by other users</div>
                          <div>• <strong>Filters:</strong> Search by city, type, and rewards</div>
                          <div>• <strong>Verification:</strong> Submit proof to complete tasks</div>
                        </div>
                      </div>
                    </PopoverContent>
                  </Popover>
                </div>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={loadMarketplaceTasks}
                >
                  <RefreshCw className="h-4 w-4 mr-2" />
                  Refresh
                </Button>
              </div>

              {filteredTasks.length === 0 ? (
                <div className="text-center py-8">
                  <Store className="w-12 h-12 mx-auto mb-3 opacity-30" />
                  <p className="text-muted-foreground">No tasks available</p>
                  <p className="text-xs text-muted-foreground mt-1">Try adjusting your filters</p>
                </div>
              ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                  {filteredTasks.map((task) => (
                    <Card key={task.id} className="p-4 bg-background border border-border hover:border-primary transition-colors">
                      <div className="space-y-3">
                        <div>
                          <h3 className="font-semibold text-lg">{task.title || task.name}</h3>
                          <p className="text-sm text-muted-foreground line-clamp-2 mt-1">
                            {task.description}
                          </p>
                        </div>

                        <div className="flex flex-wrap gap-2">
                          <Badge variant="secondary" className="flex items-center gap-1">
                            <MapPin className="h-3 w-3" />
                            {task.location_name || task.city}
                          </Badge>
                          <Badge variant="outline">{task.type.replace(/_/g, ' ')}</Badge>
                          {task.pools && (
                            <Badge className="bg-yellow-500 text-black">
                              Sponsored
                            </Badge>
                          )}
                          {task.requires_rent && (
                            <Badge className="bg-orange-500 text-white flex items-center gap-1">
                              <Coins className="h-3 w-3" />
                              Rent Required
                            </Badge>
                          )}
                        </div>

                        <div className="flex items-center justify-between">
                          <div className="space-y-1">
                            {task.requires_rent && (
                              <div className="flex items-center gap-1 text-sm font-semibold text-orange-500">
                                <Coins className="h-4 w-4" />
                                {task.rent_amount_usdc} USDC
                              </div>
                            )}
                            {task.pools && (
                              <div className="flex items-center gap-1 text-sm font-semibold text-yellow-400">
                                <Coins className="h-4 w-4" />
                                {task.pools.total_funded_sol} SOL
                              </div>
                            )}
                            {task.xp_reward > 0 && (
                              <div className="flex items-center gap-1 text-sm text-primary">
                                <Zap className="h-4 w-4" />
                                {task.xp_reward} XP
                              </div>
                            )}
                          </div>

                          <div className="flex gap-2">
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={() => handleTaskSelect(task)}
                            >
                              View
                            </Button>
                            {!isTaskAccepted(task.id) && (
                              <Button
                                size="sm"
                                onClick={() => handleAcceptTask(task)}
                                className="bg-primary hover:bg-primary/90"
                              >
                                Accept
                              </Button>
                            )}
                          </div>
                        </div>
                      </div>
                    </Card>
                  ))}
                </div>
              )}
            </Card>
          </TabsContent>
        </Tabs>

        {/* Task Detail Modal */}
        {selectedTaskDetail && (
          <Dialog open={!!selectedTaskDetail} onOpenChange={(open) => !open && handleCloseTaskModal()}>
            <DialogContent className="bg-background border border-border max-w-2xl">
              <DialogHeader>
                <DialogTitle>{selectedTaskDetail.title || selectedTaskDetail.name}</DialogTitle>
              </DialogHeader>
              <div className="space-y-4">
                <p>{selectedTaskDetail.description}</p>
                <div className="flex flex-wrap gap-2">
                  <Badge variant="secondary">
                    <MapPin className="h-3 w-3 mr-1" />
                    {selectedTaskDetail.location_name || selectedTaskDetail.city}
                  </Badge>
                  <Badge className="bg-primary text-primary-foreground">
                    <Zap className="h-3 w-3 mr-1" />
                    {selectedTaskDetail.xp_reward} XP
                  </Badge>
                  {selectedTaskDetail.sol_reward > 0 && (
                    <Badge className="bg-yellow-500 text-black">
                      <Coins className="h-3 w-3 mr-1" />
                      {selectedTaskDetail.sol_reward} SOL
                    </Badge>
                  )}
                </div>
                {!isTaskAccepted(selectedTaskDetail.id) && (
                  <Button 
                    onClick={() => handleAcceptTask(selectedTaskDetail)}
                    className="w-full bg-primary hover:bg-primary/90"
                  >
                    Accept Task
                  </Button>
                )}
              </div>
            </DialogContent>
          </Dialog>
        )}

        {/* Task Proof Dialog */}
        {showProofDialog && selectedProofTask && selectedProofUserTaskId && (
          <TaskProofDialog
            open={showProofDialog}
            onOpenChange={(open) => {
              if (!open) {
                setShowProofDialog(false);
                setSelectedProofTask(null);
                setSelectedProofUserTaskId(null);
              }
            }}
            taskId={selectedProofTask.id}
            userTaskId={selectedProofUserTaskId}
            taskLocation={selectedProofTask.lat && selectedProofTask.lon ? {
              lat: selectedProofTask.lat,
              lon: selectedProofTask.lon,
              radius_m: selectedProofTask.radius_m
            } : undefined}
            onProofSubmitted={() => {
              setShowProofDialog(false);
              setSelectedProofTask(null);
              setSelectedProofUserTaskId(null);
              loadMyAcceptedTasks();
            }}
          />
        )}
      </div>

      {/* Rent Payment Dialog */}
      {rentTaskInfo && (
        <RentPaymentDialog
          open={showRentDialog}
          onOpenChange={setShowRentDialog}
          taskId={rentTaskInfo.id}
          parcelInfo={{
            parcel_id: rentTaskInfo.parcel_id,
            owner_id: rentTaskInfo.creator_id,
            rent_amount_usdc: rentTaskInfo.rent_amount_usdc || 0.10,
            rent_policy: 'per_run'
          }}
          onSuccess={async () => {
            await handleAcceptTask(rentTaskInfo, true);
            setShowRentDialog(false);
            setRentTaskInfo(null);
          }}
        />
      )}

      {/* Runny - AI Fitness Assistant */}
      <FloatingMascot 
        mood={myAcceptedTasks.length > 0 ? "hype" : "idle"}
        message={myAcceptedTasks.length === 0 ? "Ready to tackle some tasks? Let's go!" : myAcceptedTasks.some(t => t.status === 'completed') ? "Great job completing tasks!" : "You've got this! Complete those tasks!"}
      />

      <BottomNav />
    </div>
  );
};

export default Tasks;