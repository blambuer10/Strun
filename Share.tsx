import { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { supabase } from "@/integrations/supabase/client";
import { useToast } from "@/hooks/use-toast";
import { 
  MapPin, 
  Zap, 
  Share2, 
  Copy, 
  QrCode,
  ArrowLeft,
  Instagram,
  Twitter,
  Video,
  Users
} from "lucide-react";
import QRCode from "react-qr-code";

const Share = () => {
  const { taskId } = useParams();
  const navigate = useNavigate();
  const { toast } = useToast();
  const [task, setTask] = useState<any>(null);
  const [userTask, setUserTask] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [shareData, setShareData] = useState<any>(null);
  const [isSharing, setIsSharing] = useState(false);

  useEffect(() => {
    loadTaskAndShareData();
  }, [taskId]);

  const loadTaskAndShareData = async () => {
    try {
      setLoading(true);
      
      // Load task details
      const { data: taskData, error: taskError } = await supabase
        .from("tasks")
        .select("*, pools(*)")
        .eq("id", taskId)
        .single();

      if (taskError) throw taskError;
      setTask(taskData);

      // Load user task completion
      const { data: userData } = await supabase.auth.getUser();
      if (userData.user) {
        const { data: utData } = await supabase
          .from("user_tasks")
          .select("*")
          .eq("task_id", taskId)
          .eq("user_id", userData.user.id)
          .single();
        
        setUserTask(utData);
      }

      // Load share metadata
      const { data: shareMetadata, error: shareError } = await supabase.functions.invoke(
        "get-task-share",
        { body: { taskId } }
      );

      if (!shareError && shareMetadata) {
        setShareData(shareMetadata);
      }
    } catch (error: any) {
      console.error("Error loading task:", error);
      toast({
        title: "Error",
        description: "Failed to load task details",
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  };

  const handleCopyLink = () => {
    const shareUrl = `${window.location.origin}/share/${taskId}`;
    navigator.clipboard.writeText(shareUrl);
    toast({
      title: "Link Copied!",
      description: "Share link copied to clipboard",
    });
  };

  const handleShareX = () => {
    const text = `I just completed "${task?.title}" and earned ${userTask?.xp_awarded || task?.xp_reward} XP on Strun! 🏃‍♂️💪\n\nJoin me: ${window.location.origin}/share/${taskId}`;
    const url = `https://twitter.com/intent/tweet?text=${encodeURIComponent(text)}`;
    window.open(url, "_blank");
  };

  const handleShareInstagram = () => {
    toast({
      title: "Instagram Sharing",
      description: "Screenshot this page and share on Instagram with the link copied to clipboard!",
    });
    handleCopyLink();
  };

  const handleShareTikTok = () => {
    toast({
      title: "TikTok Sharing",
      description: "Create your video and add this link in description!",
    });
    handleCopyLink();
  };

  const handleShareToCommunity = async () => {
    try {
      setIsSharing(true);
      
      const { data: userData } = await supabase.auth.getUser();
      if (!userData.user) {
        toast({
          title: "Login Required",
          description: "Please login to share to community",
          variant: "destructive",
        });
        return;
      }

      const postContent = `I just completed "${task.title}" and earned ${userTask?.xp_awarded || task.xp_reward} XP! 🏃‍♂️💪\n\n${task.description}\n\n#StrunRun #TaskCompleted`;

      const { error } = await supabase.from("posts").insert({
        user_id: userData.user.id,
        content: postContent,
        location: task.city || task.location_name,
      });

      if (error) throw error;

      toast({
        title: "Shared to Community! 🎉",
        description: "Your task completion has been shared with the community",
      });

      setTimeout(() => navigate("/community"), 1500);
    } catch (error: any) {
      console.error("Error sharing to community:", error);
      toast({
        title: "Error",
        description: error.message || "Failed to share to community",
        variant: "destructive",
      });
    } finally {
      setIsSharing(false);
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="text-center">
          <div className="w-16 h-16 border-4 border-primary/30 border-t-primary rounded-full animate-spin mx-auto mb-4" />
          <p className="text-muted-foreground">Loading task...</p>
        </div>
      </div>
    );
  }

  if (!task) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <Card className="p-8 text-center">
          <p className="text-muted-foreground mb-4">Task not found</p>
          <Button onClick={() => navigate("/tasks")}>
            <ArrowLeft className="w-4 h-4 mr-2" />
            Back to Tasks
          </Button>
        </Card>
      </div>
    );
  }

  const shareUrl = `${window.location.origin}/share/${taskId}`;

  return (
    <div className="min-h-screen bg-background pb-8">
      {/* Header */}
      <header className="border-b border-border/50 bg-card backdrop-blur-lg p-4 sticky top-0 z-50">
        <div className="container mx-auto flex items-center justify-between">
          <Button variant="ghost" size="icon" onClick={() => navigate("/tasks")}>
            <ArrowLeft className="w-5 h-5" />
          </Button>
          <h1 className="font-display font-bold text-lg">Share Task</h1>
          <div className="w-10" />
        </div>
      </header>

      <div className="container mx-auto px-4 py-6 max-w-2xl space-y-6">
        {/* Task Preview Card */}
        <Card className="p-6 glass border-primary/30 relative overflow-hidden">
          <div className="absolute top-0 right-0 w-32 h-32 bg-accent/10 rounded-full blur-3xl" />
          <div className="relative">
            <div className="flex items-center gap-3 mb-4">
              <div className="p-3 rounded-full bg-accent/20">
                <Zap className="w-6 h-6 text-accent" />
              </div>
              <div className="flex-1">
                <h2 className="font-display font-bold text-xl">{task.title}</h2>
                {task.location_name && (
                  <p className="text-sm text-muted-foreground flex items-center gap-1">
                    <MapPin className="w-3 h-3" />
                    {task.location_name}
                  </p>
                )}
              </div>
            </div>

            <p className="text-muted-foreground mb-4">{task.description}</p>

            {/* Rewards */}
            <div className="flex gap-2 flex-wrap">
              <Badge className="bg-accent/20 text-accent border-accent/30">
                <Zap className="w-3 h-3 mr-1" />
                +{userTask?.xp_awarded || task.xp_reward} XP
              </Badge>
              {(userTask?.sol_awarded || task.sol_reward) > 0 && (
                <Badge className="bg-success/20 text-success border-success/30">
                  💎 {userTask?.sol_awarded || task.sol_reward} SOL
                </Badge>
              )}
              {userTask?.status === "completed" && (
                <Badge className="bg-primary/20 text-primary border-primary/30">
                  ✓ Completed
                </Badge>
              )}
            </div>
          </div>
        </Card>

        {/* QR Code Card */}
        <Card className="p-6 glass">
          <h3 className="font-display font-bold text-lg mb-4 flex items-center gap-2">
            <QrCode className="w-5 h-5 text-primary" />
            QR Code
          </h3>
          <div className="bg-white p-4 rounded-lg w-fit mx-auto">
            <QRCode value={shareUrl} size={200} />
          </div>
          <p className="text-sm text-muted-foreground text-center mt-3">
            Scan to view this task
          </p>
        </Card>

        {/* Share Actions */}
        <Card className="p-6 glass">
          <h3 className="font-display font-bold text-lg mb-4 flex items-center gap-2">
            <Share2 className="w-5 h-5 text-primary" />
            Share on Social Media
          </h3>
          
          <div className="space-y-3">
            {/* Share to Strun Community */}
            {userTask?.status === "completed" && (
              <Button
                onClick={handleShareToCommunity}
                disabled={isSharing}
                className="w-full justify-start h-12 bg-primary/10 hover:bg-primary/20 text-primary border border-primary/30"
              >
                <Users className="w-5 h-5 mr-3" />
                {isSharing ? "Sharing..." : "Share to Strun Community"}
              </Button>
            )}

            {/* X/Twitter */}
            <Button
              onClick={handleShareX}
              className="w-full justify-start h-12 bg-[#1DA1F2]/10 hover:bg-[#1DA1F2]/20 text-[#1DA1F2] border border-[#1DA1F2]/30"
            >
              <Twitter className="w-5 h-5 mr-3" />
              Share on X (Twitter)
            </Button>

            {/* Instagram */}
            <Button
              onClick={handleShareInstagram}
              className="w-full justify-start h-12 bg-gradient-to-r from-[#833AB4]/10 to-[#FD1D1D]/10 hover:from-[#833AB4]/20 hover:to-[#FD1D1D]/20 text-[#E1306C] border border-[#E1306C]/30"
            >
              <Instagram className="w-5 h-5 mr-3" />
              Share on Instagram
            </Button>

            {/* TikTok */}
            <Button
              onClick={handleShareTikTok}
              className="w-full justify-start h-12 bg-black/10 hover:bg-black/20 text-foreground border border-border"
            >
              <Video className="w-5 h-5 mr-3" />
              Share on TikTok
            </Button>

            {/* Copy Link */}
            <Button
              onClick={handleCopyLink}
              variant="outline"
              className="w-full justify-start h-12"
            >
              <Copy className="w-5 h-5 mr-3" />
              Copy Link
            </Button>
          </div>
        </Card>

        {/* Task Details */}
        <Card className="p-6 glass">
          <h3 className="font-display font-bold text-lg mb-4">Task Details</h3>
          <div className="space-y-3 text-sm">
            <div className="flex justify-between">
              <span className="text-muted-foreground">Type:</span>
              <span className="font-medium">{task.type.replace(/_/g, ' ')}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">Location:</span>
              <span className="font-medium">{task.city}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">Radius:</span>
              <span className="font-medium">{task.radius_m}m</span>
            </div>
            {task.max_participants && (
              <div className="flex justify-between">
                <span className="text-muted-foreground">Participants:</span>
                <span className="font-medium">
                  {task.current_participants}/{task.max_participants}
                </span>
              </div>
            )}
          </div>
        </Card>

        {/* CTA */}
        {!userTask && (
          <Button
            onClick={() => navigate("/tasks")}
            className="w-full h-12"
            size="lg"
          >
            Join This Task
          </Button>
        )}
      </div>
    </div>
  );
};

export default Share;
