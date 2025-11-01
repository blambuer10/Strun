import { useState, useEffect, useRef } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { useAuth } from "@/contexts/AuthContext";
import { supabase } from "@/integrations/supabase/client";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import BottomNav from "@/components/BottomNav";
import { CreatePostDialog } from "@/components/CreatePostDialog";
import { 
  User, 
  ArrowLeft,
  MapPin,
  Heart,
  MessageSquare,
  Share2,
  Camera,
  CheckCircle2,
  Calendar,
  Award,
  Edit2,
  Check,
  X,
  Instagram,
  Twitter,
  Music
} from "lucide-react";
import { Textarea } from "@/components/ui/textarea";
import { useToast } from "@/hooks/use-toast";
import strunLogo from "@/assets/strun-logo.jpg";

const Profile = () => {
  const navigate = useNavigate();
  const { toast } = useToast();
  const { user, loading: authLoading } = useAuth();
  const { userId } = useParams(); // For viewing other users' profiles
  const queryClient = useQueryClient();
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [activeTab, setActiveTab] = useState<"posts" | "tasks">("posts");
  const [isEditingProfile, setIsEditingProfile] = useState(false);
  const [newUsername, setNewUsername] = useState("");
  const [newBio, setNewBio] = useState("");
  const [newInstagram, setNewInstagram] = useState("");
  const [newTwitter, setNewTwitter] = useState("");
  const [newTiktok, setNewTiktok] = useState("");
  const [uploading, setUploading] = useState(false);
  const [updating, setUpdating] = useState(false);
  
  // If no userId param, show current user's profile
  const profileUserId = userId || user?.id;
  const isOwnProfile = user?.id === profileUserId;

  useEffect(() => {
    if (!authLoading && !user && !userId) {
      navigate("/");
    }
  }, [user, authLoading, navigate, userId]);

  // Fetch profile data
  const { data: profile } = useQuery({
    queryKey: ["profile", profileUserId],
    queryFn: async () => {
      if (!profileUserId) return null;
      const { data, error } = await supabase
        .from("profiles")
        .select("*")
        .eq("id", profileUserId)
        .single();
      
      if (error) throw error;
      return data;
    },
    enabled: !!profileUserId,
  });

  // Fetch user's posts from posts table
  const { data: posts, refetch: refetchPosts } = useQuery({
    queryKey: ["user-posts", profileUserId],
    queryFn: async () => {
      if (!profileUserId) return [];
      
      const { data, error } = await supabase
        .from("posts")
        .select("*")
        .eq("user_id", profileUserId)
        .order("created_at", { ascending: false });
      
      if (error) throw error;
      return data || [];
    },
    enabled: !!profileUserId,
  });

  // Fetch user tasks (both pending and completed)
  const { data: userTasks } = useQuery({
    queryKey: ["user-tasks", profileUserId],
    queryFn: async () => {
      if (!profileUserId) return [];
      const { data } = await supabase
        .from("user_tasks")
        .select("*, tasks(name, title, location_name, xp_reward, type)")
        .eq("user_id", profileUserId)
        .in("status", ["pending", "completed"])
        .order("joined_at", { ascending: false })
        .limit(20);
      return data || [];
    },
    enabled: !!profileUserId,
  });

  // Stats
  const { data: stats } = useQuery({
    queryKey: ["user-stats", profileUserId],
    queryFn: async () => {
      if (!profileUserId) return { tasksCompleted: 0, totalXP: 0, postsCount: 0 };
      
      const [tasksResult, postsResult] = await Promise.all([
        supabase.from("user_tasks").select("*", { count: "exact", head: true }).eq("user_id", profileUserId).eq("status", "completed"),
        supabase.from("posts").select("*", { count: "exact", head: true }).eq("user_id", profileUserId),
      ]);

      return {
        tasksCompleted: tasksResult.count || 0,
        totalXP: profile?.xp || 0,
        postsCount: postsResult.count || 0,
      };
    },
    enabled: !!profileUserId && !!profile,
  });

  const xp = profile?.xp || 0;
  const level = Math.floor(xp / 1000) + 1;
  const userName = profile?.username || "Runner";
  const avatarUrl = profile?.avatar_url || null;

  useEffect(() => {
    if (profile) {
      setNewUsername(profile.username || "");
      setNewBio(profile.bio || "");
      setNewInstagram(profile.instagram_url || "");
      setNewTwitter(profile.twitter_url || "");
      setNewTiktok(profile.tiktok_url || "");
    }
  }, [profile]);

  const handleAvatarClick = () => {
    fileInputRef.current?.click();
  };

  const handleAvatarUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
    try {
      const file = event.target.files?.[0];
      if (!file) return;

      if (!file.type.startsWith('image/')) {
        toast({ title: "Invalid File", description: "Please upload an image file", variant: "destructive" });
        return;
      }

      if (file.size > 5 * 1024 * 1024) {
        toast({ title: "File Too Large", description: "Please upload an image smaller than 5MB", variant: "destructive" });
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

      const { error: uploadError } = await supabase.storage.from('avatars').upload(filePath, file);
      if (uploadError) throw uploadError;

      const { data: { publicUrl } } = supabase.storage.from('avatars').getPublicUrl(filePath);

      const { error: updateError } = await supabase.from('profiles').update({ avatar_url: publicUrl }).eq('id', user?.id);
      if (updateError) throw updateError;

      queryClient.invalidateQueries({ queryKey: ['profile', user?.id] });
      toast({ title: "Success! Avatar Updated", description: "Your profile photo has been updated" });
    } catch (error) {
      toast({ title: "Upload Failed", description: "Failed to upload avatar. Please try again.", variant: "destructive" });
    } finally {
      setUploading(false);
    }
  };

  const handleSaveProfile = async () => {
    if (!newUsername.trim()) {
      toast({ title: "Invalid Username", description: "Username cannot be empty", variant: "destructive" });
      return;
    }

    try {
      setUpdating(true);
      const { error } = await supabase.from('profiles').update({ 
        username: newUsername.trim(),
        bio: newBio.trim() || null,
        instagram_url: newInstagram.trim() || null,
        twitter_url: newTwitter.trim() || null,
        tiktok_url: newTiktok.trim() || null,
      }).eq('id', user?.id);
      
      if (error) throw error;

      queryClient.invalidateQueries({ queryKey: ['profile', user?.id] });
      setIsEditingProfile(false);
      toast({ title: "Success! Profile Updated", description: "Your profile has been updated" });
    } catch (error) {
      toast({ title: "Update Failed", description: "Failed to update profile. Please try again.", variant: "destructive" });
    } finally {
      setUpdating(false);
    }
  };

  const handleCancelEdit = () => {
    if (profile) {
      setNewUsername(profile.username || "");
      setNewBio(profile.bio || "");
      setNewInstagram(profile.instagram_url || "");
      setNewTwitter(profile.twitter_url || "");
      setNewTiktok(profile.tiktok_url || "");
    }
    setIsEditingProfile(false);
  };

  if (authLoading || !profile) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="text-center">
          <User className="w-12 h-12 text-accent mx-auto mb-4 animate-pulse" />
          <p className="text-muted-foreground">Loading...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background pb-20">
      {/* Header */}
      <header className="border-b border-border/50 bg-card backdrop-blur-lg p-4 sticky top-0 z-50">
        <div className="container mx-auto flex items-center justify-between">
          <Button variant="ghost" size="icon" onClick={() => navigate("/dashboard")}>
            <ArrowLeft className="w-5 h-5" />
          </Button>
          <img 
            src={strunLogo} 
            alt="Strun Logo" 
            className="h-8 w-auto object-contain"
          />
          {isOwnProfile && (
            <CreatePostDialog onPostCreated={refetchPosts} />
          )}
          {!isOwnProfile && <div className="w-10" />}
        </div>
      </header>

      <div className="container mx-auto px-4 py-6 space-y-6">
        {/* Profile Header */}
        <Card className="p-6 glass">
          <div className="flex flex-col items-center text-center">
            {isOwnProfile && (
              <input
                ref={fileInputRef}
                type="file"
                accept="image/*"
                className="hidden"
                onChange={handleAvatarUpload}
              />
            )}
            <div className="relative mb-4">
              <div className="absolute inset-0 bg-accent/30 blur-xl rounded-full" />
              {isOwnProfile ? (
                <button
                  onClick={handleAvatarClick}
                  disabled={uploading}
                  className="relative w-24 h-24 bg-gradient-to-br from-accent to-accent-glow rounded-full flex items-center justify-center overflow-hidden group cursor-pointer hover:opacity-90 transition-opacity disabled:cursor-not-allowed"
                >
                  {avatarUrl ? (
                    <img src={avatarUrl} alt="Profile" className="w-full h-full object-cover" />
                  ) : (
                    <User className="w-12 h-12 text-accent-foreground" />
                  )}
                  <div className="absolute inset-0 bg-black/40 opacity-0 group-hover:opacity-100 transition-opacity flex items-center justify-center">
                    <Camera className="w-6 h-6 text-white" />
                  </div>
                </button>
              ) : (
                <div className="relative w-24 h-24 bg-gradient-to-br from-accent to-accent-glow rounded-full flex items-center justify-center overflow-hidden">
                  {avatarUrl ? (
                    <img src={avatarUrl} alt="Profile" className="w-full h-full object-cover" />
                  ) : (
                    <User className="w-12 h-12 text-accent-foreground" />
                  )}
                </div>
              )}
              {uploading && (
                <div className="absolute inset-0 bg-black/60 rounded-full flex items-center justify-center">
                  <div className="w-8 h-8 border-4 border-white/30 border-t-white rounded-full animate-spin" />
                </div>
              )}
            </div>

            {isOwnProfile && isEditingProfile ? (
              <div className="w-full space-y-3 mb-4">
                <div>
                  <label className="text-xs text-muted-foreground mb-1 block">Username</label>
                  <Input
                    value={newUsername}
                    onChange={(e) => setNewUsername(e.target.value)}
                    placeholder="Enter username"
                    disabled={updating}
                  />
                </div>
                <div>
                  <label className="text-xs text-muted-foreground mb-1 block">Bio</label>
                  <Textarea
                    value={newBio}
                    onChange={(e) => setNewBio(e.target.value)}
                    placeholder="Tell us about yourself..."
                    className="resize-none"
                    rows={3}
                    disabled={updating}
                  />
                </div>
                <div>
                  <label className="text-xs text-muted-foreground mb-1 block">Instagram</label>
                  <Input
                    value={newInstagram}
                    onChange={(e) => setNewInstagram(e.target.value)}
                    placeholder="https://instagram.com/username"
                    disabled={updating}
                  />
                </div>
                <div>
                  <label className="text-xs text-muted-foreground mb-1 block">Twitter/X</label>
                  <Input
                    value={newTwitter}
                    onChange={(e) => setNewTwitter(e.target.value)}
                    placeholder="https://twitter.com/username"
                    disabled={updating}
                  />
                </div>
                <div>
                  <label className="text-xs text-muted-foreground mb-1 block">TikTok</label>
                  <Input
                    value={newTiktok}
                    onChange={(e) => setNewTiktok(e.target.value)}
                    placeholder="https://tiktok.com/@username"
                    disabled={updating}
                  />
                </div>
                <div className="flex gap-2">
                  <Button onClick={handleSaveProfile} disabled={updating} className="flex-1">
                    <Check className="w-4 h-4 mr-2" />
                    Save
                  </Button>
                  <Button variant="outline" onClick={handleCancelEdit} disabled={updating} className="flex-1">
                    <X className="w-4 h-4 mr-2" />
                    Cancel
                  </Button>
                </div>
              </div>
            ) : (
              <>
                <h2 className="text-2xl font-bold mb-1">{userName}</h2>
                <p className="text-sm text-muted-foreground mb-3">{profile?.email}</p>
                
                {profile?.bio && (
                  <p className="text-sm text-foreground mb-3">{profile.bio}</p>
                )}
                
                {(profile?.instagram_url || profile?.twitter_url || profile?.tiktok_url) && (
                  <div className="flex items-center gap-3 mb-3">
                    {profile.instagram_url && (
                      <a href={profile.instagram_url} target="_blank" rel="noopener noreferrer" className="text-muted-foreground hover:text-accent transition-colors">
                        <Instagram className="w-5 h-5" />
                      </a>
                    )}
                    {profile.twitter_url && (
                      <a href={profile.twitter_url} target="_blank" rel="noopener noreferrer" className="text-muted-foreground hover:text-accent transition-colors">
                        <Twitter className="w-5 h-5" />
                      </a>
                    )}
                    {profile.tiktok_url && (
                      <a href={profile.tiktok_url} target="_blank" rel="noopener noreferrer" className="text-muted-foreground hover:text-accent transition-colors">
                        <Music className="w-5 h-5" />
                      </a>
                    )}
                  </div>
                )}
              </>
            )}
            
            <div className="flex items-center gap-2 mb-4">
              <Badge variant="default" className="text-xs">
                Level {level}
              </Badge>
              <Badge variant="outline" className="text-xs">
                {xp.toLocaleString()} XP
              </Badge>
            </div>

            {/* Stats */}
            <div className="grid grid-cols-3 gap-6 w-full max-w-md mb-4">
              <div className="text-center">
                <div className="text-2xl font-bold gradient-text">{stats?.postsCount || 0}</div>
                <div className="text-xs text-muted-foreground">Posts</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold gradient-text">{stats?.tasksCompleted || 0}</div>
                <div className="text-xs text-muted-foreground">Tasks</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold gradient-text">{xp.toLocaleString()}</div>
                <div className="text-xs text-muted-foreground">XP</div>
              </div>
            </div>
            
            {isOwnProfile && !isEditingProfile && (
              <div className="flex gap-2 mt-4">
                <Button 
                  variant="outline" 
                  className="flex-1"
                  onClick={() => setIsEditingProfile(true)}
                >
                  Edit Profile
                </Button>
              </div>
            )}
          </div>
        </Card>

        {/* Tabs */}
        <div className="flex gap-2 border-b border-border/50">
          <button
            className={`flex-1 py-3 font-medium transition-colors ${
              activeTab === "posts" 
                ? "text-accent border-b-2 border-accent" 
                : "text-muted-foreground"
            }`}
            onClick={() => setActiveTab("posts")}
          >
            <Camera className="w-4 h-4 inline mr-2" />
            Posts
          </button>
          <button
            className={`flex-1 py-3 font-medium transition-colors ${
              activeTab === "tasks" 
                ? "text-accent border-b-2 border-accent" 
                : "text-muted-foreground"
            }`}
            onClick={() => setActiveTab("tasks")}
          >
            <CheckCircle2 className="w-4 h-4 inline mr-2" />
            Tasks
          </button>
        </div>

        {/* Content */}
        {activeTab === "posts" && (
          <div className="space-y-4">
            {posts && posts.length > 0 ? (
              posts.map((post) => (
                <Card key={post.id} className="p-4 glass">
                  <div className="flex items-start gap-3 mb-3">
                    <div className="w-10 h-10 bg-gradient-to-br from-accent to-accent-glow rounded-full flex items-center justify-center overflow-hidden flex-shrink-0">
                      {avatarUrl ? (
                        <img src={avatarUrl} alt={userName} className="w-full h-full object-cover" />
                      ) : (
                        <User className="w-5 h-5 text-accent-foreground" />
                      )}
                    </div>
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-1">
                        <span className="font-bold">{userName}</span>
                        <span className="text-xs text-muted-foreground">
                          {new Date(post.created_at).toLocaleDateString()}
                        </span>
                      </div>
                      {post.location && (
                        <p className="text-sm text-muted-foreground mb-2">
                          <MapPin className="w-3 h-3 inline mr-1" />
                          {post.location}
                        </p>
                      )}
                    </div>
                  </div>
                  
                  {post.image_url && (
                    <img 
                      src={post.image_url} 
                      alt="Post" 
                      className="w-full rounded-lg mb-3 max-h-96 object-cover"
                    />
                  )}
                  
                  <p className="text-foreground mb-3">{post.content}</p>
                  
                  <div className="flex items-center gap-4 text-muted-foreground">
                    <button className="flex items-center gap-1 hover:text-accent transition-colors">
                      <Heart className="w-5 h-5" />
                      <span className="text-sm">{post.likes_count || 0}</span>
                    </button>
                    <button className="flex items-center gap-1 hover:text-accent transition-colors">
                      <MessageSquare className="w-5 h-5" />
                      <span className="text-sm">{post.comments_count || 0}</span>
                    </button>
                    <button className="flex items-center gap-1 hover:text-accent transition-colors ml-auto">
                      <Share2 className="w-5 h-5" />
                    </button>
                  </div>
                </Card>
              ))
            ) : (
              <Card className="p-8 glass text-center">
                <Camera className="w-12 h-12 mx-auto mb-3 opacity-50 text-muted-foreground" />
                <p className="text-muted-foreground">No posts yet</p>
                {isOwnProfile && (
                  <p className="text-xs text-muted-foreground mt-1">
                    Create your first post using the + button above!
                  </p>
                )}
              </Card>
            )}
          </div>
        )}

        {activeTab === "tasks" && (
          <div className="space-y-3">
            {userTasks && userTasks.length > 0 ? (
              userTasks.map((userTask) => {
                const task = userTask.tasks;
                if (!task) return null;
                const isCompleted = userTask.status === "completed";
                return (
                  <Card key={userTask.id} className="p-4 glass">
                    <div className="flex items-center gap-3">
                      <div className={`w-12 h-12 rounded-lg flex items-center justify-center ${
                        isCompleted ? "bg-accent/20" : "bg-primary/20"
                      }`}>
                        <CheckCircle2 className={`w-6 h-6 ${
                          isCompleted ? "text-accent" : "text-primary"
                        }`} />
                      </div>
                      <div className="flex-1">
                        <div className="font-bold">{task.title || task.name}</div>
                        <div className="text-sm text-muted-foreground flex items-center gap-2 mt-1">
                          {task.location_name && (
                            <>
                              <MapPin className="w-4 h-4" />
                              {task.location_name}
                            </>
                          )}
                        </div>
                        <Badge 
                          variant={isCompleted ? "default" : "outline"} 
                          className="mt-2 text-xs"
                        >
                          {isCompleted ? "Completed" : "In Progress"}
                        </Badge>
                      </div>
                      <div className="text-right">
                        <div className="flex items-center gap-1 text-accent font-bold">
                          <Award className="w-4 h-4" />
                          +{task.xp_reward || 0}
                        </div>
                        {userTask.completed_at && (
                          <div className="text-xs text-muted-foreground mt-1">
                            <Calendar className="w-3 h-3 inline mr-1" />
                            {new Date(userTask.completed_at).toLocaleDateString()}
                          </div>
                        )}
                        {!isCompleted && userTask.joined_at && (
                          <div className="text-xs text-muted-foreground mt-1">
                            <Calendar className="w-3 h-3 inline mr-1" />
                            {new Date(userTask.joined_at).toLocaleDateString()}
                          </div>
                        )}
                      </div>
                    </div>
                  </Card>
                );
              })
            ) : (
              <Card className="p-8 glass text-center">
                <Award className="w-12 h-12 mx-auto mb-3 opacity-50 text-muted-foreground" />
                <p className="text-muted-foreground">No tasks yet</p>
              </Card>
            )}
          </div>
        )}
      </div>

      <BottomNav />
    </div>
  );
};

export default Profile;
