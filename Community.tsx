import { useState, useEffect, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { ScrollArea } from "@/components/ui/scroll-area";
import BottomNav from "@/components/BottomNav";
import { CreatePostDialog } from "@/components/CreatePostDialog";
import { PostCard } from "@/components/PostCard";
import { 
  Search, 
  Users, 
  MapPin, 
  Calendar, 
  Award, 
  Plus, 
  Crown, 
  Trash2, 
  MessageCircle,
  Filter
} from "lucide-react";
import strunLogo from "@/assets/strun-logo.jpg";
import communityHero from "@/assets/community-hero.jpg";
import groupHero from "@/assets/group-hero.jpg";
import { supabase } from "@/integrations/supabase/client";
import { useAuth } from "@/contexts/AuthContext";
import { formatDistanceToNow } from "date-fns";
import { useToast } from "@/hooks/use-toast";
import { useIsAdmin } from "@/hooks/useIsAdmin";
import { FloatingMascot } from "@/components/FloatingMascot";

interface Group {
  id: string;
  name: string;
  description: string;
  location: string;
  scheduled_at: string;
  prize_pool_xp: number;
  prize_pool_sol: number;
  max_participants: number;
  is_sponsored: boolean;
  sponsor_name?: string;
  sponsor_banner_url?: string;
  creator_id: string;
  member_count?: number;
  is_member?: boolean;
}

interface ChatMessage {
  id: string;
  user_id: string;
  username: string;
  message: string;
  created_at: string;
}

const Community = () => {
  const navigate = useNavigate();
  const [searchQuery, setSearchQuery] = useState("");
  const [posts, setPosts] = useState<any[]>([]);
  const [userLikes, setUserLikes] = useState<Set<string>>(new Set());
  const [userReposts, setUserReposts] = useState<Set<string>>(new Set());
  const { user, loading } = useAuth();
  const { toast } = useToast();
  const { isAdmin } = useIsAdmin();

  // Group states
  const [groups, setGroups] = useState<Group[]>([]);
  const [myGroups, setMyGroups] = useState<Group[]>([]);
  const [isCreateDialogOpen, setIsCreateDialogOpen] = useState(false);
  const [selectedGroupId, setSelectedGroupId] = useState<string | null>(null);
  const [chatMessages, setChatMessages] = useState<ChatMessage[]>([]);
  const [newMessage, setNewMessage] = useState("");
  const [showChat, setShowChat] = useState(false);
  const [countryFilter, setCountryFilter] = useState<string>("all");
  const [cityFilter, setCityFilter] = useState<string>("all");
  const [sponsorshipFilter, setSponsorshipFilter] = useState<string>("all");

  const [formData, setFormData] = useState({
    name: "",
    description: "",
    country: "",
    city: "",
    address: "",
    scheduled_at: "",
    prize_pool_xp: 0,
    prize_pool_sol: 0,
    max_participants: 10,
    is_sponsored: false,
    sponsor_name: "",
    sponsor_banner_url: "",
  });

  const hashtags = ["#StrunRun", "#LandNFT", "#FitnessGoals"];

  const loadPosts = useCallback(async () => {
    try {
      const { data: postsData, error: postsError } = await supabase
        .from("posts")
        .select("*")
        .order("created_at", { ascending: false });

      if (postsError) throw postsError;
      if (!postsData) {
        setPosts([]);
        return;
      }

      const userIds = [...new Set(postsData.map(p => p.user_id))];
      const { data: profilesData } = await supabase
        .from("profiles")
        .select("id, username, email")
        .in("id", userIds);

      const profilesMap = new Map(profilesData?.map(p => [p.id, p]) || []);

      const formattedPosts = postsData.map((post) => {
        const profile = profilesMap.get(post.user_id);
        const displayName = profile?.username || profile?.email?.split("@")[0] || "Unknown User";
        
        return {
          id: post.id,
          author: displayName,
          handle: `@${displayName}`,
          time: formatDistanceToNow(new Date(post.created_at), { addSuffix: true }),
          content: post.content,
          image: post.image_url,
          likes_count: post.likes_count || 0,
          reposts_count: post.reposts_count || 0,
          comments_count: post.comments_count || 0,
          user_id: post.user_id,
        };
      });

      setPosts(formattedPosts);
    } catch (error: any) {
      console.error("Error loading posts:", error);
      toast({
        title: "Error loading posts",
        description: error.message,
        variant: "destructive",
      });
    }
  }, [toast]);

  const loadUserInteractions = useCallback(async () => {
    if (!user) return;

    try {
      const { data: likes } = await supabase
        .from("post_likes")
        .select("post_id")
        .eq("user_id", user.id);

      const { data: reposts } = await supabase
        .from("post_reposts")
        .select("post_id")
        .eq("user_id", user.id);

      setUserLikes(new Set(likes?.map((l) => l.post_id) || []));
      setUserReposts(new Set(reposts?.map((r) => r.post_id) || []));
    } catch (error) {
      console.error("Error loading interactions:", error);
    }
  }, [user]);

  const fetchGroups = async () => {
    try {
      const { data: groupsData, error: groupsError } = await supabase
        .from("groups")
        .select("*")
        .order("scheduled_at", { ascending: true });

      if (groupsError) throw groupsError;

      const groupsWithMemberInfo = await Promise.all(
        (groupsData || []).map(async (group) => {
          const { count } = await supabase
            .from("group_members")
            .select("*", { count: "exact", head: true })
            .eq("group_id", group.id);

          const { data: membershipData } = await supabase
            .from("group_members")
            .select("id")
            .eq("group_id", group.id)
            .eq("user_id", user?.id)
            .single();

          return {
            ...group,
            member_count: count || 0,
            is_member: !!membershipData,
          };
        })
      );

      const availableGroups = groupsWithMemberInfo.filter(g => !g.is_member);
      const userGroups = groupsWithMemberInfo.filter(g => g.is_member);

      setGroups(availableGroups);
      setMyGroups(userGroups);
      
      setCountryFilter("all");
      setCityFilter("all");
      setSponsorshipFilter("all");
    } catch (error) {
      console.error("Error fetching groups:", error);
    }
  };

  useEffect(() => {
    if (loading) return;
    
    if (!user) {
      navigate("/");
      return;
    }
    
    loadPosts();
    loadUserInteractions();
    fetchGroups();
  }, [user, loading, navigate, loadPosts, loadUserInteractions]);

  const handlePostCreated = useCallback(() => {
    loadPosts();
  }, [loadPosts]);

  const handlePostUpdate = useCallback(() => {
    loadPosts();
    loadUserInteractions();
  }, [loadPosts, loadUserInteractions]);

  const handleCreateGroup = async () => {
    if (!user) return;

    try {
      const location = `${formData.address}, ${formData.city}, ${formData.country}`;
      
      const { data, error } = await supabase
        .from("groups")
        .insert({
          name: formData.name,
          description: formData.description,
          location: location,
          scheduled_at: formData.scheduled_at,
          prize_pool_xp: formData.prize_pool_xp,
          prize_pool_sol: formData.prize_pool_sol,
          max_participants: formData.max_participants,
          is_sponsored: formData.is_sponsored,
          sponsor_name: formData.sponsor_name,
          sponsor_banner_url: formData.sponsor_banner_url,
          creator_id: user.id,
        })
        .select()
        .single();

      if (error) throw error;

      await supabase
        .from("group_members")
        .insert({
          group_id: data.id,
          user_id: user.id,
        });

      const { data: profile } = await supabase
        .from("profiles")
        .select("xp")
        .eq("id", user.id)
        .single();

      if (profile) {
        await supabase
          .from("profiles")
          .update({ xp: profile.xp + 100 })
          .eq("id", user.id);
      }

      toast({
        title: "Success",
        description: "Group created! You earned 100 XP",
      });

      setIsCreateDialogOpen(false);
      setFormData({
        name: "",
        description: "",
        country: "",
        city: "",
        address: "",
        scheduled_at: "",
        prize_pool_xp: 0,
        prize_pool_sol: 0,
        max_participants: 10,
        is_sponsored: false,
        sponsor_name: "",
        sponsor_banner_url: "",
      });
      fetchGroups();
    } catch (error) {
      console.error("Error creating group:", error);
      toast({
        title: "Error",
        description: "Failed to create group",
        variant: "destructive",
      });
    }
  };

  const handleJoinGroup = async (groupId: string) => {
    if (!user) return;

    try {
      const { error } = await supabase
        .from("group_members")
        .insert({
          group_id: groupId,
          user_id: user.id,
        });

      if (error) throw error;

      toast({
        title: "Success",
        description: "Joined group successfully",
      });

      fetchGroups();
    } catch (error) {
      console.error("Error joining group:", error);
      toast({
        title: "Error",
        description: "Failed to join group",
        variant: "destructive",
      });
    }
  };

  const handleLeaveGroup = async (groupId: string) => {
    if (!user) return;

    try {
      const { error } = await supabase
        .from("group_members")
        .delete()
        .eq("group_id", groupId)
        .eq("user_id", user.id);

      if (error) throw error;

      toast({
        title: "Success",
        description: "Left group successfully",
      });

      fetchGroups();
    } catch (error) {
      console.error("Error leaving group:", error);
      toast({
        title: "Error",
        description: "Failed to leave group",
        variant: "destructive",
      });
    }
  };

  const handleDeleteGroup = async (groupId: string) => {
    if (!isAdmin) return;

    try {
      const { error } = await supabase
        .from('groups')
        .delete()
        .eq('id', groupId);

      if (error) throw error;

      toast({
        title: "Success",
        description: "Group deleted successfully",
      });

      fetchGroups();
    } catch (error) {
      console.error("Error deleting group:", error);
      toast({
        title: "Error",
        description: "Failed to delete group",
        variant: "destructive",
      });
    }
  };

  const formatDate = (dateString: string) => {
    const date = new Date(dateString);
    return date.toLocaleDateString("en-US", {
      weekday: "long",
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  };

  const getLocationParts = (location: string) => {
    const parts = location.split(",").map(p => p.trim());
    if (parts.length >= 2) {
      return { city: parts[0], country: parts[1] };
    }
    return { city: location, country: "" };
  };

  const uniqueCountries = Array.from(
    new Set(
      groups.map(g => getLocationParts(g.location).country).filter(c => c !== "")
    )
  ).sort();

  const uniqueCities = Array.from(
    new Set(
      groups.map(g => getLocationParts(g.location).city).filter(c => c !== "")
    )
  ).sort();

  const filteredGroups = groups.filter(group => {
    const { city, country } = getLocationParts(group.location);
    
    const matchesCountry = countryFilter === "all" || country === countryFilter;
    const matchesCity = cityFilter === "all" || city === cityFilter;
    const matchesSponsorship = 
      sponsorshipFilter === "all" ||
      (sponsorshipFilter === "sponsored" && group.is_sponsored) ||
      (sponsorshipFilter === "not-sponsored" && !group.is_sponsored);

    return matchesCountry && matchesCity && matchesSponsorship;
  });

  const GroupCard = ({ group, showActions = true }: { group: Group; showActions?: boolean }) => (
    <Card
      key={group.id}
      className={`p-6 ${
        group.is_sponsored
          ? "bg-gradient-to-br from-warning/10 via-card to-primary/5 border-warning/30"
          : "bg-card/80"
      }`}
    >
      {group.is_sponsored && (
        <div className="flex items-center gap-2 mb-3 text-warning">
          <Crown className="w-4 h-4" />
          <span className="text-xs font-bold">
            Sponsored by {group.sponsor_name}
          </span>
        </div>
      )}

      <div className="space-y-3">
        <div>
          <h4 className="font-bold text-lg">{group.name}</h4>
          {group.description && (
            <p className="text-sm text-muted-foreground mt-1">{group.description}</p>
          )}
          <div className="flex items-center gap-2 text-sm text-muted-foreground mt-1">
            <Users className="w-4 h-4" />
            <span>{group.member_count || 0} / {group.max_participants} runners</span>
          </div>
        </div>

        <div className="space-y-2">
          <div className="flex items-center gap-2 text-sm">
            <MapPin className="w-4 h-4 text-accent" />
            <span>{group.location}</span>
          </div>
          <div className="flex items-center gap-2 text-sm">
            <Calendar className="w-4 h-4 text-accent" />
            <span>{formatDate(group.scheduled_at)}</span>
          </div>
          <div className="flex items-center gap-2 text-sm">
            <Award className="w-4 h-4 text-accent" />
            <span className="font-bold text-accent">
              {group.prize_pool_xp} XP
              {group.prize_pool_sol > 0 && ` + ${group.prize_pool_sol} SOL`}
            </span>
          </div>
        </div>

        {showActions && (
          <div className="flex gap-2">
            {group.is_member ? (
              <>
                <Button
                  variant="destructive"
                  className="flex-1"
                  onClick={() => handleLeaveGroup(group.id)}
                >
                  Leave
                </Button>
                {isAdmin && (
                  <Button
                    variant="destructive"
                    size="icon"
                    onClick={() => handleDeleteGroup(group.id)}
                  >
                    <Trash2 className="w-4 h-4" />
                  </Button>
                )}
              </>
            ) : (
              <div className="flex gap-2 w-full">
                <Button
                  variant={group.is_sponsored ? "gradient" : "accent"}
                  className="flex-1"
                  onClick={() => handleJoinGroup(group.id)}
                >
                  Join Group
                </Button>
                {isAdmin && (
                  <Button
                    variant="destructive"
                    size="icon"
                    onClick={() => handleDeleteGroup(group.id)}
                  >
                    <Trash2 className="w-4 h-4" />
                  </Button>
                )}
              </div>
            )}
          </div>
        )}
      </div>
    </Card>
  );

  if (loading) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary mx-auto"></div>
          <p className="mt-4 text-muted-foreground">Loading...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background pb-20">
      {/* Header */}
      <header className="border-b border-border/50 bg-card backdrop-blur-lg p-4 sticky top-0 z-50">
        <div className="container mx-auto">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <img 
                src={strunLogo} 
                alt="Strun Logo" 
                className="h-8 w-auto object-contain"
              />
            </div>
            <Button variant="ghost" size="icon">
              <Search className="w-5 h-5" />
            </Button>
          </div>
        </div>
      </header>

      <Tabs defaultValue="feed" className="w-full">
        <TabsList className="w-full justify-start border-b rounded-none h-auto p-0 bg-transparent">
          <TabsTrigger value="feed" className="rounded-none border-b-2 data-[state=active]:border-accent">
            Feed
          </TabsTrigger>
          <TabsTrigger value="groups" className="rounded-none border-b-2 data-[state=active]:border-accent">
            Groups
          </TabsTrigger>
        </TabsList>

        <TabsContent value="feed" className="mt-0">
          {/* Hero Image */}
          <div className="w-full h-48 overflow-hidden">
            <img 
              src={communityHero} 
              alt="Community" 
              className="w-full h-full object-cover animate-fade-in"
            />
          </div>

          {/* Search and Info Section */}
          <div className="container mx-auto px-4 py-4">
            {/* Search Bar */}
            <div className="relative mb-4">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
              <Input
                placeholder="Search Strun..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-10 bg-card/50 border-border/50"
              />
            </div>

            {/* Trending Hashtags */}
            <div className="flex gap-2 mb-4 overflow-x-auto pb-1">
              {hashtags.map((tag) => (
                <Button
                  key={tag}
                  variant="secondary"
                  size="sm"
                  className="rounded-full text-xs bg-primary/10 hover:bg-primary/20"
                >
                  {tag}
                </Button>
              ))}
            </div>
          </div>

          {/* Feed */}
          <div className="container mx-auto px-4 space-y-4 pb-24">
            {posts.map((post) => (
              <PostCard
                key={post.id}
                post={post}
                userLiked={userLikes.has(post.id)}
                userReposted={userReposts.has(post.id)}
                onUpdate={handlePostUpdate}
              />
            ))}
          </div>

          {/* Floating Action Button */}
          <div className="fixed bottom-24 right-6 z-40">
            <CreatePostDialog onPostCreated={handlePostCreated} />
          </div>
        </TabsContent>

        <TabsContent value="groups" className="mt-0">
          {/* Hero Image */}
          <div className="w-full h-48 overflow-hidden">
            <img 
              src={groupHero} 
              alt="Group Runs" 
              className="w-full h-full object-cover animate-fade-in"
            />
          </div>

          <div className="container mx-auto px-4 py-6 space-y-6">
            {/* Filters */}
            <Card className="p-4 bg-card/80 backdrop-blur-sm">
              <div className="flex items-center gap-2 mb-3">
                <Filter className="w-4 h-4 text-accent" />
                <h3 className="font-semibold text-sm">Filter Groups</h3>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                <div>
                  <Label className="text-xs mb-1.5 block">Country</Label>
                  <Select value={countryFilter} onValueChange={setCountryFilter}>
                    <SelectTrigger className="h-9">
                      <SelectValue placeholder="All Countries" />
                    </SelectTrigger>
                    <SelectContent className="bg-popover border-border z-50">
                      <SelectItem value="all">All Countries</SelectItem>
                      {uniqueCountries.map(country => (
                        <SelectItem key={country} value={country}>
                          {country}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                <div>
                  <Label className="text-xs mb-1.5 block">City</Label>
                  <Select value={cityFilter} onValueChange={setCityFilter}>
                    <SelectTrigger className="h-9">
                      <SelectValue placeholder="All Cities" />
                    </SelectTrigger>
                    <SelectContent className="bg-popover border-border z-50">
                      <SelectItem value="all">All Cities</SelectItem>
                      {uniqueCities.map(city => (
                        <SelectItem key={city} value={city}>
                          {city}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                <div>
                  <Label className="text-xs mb-1.5 block">Sponsorship</Label>
                  <Select value={sponsorshipFilter} onValueChange={setSponsorshipFilter}>
                    <SelectTrigger className="h-9">
                      <SelectValue placeholder="All Groups" />
                    </SelectTrigger>
                    <SelectContent className="bg-popover border-border z-50">
                      <SelectItem value="all">All Groups</SelectItem>
                      <SelectItem value="sponsored">Sponsored Only</SelectItem>
                      <SelectItem value="not-sponsored">Not Sponsored</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>
            </Card>

            {/* Create Group CTA */}
            <Card className="p-6 bg-gradient-to-br from-accent/10 via-transparent to-primary/5 border-accent/30">
              <div className="flex items-center gap-4">
                <div className="bg-accent/20 p-3 rounded-full">
                  <Plus className="w-8 h-8 text-accent" />
                </div>
                <div className="flex-1">
                  <h3 className="font-bold">Create Your Own Group</h3>
                  <p className="text-sm text-muted-foreground">Organize runs with your community</p>
                </div>
                <Dialog open={isCreateDialogOpen} onOpenChange={setIsCreateDialogOpen}>
                  <DialogTrigger asChild>
                    <Button variant="accent">
                      Create Group
                    </Button>
                  </DialogTrigger>
                  <DialogContent className="max-w-md max-h-[90vh] overflow-y-auto">
                    <DialogHeader>
                      <DialogTitle>Create Group Run</DialogTitle>
                    </DialogHeader>
                    <div className="space-y-4">
                      <div>
                        <Label htmlFor="name">Group Name</Label>
                        <Input
                          id="name"
                          value={formData.name}
                          onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                          placeholder="Morning Warriors"
                        />
                      </div>
                      <div>
                        <Label htmlFor="description">Description</Label>
                        <Textarea
                          id="description"
                          value={formData.description}
                          onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                          placeholder="A fun morning run..."
                        />
                      </div>
                      <div>
                        <Label htmlFor="country">Country</Label>
                        <Input
                          id="country"
                          value={formData.country}
                          onChange={(e) => setFormData({ ...formData, country: e.target.value })}
                          placeholder="e.g., Turkey"
                        />
                      </div>
                      <div>
                        <Label htmlFor="city">City</Label>
                        <Input
                          id="city"
                          value={formData.city}
                          onChange={(e) => setFormData({ ...formData, city: e.target.value })}
                          placeholder="e.g., Istanbul"
                        />
                      </div>
                      <div>
                        <Label htmlFor="address">Address</Label>
                        <Input
                          id="address"
                          value={formData.address}
                          onChange={(e) => setFormData({ ...formData, address: e.target.value })}
                          placeholder="e.g., Taksim Square"
                        />
                      </div>
                      <div>
                        <Label htmlFor="scheduled_at">Date & Time</Label>
                        <Input
                          id="scheduled_at"
                          type="datetime-local"
                          value={formData.scheduled_at}
                          onChange={(e) => setFormData({ ...formData, scheduled_at: e.target.value })}
                        />
                      </div>
                      <div>
                        <Label htmlFor="max_participants">Max Participants</Label>
                        <Input
                          id="max_participants"
                          type="number"
                          value={formData.max_participants}
                          onChange={(e) => setFormData({ ...formData, max_participants: parseInt(e.target.value) })}
                        />
                      </div>
                      <div>
                        <Label htmlFor="prize_pool_xp">Prize Pool (XP)</Label>
                        <Input
                          id="prize_pool_xp"
                          type="number"
                          value={formData.prize_pool_xp}
                          onChange={(e) => setFormData({ ...formData, prize_pool_xp: parseInt(e.target.value) })}
                        />
                      </div>
                      <div>
                        <Label htmlFor="prize_pool_sol">Prize Pool (SOL)</Label>
                        <Input
                          id="prize_pool_sol"
                          type="number"
                          step="0.01"
                          value={formData.prize_pool_sol}
                          onChange={(e) => setFormData({ ...formData, prize_pool_sol: parseFloat(e.target.value) })}
                        />
                      </div>
                      <div className="flex items-center gap-2">
                        <input
                          type="checkbox"
                          id="is_sponsored"
                          checked={formData.is_sponsored}
                          onChange={(e) => setFormData({ ...formData, is_sponsored: e.target.checked })}
                          className="w-4 h-4"
                        />
                        <Label htmlFor="is_sponsored">Sponsored Event</Label>
                      </div>
                      {formData.is_sponsored && (
                        <>
                          <div>
                            <Label htmlFor="sponsor_name">Sponsor Name</Label>
                            <Input
                              id="sponsor_name"
                              value={formData.sponsor_name}
                              onChange={(e) => setFormData({ ...formData, sponsor_name: e.target.value })}
                              placeholder="RunTech"
                            />
                          </div>
                          <div>
                            <Label htmlFor="sponsor_banner_url">Sponsor Banner URL</Label>
                            <Input
                              id="sponsor_banner_url"
                              value={formData.sponsor_banner_url}
                              onChange={(e) => setFormData({ ...formData, sponsor_banner_url: e.target.value })}
                              placeholder="https://..."
                            />
                          </div>
                        </>
                      )}
                      <Button onClick={handleCreateGroup} className="w-full" variant="accent">
                        Create Group
                      </Button>
                    </div>
                  </DialogContent>
                </Dialog>
              </div>
            </Card>

            {/* My Groups */}
            {myGroups.length > 0 && (
              <div>
                <h2 className="text-xl font-bold mb-4">My Groups</h2>
                <div className="grid gap-4">
                  {myGroups.map((group) => (
                    <GroupCard key={group.id} group={group} />
                  ))}
                </div>
              </div>
            )}

            {/* Available Groups */}
            <div>
              <h2 className="text-xl font-bold mb-4">
                Available Groups ({filteredGroups.length})
              </h2>
              <div className="grid gap-4">
                {filteredGroups.map((group) => (
                  <GroupCard key={group.id} group={group} />
                ))}
              </div>
            </div>
          </div>
        </TabsContent>
      </Tabs>
      
      {/* Runny - AI Fitness Assistant */}
      <FloatingMascot 
        mood="cheering"
        message="Share your achievements with the community!"
      />
      
      <BottomNav />
    </div>
  );
};

export default Community;
