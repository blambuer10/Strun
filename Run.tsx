import { useState, useEffect, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { 
  Play, 
  Square, 
  Pause,
  Timer,
  Activity,
  Zap,
} from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { useAuth } from "@/contexts/AuthContext";
import { supabase } from "@/integrations/supabase/client";
import BottomNav from "@/components/BottomNav";
import GoogleMap from "@/components/GoogleMap";
import strunLogo from "@/assets/strun-logo.jpg";
import { FloatingMascot } from "@/components/FloatingMascot";

const Run = () => {
  const [isRunning, setIsRunning] = useState(false);
  const [isPaused, setIsPaused] = useState(false);
  const [distance, setDistance] = useState(0);
  const [duration, setDuration] = useState(0);
  const [calories, setCalories] = useState(0);
  const [coordinates, setCoordinates] = useState<Array<{ lat: number; lng: number }>>([]);
  const [startTime, setStartTime] = useState<Date | null>(null);
  const [showSummary, setShowSummary] = useState(false);
  const [runData, setRunData] = useState<any>(null);
  const [isMinting, setIsMinting] = useState(false);
  const navigate = useNavigate();
  const { toast } = useToast();
  const { user, loading } = useAuth();
  const timerRef = useRef<NodeJS.Timeout | null>(null);

  // Timer effect - MUST be before conditional returns
  useEffect(() => {
    if (isRunning && !isPaused) {
      timerRef.current = setInterval(() => {
        setDuration((prev) => prev + 1);
        setCalories((prev) => prev + 0.5);
      }, 1000);
    } else if (timerRef.current) {
      clearInterval(timerRef.current);
      timerRef.current = null;
    }
    return () => {
      if (timerRef.current) {
        clearInterval(timerRef.current);
      }
    };
  }, [isRunning, isPaused]);

  // Redirect to login if not authenticated - MUST be before conditional returns
  useEffect(() => {
    if (!loading && !user) {
      toast({
        title: "Login Required",
        description: "You must login to track runs.",
        variant: "destructive",
      });
      navigate("/login");
    }
  }, [user, loading, navigate, toast]);

  // Show loading state - AFTER all hooks
  if (loading) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-accent mx-auto mb-4"></div>
          <p className="text-muted-foreground">Loading...</p>
        </div>
      </div>
    );
  }

  // Don't render if no user - AFTER all hooks
  if (!user) {
    return null;
  }

  const calculateDistance = (coords: Array<{ lat: number; lng: number }>) => {
    if (coords.length < 2) return 0;
    
    let totalDistance = 0;
    for (let i = 0; i < coords.length - 1; i++) {
      const R = 6371; // Earth's radius in km
      const dLat = toRad(coords[i + 1].lat - coords[i].lat);
      const dLon = toRad(coords[i + 1].lng - coords[i].lng);
      const a =
        Math.sin(dLat / 2) * Math.sin(dLat / 2) +
        Math.cos(toRad(coords[i].lat)) * Math.cos(toRad(coords[i + 1].lat)) *
        Math.sin(dLon / 2) * Math.sin(dLon / 2);
      const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
      totalDistance += R * c;
    }
    return totalDistance;
  };

  const toRad = (value: number) => (value * Math.PI) / 180;

  const handleStart = async () => {
    try {
      // Request location permission and get initial position
      const position = await new Promise<GeolocationPosition>((resolve, reject) => {
        navigator.geolocation.getCurrentPosition(resolve, reject, {
          enableHighAccuracy: true,
          timeout: 10000,
          maximumAge: 0,
        });
      });

      const initialLocation = {
        lat: position.coords.latitude,
        lng: position.coords.longitude,
      };

      setCoordinates([initialLocation]);
      setIsRunning(true);
      setIsPaused(false);
      setStartTime(new Date());
      setDistance(0);
      setDuration(0);
      setCalories(0);
      
      toast({
        title: "Run Started!",
        description: "GPS tracking activated. Good luck!",
      });
    } catch (error: any) {
      console.error("Location permission error:", error);
      
      let errorMessage = "Could not access location.";
      if (error.code === 1) {
        errorMessage = "Location permission denied. Please enable location access in your device settings.";
      } else if (error.code === 2) {
        errorMessage = "Location unavailable. Please check your device settings.";
      } else if (error.code === 3) {
        errorMessage = "Location request timeout. Please try again.";
      }
      
      toast({
        title: "Location Error",
        description: errorMessage,
        variant: "destructive",
      });
    }
  };

  const handlePause = () => {
    setIsPaused(!isPaused);
    toast({
      title: isPaused ? "Resumed" : "Paused",
      description: isPaused ? "Keep going!" : "Take a breather",
    });
  };

  const handleStop = async () => {
    console.log('handleStop called', { isRunning, startTime: !!startTime });
    
    if (!isRunning) {
      toast({
        title: "Error",
        description: "Run is not active!",
        variant: "destructive",
      });
      return;
    }
    
    if (!startTime) {
      toast({
        title: "Error",
        description: "Start time not found!",
        variant: "destructive",
      });
      return;
    }
    
    setIsRunning(false);
    setIsPaused(false);
    
    const earnedXP = Math.floor(distance * 10);
    const pace = duration > 0 ? distance / (duration / 3600) : 0;

    try {
      // Save run to database
      const { data: savedRun, error: runError } = await supabase
        .from("runs")
        .insert({
          user_id: user.id,
          distance: distance,
          duration: duration,
          calories: Math.floor(calories),
          pace: pace,
          xp_earned: earnedXP,
          route_coordinates: coordinates,
          started_at: startTime.toISOString(),
          completed_at: new Date().toISOString(),
        })
        .select()
        .single();

      if (runError) throw runError;

      // Update user XP
      const { data: profile } = await supabase
        .from("profiles")
        .select("xp, level")
        .eq("id", user.id)
        .single();

      if (profile) {
        const newXP = profile.xp + earnedXP;
        const newLevel = Math.floor(newXP / 1000) + 1;
        
        await supabase
          .from("profiles")
          .update({ xp: newXP, level: newLevel })
          .eq("id", user.id);
      }

      // Store run data and show summary modal
      setRunData(savedRun);
      setShowSummary(true);

      toast({
        title: "Run Complete!",
        description: `Earned ${earnedXP} XP! Distance: ${distance.toFixed(2)} km`,
      });
    } catch (error) {
      console.error("Error saving run:", error);
      toast({
        title: "Error",
        description: "Failed to save run. Please try again.",
        variant: "destructive",
      });
    }
  };

  const mintLandNFT = async () => {
    if (!runData || !user || coordinates.length < 3) {
      toast({
        title: "Error",
        description: "Not enough run data to mint NFT.",
        variant: "destructive",
      });
      return;
    }

    setIsMinting(true);

    try {
      // Calculate polygon area
      const area = calculatePolygonArea(coordinates);

      // Call edge function to mint NFT with Pinata
      const { data, error } = await supabase.functions.invoke('mint-land-nft', {
        body: {
          coordinates,
          runId: runData.id,
          userId: user.id,
          area,
        },
      });

      if (error) throw error;

      toast({
        title: "NFT Successfully Minted! 🎉",
        description: `Your territory saved to IPFS. CID: ${data.ipfsCid.substring(0, 12)}...`,
      });

      setShowSummary(false);
      setTimeout(() => {
        navigate("/dashboard");
      }, 2000);
    } catch (error) {
      console.error("Error minting NFT:", error);
      toast({
        title: "Error",
        description: "Failed to mint NFT. Please try again.",
        variant: "destructive",
      });
    } finally {
      setIsMinting(false);
    }
  };

  const calculatePolygonArea = (coords: Array<{ lat: number; lng: number }>) => {
    if (coords.length < 3) return 0;
    
    let area = 0;
    for (let i = 0; i < coords.length; i++) {
      const j = (i + 1) % coords.length;
      area += coords[i].lat * coords[j].lng;
      area -= coords[j].lat * coords[i].lng;
    }
    return Math.abs(area / 2) * 12365; // Approximate km² conversion
  };

  const formatTime = (seconds: number) => {
    const hrs = Math.floor(seconds / 3600);
    const mins = Math.floor((seconds % 3600) / 60);
    const secs = seconds % 60;
    return `${hrs.toString().padStart(2, "0")}:${mins.toString().padStart(2, "0")}:${secs.toString().padStart(2, "0")}`;
  };

  return (
    <div className="min-h-screen bg-background flex flex-col">
      {/* Header */}
      <header className="border-b border-border/50 bg-card/50 backdrop-blur-lg p-4">
        <div className="container mx-auto flex items-center justify-between">
          <Button variant="ghost" onClick={() => navigate("/dashboard")}>
            ← Back
          </Button>
          <img 
            src={strunLogo} 
            alt="Strun Logo" 
            className="h-8 w-auto object-contain"
          />
          <div className="w-16" />
        </div>
      </header>

      {/* Map */}
      <div className="flex-1 relative min-h-0">
        <GoogleMap 
          tracking={isRunning && !isPaused}
          path={coordinates}
          onLocationUpdate={(location) => {
            if (isRunning && !isPaused) {
              const newCoord = { lat: location.lat, lng: location.lng };
              setCoordinates((prev) => [...prev, newCoord]);
              const newDistance = calculateDistance([...coordinates, newCoord]);
              setDistance(newDistance);
            }
          }}
        />
        
        {/* Floating Stats */}
        {isRunning && (
          <div className="absolute top-4 left-4 right-4 space-y-2">
            <Card className="p-4 bg-card/90 backdrop-blur-lg">
              <div className="grid grid-cols-3 gap-4 text-center">
                <div>
                  <div className="text-2xl font-bold text-accent">{distance.toFixed(2)}</div>
                  <div className="text-xs text-muted-foreground">km</div>
                </div>
                <div>
                  <div className="text-2xl font-bold text-accent">{formatTime(duration)}</div>
                  <div className="text-xs text-muted-foreground">time</div>
                </div>
                <div>
                  <div className="text-2xl font-bold text-accent">{Math.floor(calories)}</div>
                  <div className="text-xs text-muted-foreground">kcal</div>
                </div>
              </div>
            </Card>

            <Card className="p-3 bg-card/90 backdrop-blur-lg">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Zap className="w-4 h-4 text-accent" />
                  <span className="text-sm font-medium">XP Earning</span>
                </div>
                <span className="text-accent font-bold">+{Math.floor(distance * 10)} XP</span>
              </div>
            </Card>
          </div>
        )}
      </div>

      {/* Control Panel */}
      <div className="border-t border-border/50 bg-card/95 backdrop-blur-lg p-6">
        <div className="container mx-auto space-y-4">
          {!isRunning ? (
            <Button 
              variant="hero" 
              size="xl" 
              className="w-full"
              onClick={handleStart}
            >
              <Play className="w-6 h-6" />
              Start Run
            </Button>
          ) : (
            <div className="grid grid-cols-2 gap-4">
              <Button 
                variant={isPaused ? "accent" : "secondary"}
                size="lg"
                onClick={handlePause}
              >
                {isPaused ? <Play className="w-5 h-5" /> : <Pause className="w-5 h-5" />}
                {isPaused ? "Resume" : "Pause"}
              </Button>
              <Button 
                variant="destructive"
                size="lg"
                onClick={handleStop}
              >
                <Square className="w-5 h-5" />
                Stop Run
              </Button>
            </div>
          )}

            <div className="grid grid-cols-3 gap-3">
            {[
              { icon: Activity, label: "Distance", value: `${distance.toFixed(2)} km` },
              { icon: Timer, label: "Pace", value: duration > 0 ? `${(duration / 60 / (distance || 1)).toFixed(1)} min/km` : "0 min/km" },
              { icon: Zap, label: "XP", value: `+${Math.floor(distance * 10)}` },
            ].map((stat) => (
              <Card key={stat.label} className="p-3 bg-background/50 text-center">
                <stat.icon className="w-5 h-5 text-accent mx-auto mb-1" />
                <div className="text-xs text-muted-foreground">{stat.label}</div>
                <div className="font-bold text-sm">{stat.value}</div>
              </Card>
            ))}
          </div>
        </div>
      </div>
      
      <BottomNav />

      {/* Run Summary Dialog */}
      <Dialog open={showSummary} onOpenChange={setShowSummary}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Run Summary</DialogTitle>
            <DialogDescription>
              Mint your run area as NFT and save on blockchain
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <Card className="p-4 bg-background/50">
              <div className="grid grid-cols-2 gap-4 text-center">
                <div>
                  <div className="text-2xl font-bold text-accent">{distance.toFixed(2)}</div>
                  <div className="text-xs text-muted-foreground">km</div>
                </div>
                <div>
                  <div className="text-2xl font-bold text-accent">{formatTime(duration)}</div>
                  <div className="text-xs text-muted-foreground">time</div>
                </div>
                <div>
                  <div className="text-2xl font-bold text-accent">{Math.floor(calories)}</div>
                  <div className="text-xs text-muted-foreground">kcal</div>
                </div>
                <div>
                  <div className="text-2xl font-bold text-accent">+{Math.floor(distance * 10)}</div>
                  <div className="text-xs text-muted-foreground">XP</div>
                </div>
              </div>
            </Card>
            {coordinates.length >= 3 && (
              <>
                <Card className="p-4 bg-primary/10">
                  <div className="h-40 relative overflow-hidden rounded-lg">
                    {(() => {
                      const coords = coordinates;
                      if (coords.length < 3) return null;
                      
                      const lats = coords.map((c) => c.lat);
                      const lngs = coords.map((c) => c.lng);
                      const minLat = Math.min(...lats);
                      const maxLat = Math.max(...lats);
                      const minLng = Math.min(...lngs);
                      const maxLng = Math.max(...lngs);
                      
                      const points = coords
                        .map((coord) => {
                          const x = ((coord.lng - minLng) / (maxLng - minLng)) * 280 + 10;
                          const y = 290 - ((coord.lat - minLat) / (maxLat - minLat)) * 280;
                          return `${x},${y}`;
                        })
                        .join(" ");
                      
                      return (
                        <svg viewBox="0 0 300 300" className="w-full h-full">
                          <polygon
                            points={points}
                            fill="hsl(var(--accent))"
                            fillOpacity="0.3"
                            stroke="hsl(var(--accent))"
                            strokeWidth="3"
                          />
                          {coords.map((coord, i) => {
                            const x = ((coord.lng - minLng) / (maxLng - minLng)) * 280 + 10;
                            const y = 290 - ((coord.lat - minLat) / (maxLat - minLat)) * 280;
                            return (
                              <circle
                                key={i}
                                cx={x}
                                cy={y}
                                r="3"
                                fill="hsl(var(--accent))"
                              />
                            );
                          })}
                        </svg>
                      );
                    })()}
                  </div>
                </Card>
                <div className="text-sm text-muted-foreground text-center">
                  Your run area: {coordinates.length} GPS points
                </div>
              </>
            )}
          </div>
          <DialogFooter className="flex-col gap-2 sm:flex-col">
            {coordinates.length >= 3 && distance > 0.5 ? (
              <Button 
                onClick={mintLandNFT} 
                disabled={isMinting}
                className="w-full"
                size="lg"
              >
                {isMinting ? "Minting NFT..." : "🏆 Mint Run Area as NFT"}
              </Button>
            ) : (
              <p className="text-sm text-muted-foreground text-center">
                You must run at least 0.5 km to mint NFT
              </p>
            )}
            <Button 
              variant="outline" 
              onClick={() => {
                setShowSummary(false);
                navigate("/dashboard");
              }}
              className="w-full"
            >
              Return to Dashboard
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Runny - AI Fitness Assistant */}
      <FloatingMascot 
        mood={isRunning ? "running" : isPaused ? "tired" : "cheering"}
        message={isRunning ? "You're doing great! Keep it up!" : isPaused ? "Take a breath, you got this!" : distance > 1 ? "Amazing run! Ready for more?" : "Let's go for a run!"}
      />
    </div>
  );
};

export default Run;
