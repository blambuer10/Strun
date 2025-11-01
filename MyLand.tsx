import { useAuth } from "@/contexts/AuthContext";
import { useUserParcels } from "@/hooks/useParcelInfo";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ParcelOwnershipCard } from "@/components/ParcelOwnershipCard";
import { MapPin, Loader2 } from "lucide-react";
import BottomNav from "@/components/BottomNav";

const MyLand = () => {
  const { user } = useAuth();
  const { data: parcels, isLoading, refetch } = useUserParcels(user?.id || null);

  return (
    <div className="min-h-screen bg-background pb-20">
      <div className="container max-w-4xl mx-auto p-4 space-y-6">
        <div className="flex items-center gap-3">
          <MapPin className="h-8 w-8 text-primary" />
          <h1 className="text-3xl font-bold">My Land</h1>
        </div>

        {isLoading ? (
          <div className="flex justify-center py-12">
            <Loader2 className="h-8 w-8 animate-spin text-primary" />
          </div>
        ) : parcels && parcels.length > 0 ? (
          <div className="grid gap-4 md:grid-cols-2">
            {parcels.map((parcel) => (
              <ParcelOwnershipCard
                key={parcel.id}
                parcel={parcel}
                onUpdate={refetch}
              />
            ))}
          </div>
        ) : (
          <Card>
            <CardContent className="py-12 text-center">
              <MapPin className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
              <p className="text-muted-foreground">
                You don't own any land yet. Complete runs to claim parcels!
              </p>
            </CardContent>
          </Card>
        )}
      </div>
      <BottomNav />
    </div>
  );
};

export default MyLand;
