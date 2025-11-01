import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { useAuth } from "@/contexts/AuthContext";
import strunLogo from "@/assets/strun-logo.jpg";

const Login = () => {
  const navigate = useNavigate();
  const { user } = useAuth();

  useEffect(() => {
    if (user) {
      navigate("/dashboard");
    }
  }, [user, navigate]);

  const handleEmailLogin = () => {
    navigate("/email-auth");
  };

  return (
    <div className="min-h-screen flex items-center justify-center p-4 bg-background">
      <Card className="w-full max-w-md p-8 bg-card border-border/50">
        {/* Logo and Title */}
        <div className="text-center mb-12">
          <div className="inline-flex mb-6">
            <img 
              src={strunLogo} 
              alt="Strun Logo" 
              className="h-24 w-auto object-contain"
            />
          </div>
          <p className="text-muted-foreground text-lg">
            Run to claim your territory on Solana
          </p>
        </div>

        {/* Auth Button */}
        <div className="space-y-4">
          <Button
            variant="accent"
            size="lg"
            className="w-full h-14 text-base"
            onClick={handleEmailLogin}
          >
            Continue with Email
          </Button>
        </div>

        {/* Terms */}
        <p className="text-center text-xs text-muted-foreground mt-8 leading-relaxed">
          By continuing, you agree to our{" "}
          <a href="#" className="text-foreground underline">
            Terms of Service
          </a>{" "}
          and{" "}
          <a href="#" className="text-foreground underline">
            Privacy Policy
          </a>
          .
        </p>
      </Card>
    </div>
  );
};

export default Login;
