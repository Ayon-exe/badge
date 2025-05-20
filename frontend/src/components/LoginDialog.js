"use client";

import { useState } from "react";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { FcGoogle } from "react-icons/fc";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useRouter } from "next/navigation";
import { toast } from "react-toastify"; // Import toast
import SignupDialog from "./SignupDialog"; // Import SignupDialog

const LoginDialog = () => {
  const [isOpen, setIsOpen] = useState(false);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [showSignup, setShowSignup] = useState(false); // State to control the SignupDialog visibility
  const router = useRouter();

  const handleLogin = async () => {
    try {
      const response = await fetch(`${process.env.SERVER_URL}/api/auth/login`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ email, password }),
      });

      if (response.ok) {
        const data = await response.json();
        // console.log("Login successful:", data);

        // Save tokens
        localStorage.setItem("accessToken", data.accessToken);
        localStorage.setItem("refreshToken", data.refreshToken);


        toast.success("Logged in successfully!");
        handleRefresh();
        setIsOpen(false); // Close the dialog
      } else {
        const error = await response.json();
        setError(error.msg || "Invalid credentials");
        toast.error(error.msg || "Invalid credentials.");
      }
    } catch (err) {
      setError("An error occurred during login.");
      console.error("Login error:", err);
      toast.error("An error occurred during login.");
    }
  };

  const handleRefresh = () => {
    // This will refresh the current page
    window.location.reload();
  };
  const handleForgotPassword = () => {
    router.push("/auth/forgot-password");
  };

  const toggleSignupDialog = () => {
    setShowSignup(true); // Show Signup dialog on click
  };

  return (
    <Dialog open={isOpen} onOpenChange={setIsOpen}>
      <DialogTrigger asChild>
        <Button variant="outline">Login</Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-[425px] bg-blue-950/10 backdrop-blur-sm shadow-lg rounded-lg border border-white/20">
        <DialogHeader>
          <DialogTitle>{showSignup ? "Sign Up" : "Login"}</DialogTitle>
          <DialogDescription>
            {showSignup
              ? "Enter your details to create an account."
              : "Enter your credentials to log in."}
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-4 py-4">
          {error && <div className="text-red-500 font-medium">{error}</div>}
          {!showSignup ? (
            <>
              <div className="grid grid-cols-4 items-center gap-4">
                <Label htmlFor="email" className="text-right">
                  Email
                </Label>
                <Input
                  id="email"
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="Enter your email"
                  className="col-span-3"
                />
              </div>
              <div className="grid grid-cols-4 items-center gap-4">
                <Label htmlFor="password" className="text-right">
                  Password
                </Label>
                <Input
                  id="password"
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Enter your password"
                  className="col-span-3"
                />
              </div>
              <Button
                variant="link"
                className="text-sm text-blue-500 mt-2"
                onClick={handleForgotPassword}
              >
                Forgot Password?
              </Button>
              <div className="mt-4 text-center">
                <span>Don't have an account? </span>
                <button
                  className="text-blue-500 underline"
                  onClick={toggleSignupDialog} // Open SignupDialog when clicked
                >
                  Sign up
                </button>
              </div>
            </>
          ) : (
            <SignupDialog setShowSignup={setShowSignup} /> // Pass setShowSignup to allow closing the signup dialog
          )}
        </div>
        <DialogFooter>
          {!showSignup ? (
            <Button
              className="w-full bg-[#3DB5DA] hover:bg-[#0592be] font-bold"
              type="submit"
              onClick={handleLogin}
            >
              Login
            </Button>
          ) : (
            <></> // No button in the footer while showing signup form
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
};

export default LoginDialog;
