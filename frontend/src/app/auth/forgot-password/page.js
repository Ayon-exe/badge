"use client"; // Enabling client-side rendering

import { useState } from "react";
import axios from "axios";
import { useRouter } from "next/navigation"; // New router hook for App Router
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";

const ForgotPassword = () => {
  const [email, setEmail] = useState("");
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const router = useRouter();

  const handleSendOtp = async () => {
    try {
      const response = await axios.post(
        `${process.env.SERVER_URL}/api/auth/forgot-password`,
        { email }
      );
      setMessage(response.data.message);
      setError("");
      setTimeout(() => {
        router.push(`/auth/reset-password?email=${encodeURIComponent(email)}`);
      }, 2000);
    } catch (err) {
      setMessage("");
      setError(err.response?.data?.error || "Failed to send OTP");
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-[url('/background.jpg')] bg-cover bg-center bg-fixed">
      <div className="min-h-screen w-full flex items-center justify-center bg-blue-950/30 backdrop-blur-md shadow-lg rounded-lg">
        <div className="p-8 max-w-md w-full bg-slate-950/75 backdrop-blur-md shadow-lg rounded-lg">
          <h1 className="text-2xl font-semibold text-center">
            Forgot Password
          </h1>
          <p className="text-sm text-gray-500 text-center mt-2 mb-6">
            Enter your email to receive an OTP.
          </p>
          {error && <div className="text-red-500 mb-4">{error}</div>}
          {message && <div className="text-green-500 mb-4">{message}</div>}
          <div className="mb-4">
            <Label htmlFor="email">Email</Label>
            <Input
              id="email"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="Enter your email"
              required
            />
          </div>
          <Button onClick={handleSendOtp} disabled={!email} className="w-full">
            Send OTP
          </Button>
        </div>
      </div>
    </div>
  );
};

export default ForgotPassword;
