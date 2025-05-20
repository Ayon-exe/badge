"use client"; // Enabling client-side rendering

import { useState, Suspense } from "react";
import axios from "axios";
import { useRouter, useSearchParams } from "next/navigation";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";

const ResetPasswordContent = () => {
  const router = useRouter();
  const searchParams = useSearchParams();
  const email = searchParams.get("email");

  const [otp, setOtp] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");

  const handleResetPassword = async () => {
    if (newPassword !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }
    try {
      const response = await axios.post(
        `${process.env.SERVER_URL}/api/auth/reset-password`,
        { email, otp, newPassword }
      );
      setMessage(response.data.message);
      setError("");
      setTimeout(() => router.push("/"), 2000); // Redirect after success
    } catch (err) {
      setError(err.response?.data?.error || "Failed to reset password");
      setMessage("");
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-[url('/background.jpg')] bg-cover bg-center bg-fixed">
      <div className="min-h-screen w-full flex items-center justify-center bg-blue-950/30 backdrop-blur-md shadow-lg rounded-lg">
        <div className="p-8 bg-slate-950/75 shadow-md rounded-md max-w-md w-full">
          <h1 className="text-2xl font-semibold text-center">Reset Password</h1>
          <p className="text-sm text-gray-500 text-center mb-6">
            Enter OTP and set your new password.
          </p>
          {error && <div className="text-red-500 mb-4">{error}</div>}
          {message && <div className="text-green-500 mb-4">{message}</div>}
          <div className="mb-4">
            <Label htmlFor="otp">OTP</Label>
            <Input
              id="otp"
              type="text"
              value={otp}
              onChange={(e) => setOtp(e.target.value)}
              placeholder="Enter OTP"
              required
            />
          </div>
          <div className="mb-4">
            <Label htmlFor="newPassword">New Password</Label>
            <Input
              id="newPassword"
              type="password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              placeholder="Enter new password"
              required
            />
          </div>
          <div className="mb-4">
            <Label htmlFor="confirmPassword">Confirm Password</Label>
            <Input
              id="confirmPassword"
              type="password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              placeholder="Confirm new password"
              required
            />
          </div>
          <Button
            onClick={handleResetPassword}
            disabled={!otp || !newPassword || !confirmPassword}
            className="w-full"
          >
            Reset Password
          </Button>
        </div>
      </div>
    </div>
  );
};

const ResetPassword = () => {
  return (
    <Suspense fallback={<div>Loading...</div>}>
      <ResetPasswordContent />
    </Suspense>
  );
};

export default ResetPassword;
