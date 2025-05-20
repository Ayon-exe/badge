import { useEffect, useState } from "react";
import axios from "axios";
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
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  InputOTP,
  InputOTPGroup,
  InputOTPSlot,
} from "@/components/ui/input-otp";
import { useRouter } from "next/navigation";
import { useAuthContext } from "./AuthContext";
import { toast } from "react-toastify"; // Import toast

const SignupDialog = () => {
  const [isOpen, setIsOpen] = useState(false);
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [otp, setOtp] = useState(""); // 6-digit OTP
  const [error, setError] = useState("");
  const [otpSent, setOtpSent] = useState(false);
  const router = useRouter();
  const { fetchUser } = useAuthContext(); // Use context to fetch the user

  // Function to request OTP using Axios
  const handleSendOtp = async () => {
    try {
      const response = await axios.post(
        `${process.env.SERVER_URL}/api/auth/request-otp`,
        { email }
      );

      if (response.status === 200) {
        setOtpSent(true);
        setError("");
        toast.success("OTP sent successfully to your email.");
        console.log("OTP sent successfully to:", email);
      }
    } catch (err) {
      setError(err.response?.data?.msg || "Failed to send OTP");
      console.error("Send OTP error:", err);
      toast.error("Failed to send OTP.");
    }
  };

  const consoleOTP = (value) => {
    const sixDigitValue = value.toString().padStart(6, "0");
    setOtp(sixDigitValue);
    setOtp(value);
  };

  useEffect(() => {
    console.log("Updated otp:", otp);
  }, [otp]);

  // Function to handle registration after OTP is entered
  const handleSignup = async () => {
    if (password !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }

    try {
      const response = await axios.post(
        `${process.env.SERVER_URL}/api/auth/register`,
        {
          name,
          email,
          password,
          otp,
        }
      );

      if (response.status === 201) {
        const { accessToken, refreshToken } = response.data; // Extract tokens
        console.log("Signup successful:", response.data);

        // Save tokens in localStorage
        localStorage.setItem("accessToken", accessToken);
        localStorage.setItem("refreshToken", refreshToken);

        // Fetch the user's data
        await fetchUser();

        // Close the signup dialog
        setIsOpen(false);
        toast.success("Registered successfully! Welcome!");
        router.push("/"); // Redirect to homepage
      }
    } catch (err) {
      console.error("Signup error:", err);
      setError(err.response?.data?.msg || "Signup failed");
      toast.error("Signup failed. Try again.");
    }
  };

  return (
    <Dialog open={isOpen} onOpenChange={setIsOpen}>
      <DialogTrigger asChild>
        <Button variant="outline">Sign Up</Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-[425px] bg-blue-950/10 backdrop-blur-sm shadow-lg rounded-lg border border-white/20">
        <DialogHeader>
          <DialogTitle>Sign Up</DialogTitle>
          <DialogDescription>
            Enter your details to create an account. After entering your
            details, click "Send OTP" to receive an OTP.
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-4 py-4">
          {error && <div className="text-red-500 font-medium">{error}</div>}
          <div className="grid grid-cols-4 items-center gap-4">
            <Label htmlFor="name" className="text-right">
              Name
            </Label>
            <Input
              id="name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Enter your name"
              className="col-span-3"
            />
          </div>
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
          <div className="grid grid-cols-4 items-center gap-4">
            <Label htmlFor="confirmPassword" className="text-right">
              Confirm Password
            </Label>
            <Input
              id="confirmPassword"
              type="password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              placeholder="Confirm your password"
              className="col-span-3"
            />
          </div>
          {!otpSent ? (
            <>
              <DialogFooter>
                <Button
                  onClick={handleSendOtp}
                  disabled={!name || !email || !password || !confirmPassword}
                  className="w-full bg-[#3DB5DA] hover:bg-[#0592be] font-bold"
                >
                  Send OTP
                </Button>
              </DialogFooter>
            </>
          ) : (
            <>
              <div>
                <Label>Enter OTP</Label>
                <InputOTP
                  maxLength={6}
                  value={otp}
                  onChange={(value) => consoleOTP(value)}
                >
                  <InputOTPGroup>
                    <InputOTPSlot index={0} />
                    <InputOTPSlot index={1} />
                    <InputOTPSlot index={2} />
                    <InputOTPSlot index={3} />
                    <InputOTPSlot index={4} />
                    <InputOTPSlot index={5} />
                  </InputOTPGroup>
                </InputOTP>
              </div>
              <DialogFooter>
                <Button onClick={handleSignup}>Register</Button>
              </DialogFooter>
              {/* <div className="grid gap-4 py-4">
                <Button
                  variant="outline"
                  onClick={handleGoogleLogin}
                  className="w-full bg-white text-black font-bold"
                >
                  <FcGoogle className="w-6 h-6" />
                  Sign in with Google
                </Button>
              </div> */}
            </>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
};

export default SignupDialog;
