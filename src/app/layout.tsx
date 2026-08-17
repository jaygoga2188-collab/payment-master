import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = { title: "Payment Master", description: "Central Razorpay and Cashfree account management" };

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="en"><body>{children}</body></html>;
}
