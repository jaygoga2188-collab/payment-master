import { redirect } from "next/navigation";
import { currentAdmin } from "@/lib/admin";

export default async function Home() { redirect((await currentAdmin()) ? "/dashboard" : "/login"); }
