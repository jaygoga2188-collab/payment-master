import { redirect } from "next/navigation";
import { currentAdmin } from "@/lib/admin";
import { managerData } from "@/lib/manager";
import { AdminConsole } from "@/components/admin-console";

export const dynamic = "force-dynamic";

export default async function DashboardPage() {
  const user = await currentAdmin();
  if (!user) redirect("/login");
  return <AdminConsole user={user} initialData={await managerData()} />;
}
