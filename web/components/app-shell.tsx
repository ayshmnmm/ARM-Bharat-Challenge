"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useTheme } from "next-themes";
import { Bell, Cpu, Home, Monitor, Moon, Shield, Sun } from "lucide-react";

import { Button } from "@/components/ui/button";
import { useApi, type Overview, type SystemStatus } from "@/lib/api";
import { cn } from "@/lib/utils";

const NAV = [
  { href: "/", label: "Home", icon: Home },
  { href: "/alerts/", label: "Alerts", icon: Bell },
  { href: "/devices/", label: "Devices", icon: Monitor },
  { href: "/system/", label: "How it works", icon: Cpu },
];

function isActive(pathname: string, href: string) {
  if (href === "/") return pathname === "/";
  const base = href.replace(/\/$/, "");
  // detail pages (/device/, /alert/) belong to their list section
  return pathname.startsWith(base) || pathname.startsWith(base.replace(/s$/, "") + "/");
}

function ThemeToggle() {
  const { resolvedTheme, setTheme } = useTheme();
  return (
    <Button
      variant="ghost"
      size="icon"
      aria-label="Toggle dark mode"
      onClick={() => setTheme(resolvedTheme === "dark" ? "light" : "dark")}
    >
      <Sun className="size-4 dark:hidden" />
      <Moon className="hidden size-4 dark:block" />
    </Button>
  );
}

/** One dot for the whole system: is NetWatch watching, and is the router fine? */
function LiveStatus() {
  const { data: sys, error } = useApi<SystemStatus>("/api/system", 10000);
  let label = "Connecting…";
  let tone = "bg-muted-foreground";
  if (error) {
    label = "NetWatch is not responding";
    tone = "bg-sev-critical";
  } else if (sys) {
    const routerOk = Object.values(sys.router_services).every(Boolean);
    const age = sys.sensor_last_write_s;
    if (!routerOk) {
      label = "Router service down";
      tone = "bg-sev-high";
    } else if (age === null) {
      label = "Showing recorded data";
      tone = "bg-sev-medium";
    } else if (age > 120) {
      label = "Wi-Fi quiet";
      tone = "bg-ok";
    } else {
      label = "Watching your Wi-Fi";
      tone = "bg-ok";
    }
  }
  return (
    <Link href="/system/" className="flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground">
      <span className={cn("size-2.5 rounded-full", tone)} />
      <span className="hidden sm:inline">{label}</span>
    </Link>
  );
}

function Brand() {
  return (
    <Link href="/" className="flex items-center gap-2 font-semibold">
      <span className="flex size-8 items-center justify-center rounded-lg bg-primary text-primary-foreground">
        <Shield className="size-4" />
      </span>
      NetWatch
    </Link>
  );
}

export function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const { data: ov } = useApi<Overview>("/api/overview");
  const open = ov ? Object.values(ov.alerts_open).reduce((a, b) => a + b, 0) : 0;

  const mobileLinks = NAV.map(({ href, label, icon: Icon }) => (
    <Link
      key={href}
      href={href}
      className={cn(
        "relative flex flex-col items-center gap-0.5 rounded-md py-1.5 text-[11px] font-medium",
        isActive(pathname, href) ? "bg-accent text-accent-foreground" : "text-muted-foreground",
      )}
    >
      <Icon className="size-4" />
      {label}
      {href === "/alerts/" && open > 0 && (
        <span className="absolute top-0.5 right-[22%] rounded-full bg-sev-high px-1 text-[10px] font-semibold text-white">{open}</span>
      )}
    </Link>
  ));

  const links = NAV.map(({ href, label, icon: Icon }) => (
    <Link
      key={href}
      href={href}
      className={cn(
        "flex items-center gap-2 rounded-md px-3 py-2 text-sm font-medium transition-colors",
        isActive(pathname, href) ? "bg-accent text-accent-foreground" : "text-muted-foreground hover:text-foreground",
      )}
    >
      <Icon className="size-4" />
      {label}
      {href === "/alerts/" && open > 0 && (
        <span className="rounded-full bg-sev-high px-1.5 text-xs font-semibold text-white tabular-nums">{open}</span>
      )}
    </Link>
  ));

  return (
    <div className="flex min-h-svh flex-col">
      <header className="sticky top-0 z-30 border-b bg-background/90 backdrop-blur">
        <div className="mx-auto flex h-14 max-w-6xl items-center gap-6 px-4 md:px-6">
          <Brand />
          <nav className="hidden items-center gap-1 md:flex">{links}</nav>
          <div className="ml-auto flex items-center gap-3">
            <LiveStatus />
            <ThemeToggle />
          </div>
        </div>
        <nav className="grid grid-cols-4 gap-1 border-t px-2 py-1 md:hidden">{mobileLinks}</nav>
      </header>
      <main className="mx-auto w-full max-w-6xl flex-1 px-4 py-8 md:px-6">{children}</main>
      <footer className="mx-auto w-full max-w-6xl px-4 pb-6 text-xs text-muted-foreground md:px-6">
        NetWatch · Raspberry Pi 4 · offline
      </footer>
    </div>
  );
}
