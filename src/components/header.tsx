import { Monitor, Moon, Sun } from "lucide-react";
import { useTheme } from "@/components/theme-provider";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";

export function Header() {
  const { theme, setTheme } = useTheme();

  return (
    <header className="fixed inset-x-0 top-0 z-50 flex items-center justify-between border-b bg-background/80 px-4 py-2 backdrop-blur">
      <span className="font-heading text-sm font-medium tracking-wider">
        <span style={{ color: "oklch(0.86 0.27 145)" }}>wallet</span>
        <span style={{ color: "oklch(0.55 0.06 145)" }}>-passkeys</span>
        <span className="ml-2 text-xs uppercase tracking-[0.18em]" style={{ color: "oklch(0.55 0.06 145)" }}>
          · auth provider
        </span>
      </span>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button variant="ghost" size="icon-sm">
            <Sun className="size-4 scale-100 rotate-0 transition-all dark:scale-0 dark:-rotate-90" />
            <Moon className="absolute size-4 scale-0 rotate-90 transition-all dark:scale-100 dark:rotate-0" />
            <span className="sr-only">Toggle theme</span>
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end">
          <DropdownMenuRadioGroup
            value={theme}
            onValueChange={(v) => setTheme(v as "light" | "dark" | "system")}
          >
            <DropdownMenuRadioItem value="light">
              <Sun />
              Light
            </DropdownMenuRadioItem>
            <DropdownMenuRadioItem value="dark">
              <Moon />
              Dark
            </DropdownMenuRadioItem>
            <DropdownMenuRadioItem value="system">
              <Monitor />
              System
            </DropdownMenuRadioItem>
          </DropdownMenuRadioGroup>
        </DropdownMenuContent>
      </DropdownMenu>
    </header>
  );
}
