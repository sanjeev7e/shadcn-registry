import fs from "fs/promises";
import { NextRequest, NextResponse } from "next/server";
import path from "path";
import { lookupToken } from "@/lib/token-store";

// GET /api/r/:name — serve a registry component JSON, validated by user token
export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ name: string }> }
) {
  const auth = request.headers.get("Authorization");
  const provided = auth?.startsWith("Bearer ") ? auth.slice(7) : null;

  if (!provided) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const entry = await lookupToken(provided);
  if (!entry) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  if (new Date(entry.expiresAt) < new Date()) {
    return NextResponse.json(
      { error: "Forbidden", reason: "Token has expired" },
      { status: 403 }
    );
  }

  const { name } = await params;
  const componentName = name.replace(/\.json$/, "");

  const hasAccess =
    entry.components.includes("*") || entry.components.includes(componentName);
  if (!hasAccess) {
    return NextResponse.json(
      { error: "Forbidden", reason: "Token does not have access to this component" },
      { status: 403 }
    );
  }

  const filePath = path.join(process.cwd(), "public", "r", `${componentName}.json`);
  try {
    const content = await fs.readFile(filePath, "utf-8");
    return new NextResponse(content, {
      headers: { "Content-Type": "application/json" },
    });
  } catch {
    return NextResponse.json({ error: "Component not found" }, { status: 404 });
  }
}
