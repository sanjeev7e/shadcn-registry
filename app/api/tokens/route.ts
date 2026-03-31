import { NextRequest, NextResponse } from "next/server";
import { createToken, listTokens } from "@/lib/token-store";

function isAdmin(request: NextRequest): boolean {
  const secret = process.env.REGISTRY_ADMIN_SECRET;
  const auth = request.headers.get("Authorization");
  const provided = auth?.startsWith("Bearer ") ? auth.slice(7) : null;
  return !!secret && provided === secret;
}

// GET /api/tokens — list all tokens
export async function GET(request: NextRequest) {
  if (!isAdmin(request)) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const tokens = await listTokens();
  return NextResponse.json(tokens);
}

// POST /api/tokens — create a new token
// Body: { components: string[], expiresAt: string, label?: string }
export async function POST(request: NextRequest) {
  if (!isAdmin(request)) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  let body: { components?: unknown; expiresAt?: unknown; label?: unknown };
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
  }

  const { components, expiresAt, label } = body;

  if (
    !Array.isArray(components) ||
    components.length === 0 ||
    typeof expiresAt !== "string"
  ) {
    return NextResponse.json(
      { error: "components (non-empty array) and expiresAt (ISO string) are required" },
      { status: 400 }
    );
  }

  if (isNaN(Date.parse(expiresAt))) {
    return NextResponse.json(
      { error: "expiresAt must be a valid ISO 8601 date string" },
      { status: 400 }
    );
  }

  const entry = await createToken({
    components: components as string[],
    expiresAt,
    label: typeof label === "string" ? label : undefined,
  });

  return NextResponse.json(entry, { status: 201 });
}
