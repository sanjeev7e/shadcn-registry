import { NextRequest, NextResponse } from "next/server";

function extractBearer(request: NextRequest): string | null {
  const auth = request.headers.get("Authorization");
  return auth?.startsWith("Bearer ") ? auth.slice(7) : null;
}

// ── Static mode ───────────────────────────────────────────────────────────────
// Single shared token in REGISTRY_TOKEN. Protects /r/* static files.
function validateStatic(provided: string | null): NextResponse | null {
  const token = process.env.REGISTRY_TOKEN;
  if (!token || provided !== token) {
    return new NextResponse(JSON.stringify({ error: "Unauthorized" }), {
      status: 401,
      headers: { "Content-Type": "application/json" },
    });
  }
  return null;
}

// ── Middleware ────────────────────────────────────────────────────────────────
export function middleware(request: NextRequest) {
  const mode = process.env.REGISTRY_AUTH_MODE ?? "public";

  if (mode === "public") {
    return NextResponse.next();
  }

  if (mode === "dynamic") {
    // Direct /r/* access is disabled in dynamic mode.
    // Consumers must use /api/r/{name} with a user token.
    return new NextResponse(
      JSON.stringify({ error: "Use /api/r/{name} with a Bearer token" }),
      { status: 404, headers: { "Content-Type": "application/json" } }
    );
  }

  const error = validateStatic(extractBearer(request));
  if (error) return error;

  return NextResponse.next();
}

export const config = {
  matcher: "/r/:path*",
};
