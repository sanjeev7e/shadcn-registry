import { NextRequest, NextResponse } from "next/server";
import { revokeToken } from "@/lib/token-store";

function isAdmin(request: NextRequest): boolean {
  const secret = process.env.REGISTRY_ADMIN_SECRET;
  const auth = request.headers.get("Authorization");
  const provided = auth?.startsWith("Bearer ") ? auth.slice(7) : null;
  return !!secret && provided === secret;
}

// DELETE /api/tokens/:token — revoke a token
export async function DELETE(
  request: NextRequest,
  { params }: { params: Promise<{ token: string }> }
) {
  if (!isAdmin(request)) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const { token } = await params;
  const revoked = await revokeToken(token);

  if (!revoked) {
    return NextResponse.json({ error: "Token not found" }, { status: 404 });
  }

  return NextResponse.json({ success: true });
}
