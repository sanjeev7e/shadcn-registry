import crypto from "crypto";
import fs from "fs/promises";
import path from "path";

const DATA_FILE = path.join(process.cwd(), "data", "tokens.json");

export interface TokenEntry {
  token: string;
  label?: string;
  components: string[]; // component names, or ["*"] for full access
  expiresAt: string;    // ISO 8601
  createdAt: string;    // ISO 8601
}

async function read(): Promise<Record<string, TokenEntry>> {
  try {
    const raw = await fs.readFile(DATA_FILE, "utf-8");
    return JSON.parse(raw);
  } catch {
    return {};
  }
}

async function persist(store: Record<string, TokenEntry>): Promise<void> {
  await fs.mkdir(path.dirname(DATA_FILE), { recursive: true });
  await fs.writeFile(DATA_FILE, JSON.stringify(store, null, 2));
}

export async function createToken(params: {
  components: string[];
  expiresAt: string;
  label?: string;
}): Promise<TokenEntry> {
  const store = await read();
  const token = "tok_" + crypto.randomBytes(24).toString("hex");
  const entry: TokenEntry = {
    token,
    label: params.label,
    components: params.components,
    expiresAt: params.expiresAt,
    createdAt: new Date().toISOString(),
  };
  store[token] = entry;
  await persist(store);
  return entry;
}

export async function lookupToken(token: string): Promise<TokenEntry | null> {
  const store = await read();
  return store[token] ?? null;
}

export async function listTokens(): Promise<TokenEntry[]> {
  const store = await read();
  return Object.values(store);
}

export async function revokeToken(token: string): Promise<boolean> {
  const store = await read();
  if (!store[token]) return false;
  delete store[token];
  await persist(store);
  return true;
}
