import crypto from 'node:crypto';
import argon2 from 'argon2';

let dummyPasswordHash: string | null = null;

export function generateOpaqueToken(byteLength = 32): string {
  return crypto.randomBytes(byteLength).toString('hex');
}

export function hashSha256(data: string | Buffer): string {
  return crypto.createHash('sha256').update(data).digest('hex');
}

export async function hashPassword(password: string): Promise<string> {
  return argon2.hash(password, {
    type: argon2.argon2id,
  });
}

export async function verifyPassword(hash: string, plain: string): Promise<boolean> {
  try {
    return await argon2.verify(hash, plain);
  } catch {
    return false;
  }
}

export async function getDummyPasswordHash(): Promise<string> {
  if (!dummyPasswordHash) {
    dummyPasswordHash = await argon2.hash('zenuxs-dummy-password-for-timing-enumeration-protection', {
      type: argon2.argon2id,
    });
  }
  return dummyPasswordHash;
}

export async function verifyDummyPassword(plain: string): Promise<void> {
  const dummy = await getDummyPasswordHash();
  try {
    await argon2.verify(dummy, plain);
  } catch {
    // Ignore verification result for dummy password
  }
}
