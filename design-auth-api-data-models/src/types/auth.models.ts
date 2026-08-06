===ACP_FILE: design-auth-api-data-models/src/types/auth.models.ts===
import type { ObjectId } from "mongodb";

// ─── User Entity ───────────────────────────────────────────────
export interface User {
  _id: ObjectId;
  email: string;
  passwordHash: string;
  name: string;
  avatarUrl?: string;
  role: UserRole;
  oauthProviders: OAuthProviderLink[];
  isEmailVerified: boolean;
  passwordResetToken?: string;
  passwordResetExpires?: Date;
  createdAt: Date;
  updatedAt: Date;
}

export enum UserRole {
  USER = "user",
  ADMIN = "admin",
}

export interface OAuthProviderLink {
  provider: OAuthProvider;
  providerId: string;
  accessToken?: string;
  refreshToken?: string;
}

export enum OAuthProvider {
  GOOGLE = "google",
  GITHUB = "github",
  APPLE = "apple",
}

// ─── Session Entity ────────────────────────────────────────────
export interface Session {
  _id: ObjectId;
  userId: ObjectId;
  refreshTokenHash: string;
  deviceInfo?: string;
  ipAddress?: string;
  expiresAt: Date;
  createdAt: Date;
}

// ─── Token Entity ──────────────────────────────────────────────
export interface TokenPair {
  accessToken: string;
  refreshToken: string;
  expiresIn: number; // seconds until accessToken expires
}

export interface JwtPayload {
  sub: string;       // userId
  email: string;
  role: UserRole;
  sid: string;       // sessionId
  iat: number;
  exp: number;
}