===ACP_FILE: design-auth-api-data-models/src/types/auth.routes.ts===
import type { User, UserRole, OAuthProvider, TokenPair } from "./auth.models";

// ─── Shared ────────────────────────────────────────────────────
interface ApiError {
  code: string;
  message: string;
  details?: Record<string, string[]>;
}

interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: ApiError;
}

// ─── POST /auth/signup ─────────────────────────────────────────
export interface SignupRequest {
  email: string;
  password: string;
  name: string;
}

export interface SignupResponse {
  user: Pick<User, "_id" | "email" | "name" | "role" | "isEmailVerified">;
  tokens: TokenPair;
}

// ─── POST /auth/login ──────────────────────────────────────────
export interface LoginRequest {
  email: string;
  password: string;
}

export interface LoginResponse {
  user: Pick<User, "_id" | "email" | "name" | "role" | "isEmailVerified">;
  tokens: TokenPair;
}

// ─── POST /auth/oauth/:provider ────────────────────────────────
export interface OAuthCallbackRequest {
  provider: OAuthProvider;
  code: string;
  redirectUri: string;
}

export interface OAuthCallbackResponse {
  user: Pick<User, "_id" | "email" | "name" | "role" | "isEmailVerified">;
  tokens: TokenPair;
  isNewUser: boolean;
}

// ─── POST /auth/logout ─────────────────────────────────────────
export interface LogoutRequest {
  refreshToken: string;
}

export interface LogoutResponse {
  message: string;
}

// ─── POST /auth/refresh ────────────────────────────────────────
export interface RefreshRequest {
  refreshToken: string;
}

export interface RefreshResponse {
  tokens: TokenPair;
}

// ─── POST /auth/forgot-password ────────────────────────────────
export interface ForgotPasswordRequest {
  email: string;
}

export interface ForgotPasswordResponse {
  message: string;
}

// ─── POST /auth/reset-password ─────────────────────────────────
export interface ResetPasswordRequest {
  token: string;
  newPassword: string;
}

export interface ResetPasswordResponse {
  message: string;
}

// ─── GET /auth/me (requires Bearer token) ──────────────────────
export interface MeResponse {
  user: Pick<User, "_id" | "email" | "name" | "avatarUrl" | "role" | "isEmailVerified" | "oauthProviders" | "createdAt">;
}

// ─── Route definition registry ─────────────────────────────────
export interface AuthRouteSpec {
  method: "POST" | "GET";
  path: string;
  authRequired: boolean;
  description: string;
}

export const AUTH_ROUTES: AuthRouteSpec[] = [
  { method: "POST", path: "/auth/signup",          authRequired: false, description: "Register new user" },
  { method: "POST", path: "/auth/login",           authRequired: false, description: "Email+password login" },
  { method: "POST", path: "/auth/oauth/:provider", authRequired: false, description: "OAuth2 code exchange" },
  { method: "POST", path: "/auth/logout",          authRequired: true,  description: "Invalidate session" },
  { method: "POST", path: "/auth/refresh",         authRequired: false, description: "Rotate token pair" },
  { method: "POST", path: "/auth/forgot-password", authRequired: false, description: "Send reset email" },
  { method: "POST", path: "/auth/reset-password",  authRequired: false, description: "Confirm password reset" },
  { method: "GET",  path: "/auth/me",              authRequired: true,  description: "Current user profile" },
];

export type { ApiResponse, ApiError };