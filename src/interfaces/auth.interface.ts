export interface JwtModuleOptions {
  secret?: string;
  publicKey?: string;
  privateKey?: string;
  signOptions?: JwtSignOptions;
  verifyOptions?: JwtVerifyOptions;
}

export interface JwtSignOptions {
  algorithm?: 'HS256' | 'HS384' | 'HS512' | 'RS256' | 'RS384' | 'RS512' | 'ES256' | 'ES384' | 'ES512' | 'PS256' | 'PS384' | 'PS512';
  expiresIn?: string | number;
  issuer?: string;
  audience?: string | string[];
  subject?: string;
  jwtid?: string;
  notBefore?: string | number;
}

export interface JwtVerifyOptions {
  algorithms?: string[];
  issuer?: string | string[];
  audience?: string | string[];
  subject?: string;
  clockTolerance?: number;
  maxTokenAge?: string | number;
}

export interface JwtPayload {
  sub?: string;
  iss?: string;
  aud?: string | string[];
  exp?: number;
  nbf?: number;
  iat?: number;
  jti?: string;
  [key: string]: any;
}

export interface AuthRequest {
  user?: any;
  headers?: Record<string, string>;
}

export interface AuthContext {
  getRequest(): AuthRequest;
  getResponse(): any;
  getHandler(): Function;
  getClass(): any;
}

export interface PasswordHashOptions {
  algorithm?: 'bcrypt' | 'argon2id' | 'argon2d' | 'argon2i';
  memoryCost?: number;
  timeCost?: number;
}
