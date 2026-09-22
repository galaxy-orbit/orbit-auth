import type { JwtModuleOptions, JwtPayload, JwtSignOptions, JwtVerifyOptions } from '../interfaces/auth.interface';

let jose: any;

async function loadJose() {
  if (!jose) {
    try {
      jose = await import('jose');
    } catch {
      throw new Error('jose library is required for JWT operations. Install it with: bun add jose');
    }
  }
  return jose;
}

export class JwtService {
  private readonly options: JwtModuleOptions;
  private secretKey: Uint8Array | null = null;

  constructor(options: JwtModuleOptions = {}) {
    this.options = options;
    
    if (options.secret) {
      this.secretKey = new TextEncoder().encode(options.secret);
    }
  }

  async sign(payload: JwtPayload, options?: JwtSignOptions): Promise<string> {
    const { SignJWT } = await loadJose();
    
    const signOptions = { ...this.options.signOptions, ...options };
    const algorithm = signOptions.algorithm || 'HS256';

    let key: any;
    if (this.options.privateKey) {
      const { importPKCS8 } = await loadJose();
      key = await importPKCS8(this.options.privateKey, algorithm);
    } else if (this.secretKey) {
      key = this.secretKey;
    } else {
      throw new Error('No secret or private key configured');
    }

    let jwt = new SignJWT(payload)
      .setProtectedHeader({ alg: algorithm });

    if (signOptions.issuer) {
      jwt = jwt.setIssuer(signOptions.issuer);
    }
    if (signOptions.audience) {
      jwt = jwt.setAudience(signOptions.audience);
    }
    if (signOptions.subject) {
      jwt = jwt.setSubject(signOptions.subject);
    }
    if (signOptions.jwtid) {
      jwt = jwt.setJti(signOptions.jwtid);
    }
    if (signOptions.expiresIn) {
      const exp = typeof signOptions.expiresIn === 'number'
        ? `${signOptions.expiresIn}s`
        : signOptions.expiresIn;
      jwt = jwt.setExpirationTime(exp);
    }
    if (signOptions.notBefore) {
      const nbf = typeof signOptions.notBefore === 'number'
        ? `${signOptions.notBefore}s`
        : signOptions.notBefore;
      jwt = jwt.setNotBefore(nbf);
    }

    jwt = jwt.setIssuedAt();

    return jwt.sign(key);
  }

  async verify<T extends JwtPayload = JwtPayload>(
    token: string,
    options?: JwtVerifyOptions
  ): Promise<T> {
    const { jwtVerify, importSPKI } = await loadJose();
    
    const verifyOptions = { ...this.options.verifyOptions, ...options };

    let key: any;
    if (this.options.publicKey) {
      const algorithm = verifyOptions.algorithms?.[0] || 'RS256';
      key = await importSPKI(this.options.publicKey, algorithm);
    } else if (this.secretKey) {
      key = this.secretKey;
    } else {
      throw new Error('No secret or public key configured');
    }

    const verifyOpts: any = {};
    if (verifyOptions.issuer) {
      verifyOpts.issuer = verifyOptions.issuer;
    }
    if (verifyOptions.audience) {
      verifyOpts.audience = verifyOptions.audience;
    }
    if (verifyOptions.subject) {
      verifyOpts.subject = verifyOptions.subject;
    }
    if (verifyOptions.clockTolerance) {
      verifyOpts.clockTolerance = `${verifyOptions.clockTolerance}s`;
    }
    if (verifyOptions.maxTokenAge) {
      verifyOpts.maxTokenAge = typeof verifyOptions.maxTokenAge === 'number'
        ? `${verifyOptions.maxTokenAge}s`
        : verifyOptions.maxTokenAge;
    }

    const { payload } = await jwtVerify(token, key, verifyOpts);
    return payload as T;
  }

  async decode<T extends JwtPayload = JwtPayload>(token: string): Promise<T | null> {
    const { decodeJwt } = await loadJose();
    
    try {
      return decodeJwt(token) as T;
    } catch {
      return null;
    }
  }

  async signAsync(payload: JwtPayload, options?: JwtSignOptions): Promise<string> {
    return this.sign(payload, options);
  }

  async verifyAsync<T extends JwtPayload = JwtPayload>(
    token: string,
    options?: JwtVerifyOptions
  ): Promise<T> {
    return this.verify<T>(token, options);
  }
}

export const JWT_SERVICE = Symbol('JWT_SERVICE');
export const JWT_OPTIONS = Symbol('JWT_OPTIONS');
