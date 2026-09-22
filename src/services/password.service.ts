import type { PasswordHashOptions } from '../interfaces/auth.interface';

export class PasswordService {
  private readonly defaultOptions: PasswordHashOptions;

  constructor(options: PasswordHashOptions = {}) {
    this.defaultOptions = {
      algorithm: options.algorithm || 'argon2id',
      memoryCost: options.memoryCost,
      timeCost: options.timeCost,
    };
  }

  async hash(password: string, options?: PasswordHashOptions): Promise<string> {
    const opts = { ...this.defaultOptions, ...options };
    
    return Bun.password.hash(password, {
      algorithm: opts.algorithm as any,
      memoryCost: opts.memoryCost,
      timeCost: opts.timeCost,
    });
  }

  async verify(password: string, hash: string): Promise<boolean> {
    return Bun.password.verify(password, hash);
  }

  async needsRehash(hash: string, options?: PasswordHashOptions): Promise<boolean> {
    const currentAlgorithm = this.detectAlgorithm(hash);
    const targetAlgorithm = options?.algorithm || this.defaultOptions.algorithm;
    
    return currentAlgorithm !== targetAlgorithm;
  }

  private detectAlgorithm(hash: string): string {
    if (hash.startsWith('$argon2id$')) return 'argon2id';
    if (hash.startsWith('$argon2i$')) return 'argon2i';
    if (hash.startsWith('$argon2d$')) return 'argon2d';
    if (hash.startsWith('$2a$') || hash.startsWith('$2b$') || hash.startsWith('$2y$')) return 'bcrypt';
    return 'unknown';
  }
}

export const PASSWORD_SERVICE = Symbol('PASSWORD_SERVICE');
