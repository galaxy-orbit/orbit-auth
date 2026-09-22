# @galaxy-stack/orbit-auth

[![npm version](https://img.shields.io/npm/v/@galaxy-stack/orbit-auth.svg)](https://www.npmjs.com/package/@galaxy-stack/orbit-auth)
[![docs](https://img.shields.io/badge/docs-galaxy--orbit--framework.vercel.app-blue)](https://galaxy-orbit-framework.vercel.app)

Part of the [Orbit framework](https://github.com/galaxy-orbit/orbit) — a NestJS-style backend framework for [Bun](https://bun.sh).

## Installation

```bash
bun add @galaxy-stack/orbit-auth
```

# @galaxy-stack/orbit-auth

## Mô tả
Module xác thực cho Orbit với JWT support sử dụng thư viện `jose` và password hashing với Bun native API.

## Tính năng chính

### 1. JWT Service
```typescript
import { JwtService } from '@galaxy-stack/orbit-auth';

const jwt = new JwtService({
  secret: 'your-secret-key',
  expiresIn: '1h',
});

// Tạo token
const token = await jwt.sign({ userId: 1, role: 'admin' });

// Verify token
const payload = await jwt.verify(token);

// Decode (không verify)
const decoded = jwt.decode(token);
```

### 2. Password Service
```typescript
import { PasswordService } from '@galaxy-stack/orbit-auth';

const password = new PasswordService();

// Hash password (sử dụng Bun.password)
const hash = await password.hash('my-password');

// Verify password
const isValid = await password.verify('my-password', hash);
```

### 3. Auth Guard
```typescript
import { AuthGuard, UseGuards } from '@galaxy-stack/orbit-auth';

@Controller('protected')
@UseGuards(AuthGuard)
class ProtectedController {
  @Get()
  getProtectedData() {
    return { secret: 'data' };
  }
}
```

## Cấu hình Module

```typescript
import { AuthModule } from '@galaxy-stack/orbit-auth';

@Module({
  imports: [
    AuthModule.forRoot({
      jwt: {
        secret: process.env.JWT_SECRET,
        expiresIn: '7d',
      },
      password: {
        algorithm: 'argon2id',  // hoặc 'bcrypt'
      },
    }),
  ],
})
class AppModule {}
```

### Async Configuration
```typescript
AuthModule.forRootAsync({
  inject: [ConfigService],
  useFactory: (config: ConfigService) => ({
    jwt: {
      secret: config.get('JWT_SECRET'),
      expiresIn: config.get('JWT_EXPIRES_IN'),
    },
  }),
})
```

## JWT Options

```typescript
interface JwtOptions {
  secret: string;           // Secret key
  publicKey?: string;       // Public key (RS256)
  privateKey?: string;      // Private key (RS256)
  algorithm?: string;       // HS256, RS256, ES256, etc.
  expiresIn?: string;       // '1h', '7d', '30m'
  issuer?: string;          // Token issuer
  audience?: string;        // Token audience
}
```

## Password Algorithms
- `argon2id` (recommended)
- `argon2i`
- `argon2d`
- `bcrypt`

## Custom AuthGuard

```typescript
import { AuthGuard as BaseAuthGuard, JwtService } from '@galaxy-stack/orbit-auth';

class CustomAuthGuard extends BaseAuthGuard {
  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const token = this.extractToken(request);
    
    if (!token) return false;
    
    try {
      const payload = await this.jwtService.verify(token);
      request.user = payload;
      return true;
    } catch {
      return false;
    }
  }
}
```
