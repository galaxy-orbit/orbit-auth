import { describe, test, expect } from 'bun:test';
import 'reflect-metadata';
import { AuthGuard, UnauthorizedException, ForbiddenException, PUBLIC_METADATA, ROLES_METADATA } from './auth.guard';
import { JwtService } from '../services/jwt.service';

function makeContext(handler: Function, request: any) {
  const ctor = function AuthController() {};
  return {
    getHandler: () => handler,
    getClass: () => ctor,
    getRequest: () => request,
  } as any;
}

const jwt = new JwtService({ secret: 'guard-test-secret' });

async function makeToken(payload: Record<string, any>) {
  return jwt.sign(payload as any, { expiresIn: 60 });
}

describe('AuthGuard — token extraction', () => {
  test('default extractor reads bearer from headers (any case)', async () => {
    const guard = new AuthGuard({ jwtService: jwt });
    const token = await makeToken({ sub: 'u1' });

    const ok = await guard.canActivate(makeContext(() => {}, {
      headers: { Authorization: `Bearer ${token}` },
    }));
    expect(ok).toBe(true);

    const ok2 = await guard.canActivate(makeContext(() => {}, {
      headers: { authorization: `bearer ${token}` },
    }));
    expect(ok2).toBe(true);
  });

  test('missing/malformed headers reject with No token provided', async () => {
    const guard = new AuthGuard({ jwtService: jwt });

    await expect(guard.canActivate(makeContext(() => {}, { headers: {} })))
      .rejects.toThrow('No token provided');
    await expect(guard.canActivate(makeContext(() => {}, {
      headers: { authorization: 'Basic abc' },
    }))).rejects.toThrow('No token provided');
    await expect(guard.canActivate(makeContext(() => {}, {
      headers: { authorization: 'Bearer' },
    }))).rejects.toThrow('No token provided');
  });

  test('custom extractToken is respected', async () => {
    const guard = new AuthGuard({
      jwtService: jwt,
      extractToken: (req: any) => req.query?.token ?? null,
    });
    const token = await makeToken({ sub: 'u2' });
    expect(await guard.canActivate(makeContext(() => {}, { query: { token } }))).toBe(true);
  });
});

describe('AuthGuard — @Public routes', () => {
  test('method-level and class-level PUBLIC bypass auth entirely', async () => {
    const guard = new AuthGuard({ jwtService: jwt });

    const publicHandler = () => {};
    Reflect.defineMetadata(PUBLIC_METADATA, true, publicHandler);

    class PublicClass {}
    Reflect.defineMetadata(PUBLIC_METADATA, true, PublicClass);

    await expect(guard.canActivate(makeContext(publicHandler, {}))).resolves.toBe(true);
    await expect(guard.canActivate({
      getHandler: () => ({} as any),
      getClass: () => PublicClass,
      getRequest: () => ({}),
    } as any)).resolves.toBe(true);
  });
});

describe('AuthGuard — verification and user mapping', () => {
  test('invalid tokens map to UnauthorizedException Invalid token', async () => {
    const guard = new AuthGuard({ jwtService: jwt });
    await expect(guard.canActivate(makeContext(() => {}, {
      headers: { authorization: 'Bearer not-a-jwt' },
    }))).rejects.toThrow('Invalid token');
  });

  test('payload lands on request.user', async () => {
    const guard = new AuthGuard({ jwtService: jwt });
    const request: any = { headers: { authorization: `Bearer ${await makeToken({ sub: 'u3', roles: ['user'] })}` } };
    await guard.canActivate(makeContext(() => {}, request));
    expect(request.user.sub).toBe('u2'.replace('2', '3'));
  });

  test('validateUser maps payload and rejects null users', async () => {
    const guard = new AuthGuard({
      jwtService: jwt,
      validateUser: (payload: any) => ({ id: 1, email: payload.sub, roles: ['admin'] }),
    });
    const request: any = { headers: { authorization: `Bearer ${await makeToken({ sub: 'me@x.dev' })}` } };
    await guard.canActivate(makeContext(() => {}, request));
    expect(request.user.email).toBe('me@x.dev');

    const rejecting = new AuthGuard({ jwtService: jwt, validateUser: () => null });
    await expect(rejecting.canActivate(makeContext(() => {}, {
      headers: { authorization: `Bearer ${await makeToken({ sub: 'x' })}` },
    }))).rejects.toThrow('Invalid user');
  });
});

describe('AuthGuard — role enforcement', () => {
  const makeGuard = () => new AuthGuard({ jwtService: jwt });

  test('required role present in roles array passes', async () => {
    const guard = new AuthGuard({ jwtService: jwt });
    const handler = () => {};
    Reflect.defineMetadata(ROLES_METADATA, ['admin'], handler);

    const token = await makeToken({ sub: 'a', roles: ['user', 'admin'] });
    const request: any = { headers: { authorization: `Bearer ${token}` } };
    await expect(guard.canActivate(makeContext(handler, request))).resolves.toBe(true);
  });

  test('missing role raises ForbiddenException 403', async () => {
    const guard = new AuthGuard({ jwtService: jwt });
    const handler = () => {};
    Reflect.defineMetadata(ROLES_METADATA, ['admin'], handler);

    const token = await makeToken({ sub: 'b', roles: ['user'] });
    try {
      await guard.canActivate(makeContext(handler, {
        headers: { authorization: `Bearer ${token}` },
      }));
      throw new Error('should not reach');
    } catch (e: any) {
      expect(e).toBeInstanceOf(ForbiddenException);
      expect(e.statusCode).toBe(403);
      expect(e.message).toBe('Insufficient permissions');
    }
  });

  test('single string role works alongside arrays', async () => {
    const guard = new AuthGuard({ jwtService: jwt });
    const handler = () => {};
    Reflect.defineMetadata(ROLES_METADATA, ['editor'], handler);

    const token = await makeToken({ sub: 'c', role: 'editor' });
    await expect(guard.canActivate(makeContext(handler, {
      headers: { authorization: `Bearer ${token}` },
    }))).resolves.toBe(true);
  });
});

describe('AuthGuard — exception mapping', () => {
  test('validateUser errors surface as UnauthorizedException Invalid token', async () => {
    const guard = new AuthGuard({
      jwtService: jwt,
      validateUser: () => { throw new Error('db exploded'); },
    });

    // validateUser throwing UnauthorizedException keeps its identity
    const withAuthError = new AuthGuard({
      jwtService: jwt,
      validateUser: () => { throw new UnauthorizedException('custom message'); },
    });
    await expect(withAuthError.canActivate(makeContext(() => {}, {
      headers: { authorization: `Bearer ${await makeToken({ sub: 'd' })}` },
    }))).rejects.toThrow('custom message');

    await expect(guard.canActivate(makeContext(() => {}, {
      headers: { authorization: `Bearer ${await makeToken({ sub: 'x' })}` },
    }))).rejects.toThrow('Invalid token');
  });

  test('exception classes carry the documented status codes', () => {
    expect(new UnauthorizedException().statusCode).toBe(401);
    expect(new ForbiddenException().statusCode).toBe(403);
    expect(new UnauthorizedException('msg').name).toBe('UnauthorizedException');
  });
});
