import { describe, test, expect } from 'bun:test';
import { JwtService } from './services/jwt.service';
import { PasswordService } from './services/password.service';

describe('JwtService', () => {
  const service = new JwtService({ secret: 'test-secret-key-for-orbit-framework' });

  test('signs and verifies round-trip payload', async () => {
    const payload = { sub: 'user-1', email: 'user@orbit.dev', role: 'admin' };
    const token = await service.sign(payload, { expiresIn: 3600 });
    expect(typeof token).toBe('string');
    const parts = token.split('.');
    expect(parts).toHaveLength(3);

    const decoded = await service.verify<{ sub?: string; email: string }>(token);
    expect(decoded.email).toBe('user@orbit.dev');
    expect(decoded.sub).toBe('user-1');
  });

  test('rejects a token signed with a different secret', async () => {
    const other = new JwtService({ secret: 'another-secret-entirely' });
    const token = await other.sign({ sub: 'user-2' }, { expiresIn: 60 });
    await expect(service.verify(token)).rejects.toThrow();
  });

  test('expired tokens are rejected', async () => {
    const token = await service.sign({ sub: 'user-3' }, { expiresIn: -10 });
    await expect(service.verify(token)).rejects.toThrow();
  });

  test('issuer and audience are enforced on verify', async () => {
    const token = await service.sign({ sub: 'user-4' }, { expiresIn: 300, issuer: 'orbit-auth', audience: 'orbit-api' });

    expect((await service.verify(token, { issuer: 'orbit-auth', audience: 'orbit-api' })).sub).toBe('user-4');
    await expect(service.verify(token, { issuer: 'other-issuer' })).rejects.toThrow();
    await expect(service.verify(token, { audience: 'other-audience' })).rejects.toThrow();
  });

  test('decode extracts payload without verification', async () => {
    const token = await service.sign({ sub: 'user-5', role: 'user' }, { expiresIn: 300 });
    const payload = await service.decode<any>(token);
    expect(payload?.sub).toBe('user-5');
    expect(payload?.role).toBe('user');
  });

  test('decode returns null for garbage input', async () => {
    expect(await service.decode('not-a-jwt')).toBeNull();
  });

  test('throws when no secret configured', async () => {
    const empty = new JwtService({});
    await expect(empty.sign({ sub: 'x' })).rejects.toThrow('No secret or private key configured');
    await expect(empty.verify('token')).rejects.toThrow('No secret or public key configured');
  });
});

describe('PasswordService', () => {
  const service = new PasswordService();

  test('hash + verify round-trip (argon2id)', async () => {
    const hash = await service.hash('correct horse battery staple');
    expect(hash.startsWith('$argon2id$')).toBe(true);

    expect(await service.verify('correct horse battery staple', hash)).toBe(true);
    expect(await service.verify('wrong password', hash)).toBe(false);
  });

  test('different hashes for identical passwords (salted)', async () => {
    const h1 = await service.hash('same-password');
    const h2 = await service.hash('same-password');
    expect(h1).not.toBe(h2);
    expect(await service.verify('same-password', h2)).toBe(true);
  });

  test('needsRehash detects algorithm mismatch', async () => {
    const hash = await service.hash('pw', { algorithm: 'bcrypt' });
    expect(await service.needsRehash(hash, { algorithm: 'argon2id' })).toBe(true);
    expect(await service.needsRehash(hash, { algorithm: 'bcrypt' })).toBe(false);
  });

  test('detects bcrypt-formatted hashes', async () => {
    const hash = await service.hash('pw', { algorithm: 'bcrypt' });
    expect(hash.startsWith('$2')).toBe(true);
    expect(await service.verify('pw', hash)).toBe(true);
  });
});
