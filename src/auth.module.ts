import type { DynamicModule } from '@galaxy-stack/orbit-core';
import type { JwtModuleOptions, PasswordHashOptions } from './interfaces/auth.interface';
import { JwtService, JWT_SERVICE, JWT_OPTIONS } from './services/jwt.service';
import { PasswordService, PASSWORD_SERVICE } from './services/password.service';
import { AuthGuard, AUTH_GUARD, type AuthGuardOptions } from './guards/auth.guard';

export interface AuthModuleOptions {
  jwt?: JwtModuleOptions;
  password?: PasswordHashOptions;
  guard?: Omit<AuthGuardOptions, 'jwtService'>;
  isGlobal?: boolean;
}

export interface AuthModuleAsyncOptions {
  imports?: any[];
  useFactory: (...args: any[]) => Promise<AuthModuleOptions> | AuthModuleOptions;
  inject?: any[];
  isGlobal?: boolean;
}

export class JwtModule {
  static register(options: JwtModuleOptions): DynamicModule {
    return {
      module: JwtModule,
      providers: [
        {
          provide: JWT_OPTIONS,
          useValue: options,
        },
        {
          provide: JWT_SERVICE,
          useFactory: () => new JwtService(options),
        },
        {
          provide: JwtService,
          useExisting: JWT_SERVICE,
        },
      ],
      exports: [JWT_SERVICE, JwtService],
    };
  }

  static registerAsync(options: {
    imports?: any[];
    useFactory: (...args: any[]) => Promise<JwtModuleOptions> | JwtModuleOptions;
    inject?: any[];
  }): DynamicModule {
    return {
      module: JwtModule,
      imports: options.imports || [],
      providers: [
        {
          provide: JWT_OPTIONS,
          useFactory: options.useFactory,
          inject: options.inject || [],
        },
        {
          provide: JWT_SERVICE,
          useFactory: (opts: JwtModuleOptions) => new JwtService(opts),
          inject: [JWT_OPTIONS],
        },
        {
          provide: JwtService,
          useExisting: JWT_SERVICE,
        },
      ],
      exports: [JWT_SERVICE, JwtService],
    };
  }
}

export const AUTH_MODULE_OPTIONS = Symbol('AUTH_MODULE_OPTIONS');

export class AuthModule {
  static forRoot(options: AuthModuleOptions = {}): DynamicModule {
    return {
      module: AuthModule,
      global: options.isGlobal ?? true,
      providers: [
        {
          provide: AUTH_MODULE_OPTIONS,
          useValue: options,
        },
        {
          provide: JWT_OPTIONS,
          useFactory: (opts: AuthModuleOptions) => opts.jwt || {},
          inject: [AUTH_MODULE_OPTIONS],
        },
        {
          provide: JWT_SERVICE,
          useFactory: (opts: AuthModuleOptions) => new JwtService(opts.jwt || {}),
          inject: [AUTH_MODULE_OPTIONS],
        },
        {
          provide: JwtService,
          useExisting: JWT_SERVICE,
        },
        {
          provide: PASSWORD_SERVICE,
          useFactory: (opts: AuthModuleOptions) => new PasswordService(opts.password),
          inject: [AUTH_MODULE_OPTIONS],
        },
        {
          provide: PasswordService,
          useExisting: PASSWORD_SERVICE,
        },
        {
          provide: AUTH_GUARD,
          useFactory: (opts: AuthModuleOptions, jwtService: JwtService) => {
            return new AuthGuard({ jwtService, ...opts.guard });
          },
          inject: [AUTH_MODULE_OPTIONS, JWT_SERVICE],
        },
        {
          provide: AuthGuard,
          useExisting: AUTH_GUARD,
        },
      ],
      exports: [
        AUTH_MODULE_OPTIONS,
        JWT_SERVICE, 
        JwtService, 
        PASSWORD_SERVICE, 
        PasswordService, 
        AUTH_GUARD, 
        AuthGuard,
      ],
    };
  }

  static forRootAsync(options: AuthModuleAsyncOptions): DynamicModule {
    return {
      module: AuthModule,
      global: options.isGlobal ?? true,
      imports: options.imports || [],
      providers: [
        {
          provide: AUTH_MODULE_OPTIONS,
          useFactory: options.useFactory,
          inject: options.inject || [],
        },
        {
          provide: JWT_SERVICE,
          useFactory: (opts: AuthModuleOptions) => new JwtService(opts.jwt || {}),
          inject: [AUTH_MODULE_OPTIONS],
        },
        {
          provide: JwtService,
          useExisting: JWT_SERVICE,
        },
        {
          provide: PASSWORD_SERVICE,
          useFactory: (opts: AuthModuleOptions) => new PasswordService(opts.password),
          inject: [AUTH_MODULE_OPTIONS],
        },
        {
          provide: PasswordService,
          useExisting: PASSWORD_SERVICE,
        },
        {
          provide: AUTH_GUARD,
          useFactory: (opts: AuthModuleOptions, jwtService: JwtService) => {
            return new AuthGuard({ jwtService, ...opts.guard });
          },
          inject: [AUTH_MODULE_OPTIONS, JWT_SERVICE],
        },
        {
          provide: AuthGuard,
          useExisting: AUTH_GUARD,
        },
      ],
      exports: [
        AUTH_MODULE_OPTIONS,
        JWT_SERVICE, 
        JwtService, 
        PASSWORD_SERVICE, 
        PasswordService, 
        AUTH_GUARD, 
        AuthGuard,
      ],
    };
  }
}
