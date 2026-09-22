import 'reflect-metadata';
import type { AuthContext, JwtPayload } from '../interfaces/auth.interface';
import { JwtService } from '../services/jwt.service';

export const PUBLIC_METADATA = 'auth:public';
export const ROLES_METADATA = 'auth:roles';

export class UnauthorizedException extends Error {
  public readonly statusCode = 401;

  constructor(message: string = 'Unauthorized') {
    super(message);
    this.name = 'UnauthorizedException';
  }
}

export class ForbiddenException extends Error {
  public readonly statusCode = 403;

  constructor(message: string = 'Forbidden') {
    super(message);
    this.name = 'ForbiddenException';
  }
}

export interface AuthGuardOptions {
  jwtService: JwtService;
  extractToken?: (request: any) => string | null;
  validateUser?: (payload: JwtPayload) => Promise<any> | any;
}

export class AuthGuard {
  private readonly jwtService: JwtService;
  private readonly extractToken: (request: any) => string | null;
  private readonly validateUser?: (payload: JwtPayload) => Promise<any> | any;

  constructor(options: AuthGuardOptions) {
    this.jwtService = options.jwtService;
    this.extractToken = options.extractToken || this.defaultExtractToken;
    this.validateUser = options.validateUser;
  }

  private defaultExtractToken(request: any): string | null {
    const authorization = request.headers?.['authorization'] || 
                          request.headers?.['Authorization'];
    
    if (!authorization) {
      return null;
    }

    const [type, token] = authorization.split(' ');
    
    if (type?.toLowerCase() !== 'bearer' || !token) {
      return null;
    }

    return token;
  }

  async canActivate(context: AuthContext): Promise<boolean> {
    const handler = context.getHandler();
    const classRef = context.getClass();

    const isPublic = Reflect.getMetadata(PUBLIC_METADATA, handler) ||
                     Reflect.getMetadata(PUBLIC_METADATA, classRef);

    if (isPublic) {
      return true;
    }

    const request = context.getRequest();
    const token = this.extractToken(request);

    if (!token) {
      throw new UnauthorizedException('No token provided');
    }

    try {
      const payload = await this.jwtService.verify(token);
      
      let user = payload;
      if (this.validateUser) {
        user = await this.validateUser(payload);
        if (!user) {
          throw new UnauthorizedException('Invalid user');
        }
      }

      request.user = user;

      const requiredRoles: string[] = Reflect.getMetadata(ROLES_METADATA, handler) ||
                                       Reflect.getMetadata(ROLES_METADATA, classRef) ||
                                       [];

      if (requiredRoles.length > 0) {
        const userRoles = user.roles || user.role || [];
        const roles = Array.isArray(userRoles) ? userRoles : [userRoles];
        
        const hasRole = requiredRoles.some(role => roles.includes(role));
        if (!hasRole) {
          throw new ForbiddenException('Insufficient permissions');
        }
      }

      return true;
    } catch (error) {
      if (error instanceof UnauthorizedException || error instanceof ForbiddenException) {
        throw error;
      }
      throw new UnauthorizedException('Invalid token');
    }
  }
}

export const AUTH_GUARD = Symbol('AUTH_GUARD');
