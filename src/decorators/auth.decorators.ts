import 'reflect-metadata';
import { PUBLIC_METADATA, ROLES_METADATA } from '../guards/auth.guard';

export function Public(): MethodDecorator & ClassDecorator {
  return (target: any, propertyKey?: string | symbol, descriptor?: PropertyDescriptor) => {
    if (propertyKey) {
      Reflect.defineMetadata(PUBLIC_METADATA, true, target[propertyKey]);
    } else {
      Reflect.defineMetadata(PUBLIC_METADATA, true, target);
    }
    return descriptor as any;
  };
}

export function Roles(...roles: string[]): MethodDecorator & ClassDecorator {
  return (target: any, propertyKey?: string | symbol, descriptor?: PropertyDescriptor) => {
    if (propertyKey) {
      Reflect.defineMetadata(ROLES_METADATA, roles, target[propertyKey]);
    } else {
      Reflect.defineMetadata(ROLES_METADATA, roles, target);
    }
    return descriptor as any;
  };
}

export function CurrentUser(): ParameterDecorator {
  return (target, propertyKey, parameterIndex) => {
    const existingParams: Map<number, string> = 
      Reflect.getMetadata('auth:currentUser', target, propertyKey!) || new Map();
    existingParams.set(parameterIndex, 'user');
    Reflect.defineMetadata('auth:currentUser', existingParams, target, propertyKey!);
  };
}

export const CURRENT_USER_METADATA = 'auth:currentUser';
