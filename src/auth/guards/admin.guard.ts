import { Injectable, CanActivate, ExecutionContext, ForbiddenException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { UserRole } from '../../user/entities/user.entity';

@Injectable()
export class AdminGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest();
    const user = request.user;

    if (!user) {
      throw new ForbiddenException('Token de acesso necessário');
    }

    // ✅ Verificar se é admin ou moderador (se implementado)
    const allowedRoles = [UserRole.ADMIN];
    
    if (!allowedRoles.includes(user.role)) {
      throw new ForbiddenException('Acesso restrito a administradores');
    }

    return true;
  }
}
