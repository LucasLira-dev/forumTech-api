import { IsEnum, IsNotEmpty } from 'class-validator';
import { UserRole } from '../entities/user.entity';

export class UpdateUserRoleDto {
  @IsEnum(UserRole, { 
    message: 'Função deve ser user, admin ou moderator' 
  })
  @IsNotEmpty({ message: 'Função é obrigatória' })
  role: UserRole;
}