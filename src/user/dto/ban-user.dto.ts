import { IsString, IsNotEmpty, MaxLength, MinLength } from 'class-validator';

export class BanUserDto {
  @IsString({ message: 'O motivo deve ser uma string' })
  @IsNotEmpty({ message: 'Motivo do banimento é obrigatório' })
  @MinLength(10, { message: 'Motivo deve ter pelo menos 10 caracteres' })
  @MaxLength(500, { message: 'Motivo não pode exceder 500 caracteres' })
  reason: string;
}