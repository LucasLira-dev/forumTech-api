import { IsString, IsNotEmpty, MaxLength } from 'class-validator';

export class BanUserDto {
  @IsString({ message: 'O motivo deve ser uma string' })
  @IsNotEmpty({ message: 'Motivo do banimento é obrigatório' })
  @MaxLength(500, { message: 'Motivo não pode exceder 500 caracteres' })
  reason: string;
}