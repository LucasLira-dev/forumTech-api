import { IsBoolean, IsOptional, IsString, IsUrl, MaxLength, MinLength } from "class-validator";

export class CreateProfileDto {
    @IsOptional()
    @IsString( { message: 'O nome de usuário deve ser uma string' })
    @MaxLength(30, { message: 'O nome de usuário não pode ter mais que 30 caracteres' })
    @MinLength(3, { message: 'Nome de usuário deve ter pelo menos 3 caracteres' })
    userName?: string;

    @IsOptional()
    @IsString({ message: 'A bio deve ser uma string' })
    @MaxLength(200, { message: 'A bio não pode ter mais que 200 caracteres' })
    bio?: string;

    @IsOptional()
    @IsUrl({}, { message: 'Avatar URL deve ser uma URL válida' })
    avatarUrl?: string;

    @IsOptional()
    @IsBoolean( { message: 'isPublic apenas aceita true ou false' })
    isPublic?: boolean;

    @IsOptional()
    @IsUrl({}, { message: 'Capa URL deve ser uma URL válida' })
    capaUrl?: string;
}
