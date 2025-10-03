import { IsNotEmpty, IsString, IsUUID } from 'class-validator';

export class CreateCommentDto {
  @IsString({ message: 'Conteúdo deve ser uma string' })
  @IsNotEmpty({ message: 'Conteúdo é obrigatório' })
  content: string;

  @IsUUID('4', { message: 'topicId deve ser um UUID válido' })
  @IsNotEmpty({ message: 'topicId é obrigatório' })
  topicId: string;
}