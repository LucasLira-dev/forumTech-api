import { ArrayMaxSize, ArrayMinSize, IsArray, IsNotEmpty, IsString, MaxLength } from "class-validator";

export class CreateTopicDto {
    @IsString({ message: 'Titulo deve ser uma string' })
    @IsNotEmpty({ message: 'Titulo não pode ser vazio' })
    @MaxLength(100, { message: 'Titulo deve ter no máximo 100 caracteres' })
    title: string;

    @IsString({ message: 'Descrição deve ser uma string' })
    @IsNotEmpty({ message: 'Descrição não pode ser vazia' })
    description: string;


    @IsNotEmpty({ message: 'Pelo menos uma tecnologia é obrigatória' })
    @IsArray({ message: 'Technologies deve ser um array' })
    @ArrayMinSize(1, { message: 'Pelo menos uma tecnologia é obrigatória' })
    @ArrayMaxSize(5, { message: 'Máximo de 5 tecnologias por tópico' })
    @IsString({ each: true, message: 'Cada tecnologia deve ser uma string' })
    technologies: string[];
}
