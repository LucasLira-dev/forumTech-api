import { IsEmail, IsString, MinLength } from "class-validator";

export class CreateUserDto {
    @IsEmail({}, { message: 'Invalid email' })
    email: string;

    @IsString({ message: 'Password must be a string' })
    @MinLength(6, { message: 'Password must be at least 6 characters long' })
    password: string;

    @IsString({ message: 'Name must be a string' })
    name: string;
}
