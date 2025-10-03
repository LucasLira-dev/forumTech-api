import { User } from "src/user/entities/user.entity";
import { Column, Entity, JoinColumn, ManyToOne, PrimaryGeneratedColumn } from "typeorm";

@Entity('refresh_token')
export class RefreshToken {
    @PrimaryGeneratedColumn('uuid')
    id: string;

    @Column()
    token: string;

    @Column()
    expiresAt: Date;

    @ManyToOne(() => User, user => user.refreshTokens)
    @JoinColumn({ name: 'userId' })
    user: User;
}