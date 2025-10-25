import { User } from "src/user/entities/user.entity";
import { Column, CreateDateColumn, Entity, JoinColumn, OneToOne, PrimaryGeneratedColumn, UpdateDateColumn } from "typeorm";
@Entity('profiles')
export class Profile {
    @PrimaryGeneratedColumn('uuid')
    id: string;

    @Column( { unique: true})
    userName: string;

    @Column({ type: 'text', nullable: true })
    bio: string | null;

    @Column({ type: 'text', nullable: true })
    avatarUrl: string | null;

    @Column({ type: 'text', nullable: true })
    capaUrl: string | null;

    @Column( { default: false })
    isPublic: boolean;

    @OneToOne(() => User, user => user.profile, { onDelete: 'CASCADE' })
    @JoinColumn( {name: 'userId'})
    user: User;

    @Column()
    userId: string;

    @CreateDateColumn()
    createdAt: Date;

    @UpdateDateColumn()
    updatedAt: Date;
}
