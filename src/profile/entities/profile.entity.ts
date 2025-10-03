import { User } from "src/user/entities/user.entity";
import { Column, CreateDateColumn, Entity, JoinColumn, OneToOne, PrimaryGeneratedColumn, UpdateDateColumn } from "typeorm";
@Entity('profiles')
export class Profile {
    @PrimaryGeneratedColumn('uuid')
    id: string;

    @Column( { unique: true})
    userName: string;

    @Column({ nullable: true, length: 200 })
    bio: string;

    @Column({ nullable: true })
    avatarUrl: string;

    @Column({ nullable: true })
    capaUrl: string;

    @Column( { default: false })
    isPublic: boolean;

    @OneToOne(() => User, user => user.profile)
    @JoinColumn( {name: 'userId'})
    user: User;

    @Column()
    userId: string;

    @CreateDateColumn()
    createdAt: Date;

    @UpdateDateColumn()
    updatedAt: Date;
}
