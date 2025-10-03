import { Comment } from "src/comments/entities/comment.entity";
import { User } from "src/user/entities/user.entity";
import { Column, CreateDateColumn, Entity, JoinColumn, ManyToOne, OneToMany, PrimaryGeneratedColumn, UpdateDateColumn } from "typeorm";

@Entity('topics')
export class Topic {
    @PrimaryGeneratedColumn('uuid')
    topicId: string;

    @Column({ nullable: false, length: 100 })
    title: string;

    @Column({ nullable: false, type: 'text' })
    description: string;

    @Column('simple-array', { nullable: false })
    technologies: string[];

    @CreateDateColumn()
    createdAt: Date;

    @UpdateDateColumn()
    updatedAt: Date;

    @ManyToOne(() => User, user => user.topics, { onDelete: 'CASCADE' })
    @JoinColumn({ name: 'userId' }) // especifica o nome da coluna de junção
    user: User;

    @Column()
    userId: string; // chave estrangeira para User

    @OneToMany(() => Comment, comment => comment.topic, { cascade: true })
    comments: Comment[];
}
