import { Topic } from "src/topic/entities/topic.entity";
import { User } from "src/user/entities/user.entity";
import { Column, CreateDateColumn, Entity, JoinColumn, ManyToOne, PrimaryGeneratedColumn, UpdateDateColumn } from "typeorm";

@Entity({ name: 'comments' })
export class Comment {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column()
  content: string;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;

  @ManyToOne(() => Topic, topic => topic.comments, { onDelete: 'CASCADE' })
  @JoinColumn( { name: 'topicId' } )
  topic: Topic;

  @Column()
  topicId: string;

  @ManyToOne(() => User, user => user.comments, { eager: true, onDelete: 'CASCADE' })
  @JoinColumn( { name: 'userId' } )
  user: User;

  @Column()
  userId: string;
}
