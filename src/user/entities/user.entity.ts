
import { Exclude } from 'class-transformer';
import { Comment } from 'src/comments/entities/comment.entity';
import { Profile } from 'src/profile/entities/profile.entity';
import { RefreshToken } from 'src/refresh-token/refresh.entity';
import { Topic } from 'src/topic/entities/topic.entity';
import { 
  Entity, 
  PrimaryGeneratedColumn, 
  Column, 
  CreateDateColumn, 
  UpdateDateColumn,
  OneToMany,
  OneToOne,
} from 'typeorm';

export enum UserRole {
  ADMIN = 'admin',
  USER = 'user',
}

@Entity('user')
export class User {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ unique: true })
  email: string;

  @Column({ select: false }) // ← Não retorna a senha por padrão
  @Exclude() // ← Exclui do response quando usar class-transformer
  password: string;

  @Column({ nullable: false })
  name: string;

  @Column({ default: true })
  isActive: boolean;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;

  @Column({
    type: 'enum',
    enum: UserRole,
    default: UserRole.USER,
  })
  role: UserRole;


  @Column({ default: false })
  isBanned: boolean;

  @Column( { nullable: true })
  bannedAt: Date | null;

  @Column( { nullable: true })
  banReason: string | null;

  @Column( { nullable: true })
  bannedByUserId: string | null;

  @OneToMany(() => RefreshToken, refreshToken => refreshToken.user)
  refreshTokens: RefreshToken[];

  @OneToMany(() => Topic, topic => topic.user)
  topics: Topic[];

  @OneToMany(() => Comment, comment => comment.user)
  comments: Comment[];

  @OneToOne(() => Profile, profile => profile.user)
  profile: Profile;
}