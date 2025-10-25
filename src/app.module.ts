import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from './auth/auth.module';
import { UserModule } from './user/user.module';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { RefreshTokenModule } from './refresh-token/refresh-token.module';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from './user/entities/user.entity';
import { RefreshToken } from './refresh-token/refresh.entity';
import { TopicModule } from './topic/topic.module';
import { Topic } from './topic/entities/topic.entity';
import { CommentsModule } from './comments/comments.module';
import { Comment } from './comments/entities/comment.entity';
import { ProfileModule } from './profile/profile.module';
import { Profile } from './profile/entities/profile.entity';
import { UploadService } from './upload/upload.service';
import { UploadModule } from './upload/upload.module';
import { HealthController } from './health/health.controller';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
    }),
    TypeOrmModule.forRootAsync({
      imports: [ConfigModule],
      useFactory: (configService: ConfigService) => ({
        type: 'postgres',
        host: configService.get('DB_HOST'),
        port: +(configService.get<number>('DB_PORT') ?? 5432),
        username: configService.get('DB_USERNAME'),
        password: configService.get('DB_PASSWORD'),
        database: configService.get('DB_NAME'),
        entities: [User, RefreshToken, Topic, Comment, Profile], // Suas entities aqui
        synchronize: configService.get('NODE_ENV') === 'development', // Só em desenvolvimento
        logging: configService.get('NODE_ENV') === 'development',
      }),
      inject: [ConfigService],
    }),
    AuthModule,
    UserModule,
    RefreshTokenModule,
    TopicModule,
    CommentsModule,
    ProfileModule,
    UploadModule
  ],
  controllers: [AppController, HealthController],
  providers: [AppService, UploadService],
})
export class AppModule {}
