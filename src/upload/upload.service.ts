import { Injectable, InternalServerErrorException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { createClient, SupabaseClient } from '@supabase/supabase-js';
import { randomUUID } from 'crypto';

@Injectable()
export class UploadService {
  private readonly supabase: SupabaseClient;
  private readonly bucketName: string;

  constructor(private configService: ConfigService) {
    const supabaseUrl = this.configService.get<string>('SUPABASE_URL');
    const supabaseServiceKey = this.configService.get<string>('SUPABASE_SERVICE_ROLE_KEY');
    this.bucketName = this.configService.get<string>('SUPABASE_BUCKET_NAME') ?? 'profiles';

    if (!supabaseUrl || !supabaseServiceKey) {
      throw new InternalServerErrorException('Configurações do Supabase não foram definidas');
    }

    this.supabase = createClient(supabaseUrl, supabaseServiceKey, {
      auth: {
        persistSession: false,
        autoRefreshToken: false,
      },
    });
  }

  async uploadImage(file: Express.Multer.File, userId: string): Promise<string> {
  const uniqueId = `${Date.now()}-${randomUUID()}`;
  const extension = this.getFileExtension(file.originalname);
  const filePath = `${userId}/${uniqueId}${extension ? `.${extension}` : ''}`;

    const { error } = await this.supabase.storage
      .from(this.bucketName)
      .upload(filePath, file.buffer, {
        cacheControl: '3600',
        contentType: file.mimetype,
        upsert: false,
      });

    if (error) {
      throw new InternalServerErrorException(`Falha ao enviar arquivo: ${error.message}`);
    }

    const {
      data: { publicUrl }
    } = this.supabase.storage.from(this.bucketName).getPublicUrl(filePath);

    return publicUrl;
  }

  async deleteImage(fileId: string): Promise<void> {
    const storagePath = this.extractStoragePath(fileId);

    if (!storagePath) {
      return;
    }

    await this.supabase.storage.from(this.bucketName).remove([storagePath]);
  }

  extractStoragePath(fileUrl: string): string {
    if (!fileUrl) {
      return '';
    }

    if (!fileUrl.startsWith('http')) {
      return fileUrl;
    }

    try {
      const parsedUrl = new URL(fileUrl);
      const publicPrefix = `/storage/v1/object/public/${this.bucketName}/`;
      const signedPrefix = `/storage/v1/object/sign/${this.bucketName}/`;

      if (parsedUrl.pathname.includes(publicPrefix)) {
        return decodeURIComponent(parsedUrl.pathname.split(publicPrefix)[1] ?? '');
      }

      if (parsedUrl.pathname.includes(signedPrefix)) {
        const [path] = parsedUrl.pathname.split(signedPrefix)[1]?.split('?') ?? [''];
        return decodeURIComponent(path ?? '');
      }
    } catch (error) {
      return '';
    }

    return '';
  }

  private getFileExtension(filename: string): string {
    const parts = filename?.split('.') ?? [];
    return parts.length > 1 ? parts.pop()?.toLowerCase() ?? '' : '';
  }
}