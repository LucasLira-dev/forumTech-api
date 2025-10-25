import { Controller, Get, Post, Body, Patch, Param, Delete, UseGuards, Request, Query, UseInterceptors, UploadedFile, BadRequestException } from '@nestjs/common';
import { ProfileService } from './profile.service';
import { UpdateProfileDto } from './dto/update-profile.dto';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { FileInterceptor } from '@nestjs/platform-express';
import { UploadService } from 'src/upload/upload.service';

@Controller('profile')
export class ProfileController {
  constructor(
    private readonly profileService: ProfileService,
    private readonly uploadService: UploadService
  ) {}

  @Get('public')
  findAllPublicProfiles(){
    return this.profileService.findAllPublicProfiles();
  }

  @Get('search')
  search(@Query('query') query: string) {
    return this.profileService.searchPublicProfiles(query);
  }

  @Get('user/:userName')
  findProfileByUserName(@Param('userName') userName: string) {
    return this.profileService.findProfileByUserName(userName);
  }

  @UseGuards(JwtAuthGuard)
  @Patch('update-visibility')
  updateVisibility(@Body('isPublic') isPublic: boolean, @Request() req) {
    return this.profileService.updateProfileVisibility(isPublic, req.user.id);
  }

  @UseGuards(JwtAuthGuard)
  @Get('my-profile')
  findMyProfile(@Request() req){
    return this.profileService.findMyProfile(req.user.id)
  }

  @UseGuards(JwtAuthGuard)
  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.profileService.findOneProfile(id);
  }

  @UseGuards(JwtAuthGuard)
  @Patch('update-profile')
  upsertProfile(@Body() updateProfileDto: UpdateProfileDto, @Request() req) {
    return this.profileService.upsertProfile(updateProfileDto, req.user.id);
  }

  @UseGuards(JwtAuthGuard)
  @Post('upload-avatar')
  @UseInterceptors(FileInterceptor('file', {
    limits: { fileSize: 5 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
      if (!file.mimetype.match(/\/(jpg|jpeg|png|gif|webp)$/)) {
        return cb(new BadRequestException('Apenas imagens são permitidas'), false);
      }
      cb(null, true);
    }
  }))
  async uploadAvatar(
    @UploadedFile() file: Express.Multer.File,
    @Request() req
  ) {
    if (!file) {
      throw new BadRequestException('Arquivo não fornecido ou inválido');
    }

    //upload para Appwrite e retornar a URL
    const avatarUrl = await this.uploadService.uploadImage(file, req.user.id);

    //salvar a URL no banco de dados (Profile)
    await this.profileService.upsertProfile({ avatarUrl }, req.user.id);

    return {
      message: 'Avatar atualizado com sucesso',
      avatarUrl
    }
  }

  @UseGuards(JwtAuthGuard)
  @Post('upload-capa')
  @UseInterceptors(FileInterceptor('file', {
    limits: { fileSize: 5 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
      if (!file.mimetype.match(/\/(jpg|jpeg|png|gif|webp)$/)) {
        return cb(new BadRequestException('Apenas imagens são permitidas'), false);
      }
      cb(null, true);
    }
  }))
  async uploadCapa(
    @UploadedFile() file: Express.Multer.File,
    @Request() req
  ) {
    if (!file) {
      throw new BadRequestException('Arquivo não fornecido ou inválido');
    }

    //upload para Appwrite e retornar a URL
    const capaUrl = await this.uploadService.uploadImage(file, req.user.id);

    //salvar a URL no banco de dados (Profile)
    await this.profileService.upsertProfile({ capaUrl }, req.user.id);

    return {
      message: 'Capa atualizada com sucesso',
      capaUrl
    }
  }

  @UseGuards(JwtAuthGuard)
  @Delete('delete-profile')
  remove(@Request() req) {
    return this.profileService.remove(req.user.id);
  }
}
