import { Controller, Get, Post, Body, Patch, Param, Delete, UseGuards, Request, Query } from '@nestjs/common';
import { ProfileService } from './profile.service';
import { CreateProfileDto } from './dto/create-profile.dto';
import { UpdateProfileDto } from './dto/update-profile.dto';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';

@UseGuards(JwtAuthGuard)
@Controller('profile')
export class ProfileController {
  constructor(private readonly profileService: ProfileService) {}

  @Post()
  create(@Body() createProfileDto: CreateProfileDto, @Request() req) {
    return this.profileService.create(createProfileDto, req.user.id);
  }

  @Get('public')
  findAllPublicProfiles(){
    return this.profileService.findAllPublicProfiles();
  }

  @Get('search')
  search(@Query('query') query: string) {
    return this.profileService.searchPublicProfiles(query);
  }

  @Patch('update-visibility')
  updateVisibility(@Body('isPublic') isPublic: boolean, @Request() req) {
    return this.profileService.updateProfileVisibility(isPublic, req.user.id);
  }

  @Get('my-profile')
  findMyProfile(@Request() req){
    return this.profileService.findMyProfile(req.user.id)
  }

  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.profileService.findOneProfile(id);
  }

  @Patch('update-profile')
  update(@Body() updateProfileDto: UpdateProfileDto, @Request() req) {
    return this.profileService.update(updateProfileDto, req.user.id);
  }

  @Delete('delete-profile')
  remove(@Request() req) {
    return this.profileService.remove(req.user.id);
  }
}
