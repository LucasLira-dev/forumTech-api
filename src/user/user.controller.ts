import { Controller, Get, Post, Body, Patch, Param, Delete, UseGuards, Request, Query } from '@nestjs/common';
import { UserService } from './user.service';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { AdminGuard } from 'src/auth/guards/admin.guard';
import { UpdateUserRoleDto } from './dto/update-user-role.dto';
import { BanUserDto } from './dto/ban-user.dto';

@Controller('user')
export class UserController {
  constructor(private readonly userService: UserService) {}

  @Post('register')
  create(@Body() createUserDto: CreateUserDto) {
    return this.userService.create(createUserDto);
  }

  @UseGuards(JwtAuthGuard, AdminGuard)
  @Get('profiles')
  findAll() {
    return this.userService.findAll();
  }

  @Get('admin/search')
  @UseGuards(JwtAuthGuard, AdminGuard)
  search(@Query('query') query: string) {
    return this.userService.searchAllUsers(query);
  }

  @Get('admins')
  @UseGuards(JwtAuthGuard, AdminGuard)
  findAdmins() {
    return this.userService.findAdmins();
  }

  @Patch('admin/:userId/role')
  @UseGuards(JwtAuthGuard, AdminGuard)
  updateUserRole(@Param('userId') userId: string, @Body() updateUserDto: UpdateUserRoleDto, @Request() req) {
    return this.userService.updateUserRole(userId, updateUserDto.role, req.user.id);
  }

  @Patch('admin/:userId/ban')
  @UseGuards(JwtAuthGuard, AdminGuard)
  banUser(@Param('userId') userId: string, @Body() banDto: BanUserDto, @Request() req) {
    return this.userService.banUser(userId, banDto.reason, req.user.id);
  }

  @Patch('admin/:userId/unban')
  @UseGuards(JwtAuthGuard, AdminGuard)
  unbanUser(@Param('userId') userId: string) {
    return this.userService.unbanUser(userId);
  }

  @Get('admin/bannedUsers')
  @UseGuards(JwtAuthGuard, AdminGuard)
  findBannedUsers() {
    return this.userService.findBannedUsers();
  }

  @Get(':id')
  @UseGuards(JwtAuthGuard)
  findOne(@Param('id') id: string) {
    return this.userService.findOne(id);
  }

  @Patch('updateEmail')
  @UseGuards(JwtAuthGuard)
  update(@Body() updateEmail: { email: string, password: string }, @Request() req) {
    return this.userService.updateEmail(updateEmail.email, updateEmail.password, req.user.id);
  }

  @Patch('updatePassword')
  @UseGuards(JwtAuthGuard)
  updatePassword(@Body() UpdatePasswordDto: { oldPassword: string; newPassword: string }, @Request() req) {
    return this.userService.updatePassword(req.user.id, UpdatePasswordDto.oldPassword, UpdatePasswordDto.newPassword);
  }

  @Delete(':id')
  @UseGuards(JwtAuthGuard)
  remove(@Param('id') id: string) {
    return this.userService.remove(id);
  }
}
