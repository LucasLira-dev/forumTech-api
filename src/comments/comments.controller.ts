import { Controller, Get, Post, Body, Patch, Param, Delete, UseGuards, Request } from '@nestjs/common';
import { CommentsService } from './comments.service';
import { CreateCommentDto } from './dto/create-comment.dto';
import { UpdateCommentDto } from './dto/update-comment.dto';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';

@UseGuards(JwtAuthGuard)
@Controller('comments')
export class CommentsController {
  constructor(private readonly commentsService: CommentsService) {}

  @Post()
  create(@Body() createCommentDto: CreateCommentDto, @Request() req) {
    const userId = req.user.id;
    return this.commentsService.create(createCommentDto, userId);
  }

  @Get('my-comments')
  findAll(@Request() req) {
    const userId = req.user.id;
    return this.commentsService.findAllCommentsByUser(userId);
  }

  @Get('by-topic/:topicId')
  findByTopic(@Param('topicId') topicId: string) {
    return this.commentsService.findByTopicId(topicId);
  }

  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.commentsService.findOne(id);
  }

  @Patch('updateComment/:id')
  update(@Param('id') id: string, @Body() updateCommentDto: UpdateCommentDto, @Request() req) {
    const userId = req.user.id;
    return this.commentsService.update(id, updateCommentDto, userId);
  }

  @Delete('deleteComment/:id')
  remove(@Param('id') id: string, @Request() req) {
    const userId = req.user.id;
    return this.commentsService.remove(id, userId);
  }
}
