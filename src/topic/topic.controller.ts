import { Controller, Get, Post, Body, Patch, Param, Delete, Request, UseGuards, Query } from '@nestjs/common';
import { TopicService } from './topic.service';
import { CreateTopicDto } from './dto/create-topic.dto';
import { UpdateTopicDto } from './dto/update-topic.dto';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';

@UseGuards(JwtAuthGuard)
@Controller('topic')
export class TopicController {
  constructor(private readonly topicService: TopicService) {}

  @Post('create')
  create(
    @Body() createTopicDto: CreateTopicDto,
    @Request() req,
  ) {
    return this.topicService.create(createTopicDto, req.user.id);
  }

  @Get()
  findAll() {
    return this.topicService.findAll();
  }

  @Get('search')
  search(@Query('q') query?: string) {
    return this.topicService.searchTopic(query);
  }

  @Get('topicsByUser')
  findByUser(@Request() req) {
    return this.topicService.findByUserId(req.user.id);
  }

  @Get(':topicId')
  findOne(@Param('topicId') topicId: string) {
    return this.topicService.findOne(topicId);
  }


  @Patch(':topicId')
  update(@Param('topicId') topicId: string, @Body() updateTopicDto: UpdateTopicDto, @Request() req) {
    return this.topicService.update(topicId, updateTopicDto, req.user.id);
  }

  @Delete(':topicId')
  remove(@Param('topicId') topicId: string, @Request() req) {
    return this.topicService.remove(topicId, req.user.id);
  }
}
