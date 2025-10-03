import { Controller, Get, Param } from '@nestjs/common';

@Controller('property')
export class PropertyController {
    @Get()
    findAll() {
        return "All properties";
    }

    @Get(':id')
    findById(@Param('id') id: number) {
        return `Property with ID: ${id}`;
    }
}
