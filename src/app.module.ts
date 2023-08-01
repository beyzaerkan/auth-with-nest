import { Module } from '@nestjs/common';
import { AppService } from './app.service';
import { AuthModule } from './auth/auth.module';
import { ConfigModule } from '@nestjs/config';
import { MongooseModule } from '@nestjs/mongoose';

@Module({
  imports: [AuthModule,
  ConfigModule.forRoot({
    isGlobal: true
  }),
  MongooseModule.forRoot("mongodb://localhost/auth-with-nest")
  ],
  controllers: [],
  providers: [AppService],
})
export class AppModule {}
