import { BadRequestException, Injectable, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { TokenSchema, UserSchema } from './schemas';
import mongoose from 'mongoose';
import { LoginDto, RegisterDto } from './dto';
import * as bcrypt from 'bcrypt';
import { IJwtPayload } from './interface';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
    constructor(
        @InjectModel("Token") private tokenModel: mongoose.Model<TokenSchema>,
        @InjectModel("User") private userModel: mongoose.Model<UserSchema>,
        private jwtService: JwtService
    ) { }

    async userInfo(userId: IJwtPayload) {
        const user = await this.userModel.findById(userId).select("name surname email")
        return user
    }

    async login(dto: LoginDto) {
        const { email, password } = dto;

        const user = await this.userModel.findOne({ email });

        if (!user) throw new UnauthorizedException("Invalid password or email");

        //sifre kontrolu
        const comparePasswords = await this.comparePasswords(password, user.password);

        if (!comparePasswords) {
            throw new UnauthorizedException("Invalid password or email");
        }

        // token olustur
        const userId = user._id;
        const token = await this.createToken({ userId });


        await this.tokenModel.findOneAndUpdate(
            {
                userId: new mongoose.Types.ObjectId(String(userId)),
            },
            {
                $set: {
                    token
                }
            },
            {
                upsert: true, // yoksa ekle
                new: true     // varsa guncelle
            }
        )

        return {
            token,
        }

    }

    async register(dto: RegisterDto) {
        const hash = await this.hashData(dto.password);

        const isUserExist = await this.userModel.findOne({ email: dto.email });

        if (isUserExist) throw new BadRequestException("This user is exist");

        const newUser = new this.userModel({
            ...dto,
            password: hash,
        });

        await newUser.save().catch((e) => {
            throw new BadRequestException("Register failed");
        })

        return {
            result: 'Register success...',
        }
    }

    // password hashleme fonksiyonu
    async hashData(data: string) {
        return await bcrypt.hash(data, 10); //password hash
    }

    async comparePasswords(password, hashedPass) {
        return await bcrypt.compare(password, hashedPass)
    }

    async createToken(payload: IJwtPayload) {
        const token = await this.jwtService.sign(payload);

        return token;
    }
}

