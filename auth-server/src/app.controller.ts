import { Body, Controller, Post } from '@nestjs/common';
import { AppService } from './app.service';

@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Post('/webauthn/register/generate-options')
  generateOptions(@Body() user: any): PublicKeyCredentialCreationOptions {
    return this.appService.generateOptions(user);
  }

  @Post('/webauthn/register/verify')
  verify(@Body() request) {
    return this.appService.verify(request);
  }

  @Post('/webauthn/authenticate')
  authenticate(@Body() user): PublicKeyCredentialRequestOptions {
    return this.appService.authenticate(user);
  }

  @Post('/webauthn/authenticate/verify')
  verifyAuthentication(@Body() request) {
    return this.appService.verifyAuthentication(request);
  }
}
