import { env } from './env.js';

export const appConfig = {
  cookie: {
    accessToken: {
      name: env.ACCESS_TOKEN_COOKIE!,
      secret: process.env.ACCESS_TOKEN_SECRET!,
      expires: 60 * 5,
    },
    refreshToken: {
      name: env.REFRESH_TOKEN_COOKIE!,
      secret: process.env.REFRESH_TOKEN_SECRET!,
      expires: 60 * 60 * 24 * 7,
    },
  },
  port: env.PORT,
};
