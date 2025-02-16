import dotenv from 'dotenv';
import { cleanEnv, port, str, url } from 'envalid';

dotenv.config();

export const env = cleanEnv(process.env, {
  DATABASE_URL: str(),
  ACCESS_TOKEN_COOKIE: str(),
  ACCESS_TOKEN_SECRET: str(),
  REFRESH_TOKEN_COOKIE: str(),
  REFRESH_TOKEN_SECRET: str(),
  PORT: port(),
  APP_ORIGIN: url(),
});
