import { sign } from 'hono/jwt';
import type { JWTPayload } from 'hono/utils/jwt/types';
import { env } from './../config/env.js';

function createExpiresAt(time: number) {
  return Math.floor(Date.now() / 1000) + time;
}

export const generateAccessToken = (payload: JWTPayload, exp: number) => {
  return sign(
    {
      ...payload,
      exp: createExpiresAt(exp),
    },
    env.ACCESS_TOKEN_SECRET
  );
};

export const generateRefreshToken = (payload: JWTPayload, exp: number) => {
  return sign(
    {
      ...payload,
      exp: createExpiresAt(exp),
    },
    env.REFRESH_TOKEN_SECRET
  );
};
