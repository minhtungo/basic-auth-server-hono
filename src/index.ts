import { serve } from '@hono/node-server';
import { zValidator } from '@hono/zod-validator';
import { hash as hashPassword, verify as verifyPassword } from '@node-rs/argon2';
import { Hono } from 'hono';
import { deleteCookie, getCookie, setCookie } from 'hono/cookie';
import { cors } from 'hono/cors';
import { jwt, verify } from 'hono/jwt';
import { JwtTokenExpired, JwtTokenInvalid } from 'hono/utils/jwt/types';
import { z } from 'zod';
import { appConfig } from './config/app.js';
import { env } from './config/env.js';
import { generateAccessToken, generateRefreshToken } from './lib/token.js';
import type { JWTPayload, Variables } from './lib/auth.js';

const app = new Hono<{ Variables: Variables }>();

const db = {
  users: [{ id: 1, username: 'admin', password: await hashPassword('admin'), name: 'John Doe' }],
};

app.use(
  '*',
  cors({
    origin: env.APP_ORIGIN,
    credentials: true,
  })
);

app.get('/', (c) => {
  return c.text('Hello!');
});

app.post(
  '/log-in',
  zValidator(
    'json',
    z.object({
      username: z.string(),
      password: z.string(),
    }),
    async (result, c) => {
      if (!result.success) return c.json(result.error, 400);

      const { username, password } = result.data;

      const user = db.users.find((user) => user.username === username);
      if (!user) return c.json({ message: 'username or password is incorrect' }, 401);

      const isPasswordMatch = await verifyPassword(user.password, password);

      if (!isPasswordMatch) return c.json({ message: 'username or password is incorrect' }, 401);

      const payload: JWTPayload = { id: user.id, username };

      const accessToken = await generateAccessToken(payload, appConfig.cookie.accessToken.expires);
      const refreshToken = await generateRefreshToken(payload, appConfig.cookie.refreshToken.expires);

      setCookie(c, appConfig.cookie.refreshToken.name, refreshToken, {
        secure: true,
        httpOnly: true,
        sameSite: 'strict',
        maxAge: appConfig.cookie.refreshToken.expires,
      });

      return c.json({ accessToken, user: { name: user.name } });
    }
  )
);

app.post('/log-out', (c) => {
  deleteCookie(c, env.REFRESH_TOKEN_COOKIE);

  return c.json({ message: 'success' });
});

app.get('/refresh', async (c) => {
  const refreshToken = getCookie(c, env.REFRESH_TOKEN_COOKIE);
  if (!refreshToken) return c.json({ message: 'refresh token not found' }, 401);

  try {
    const decoded = (await verify(refreshToken, env.REFRESH_TOKEN_SECRET)) as JWTPayload;
    const payload: JWTPayload = { id: decoded.id, username: decoded.username };
    const accessToken = await generateAccessToken(payload, appConfig.cookie.accessToken.expires);

    return c.json({ accessToken });
  } catch (error) {
    switch (true) {
      case error instanceof JwtTokenExpired:
        return c.json({ message: 'refresh token expired' }, 401);

      case error instanceof JwtTokenInvalid:
        return c.json({ message: 'refresh token invalid' }, 401);

      default:
        return c.json({ message: 'unexpected error', error }, 401);
    }
  }
});

app.use(
  '/auth/*',
  jwt({
    secret: env.ACCESS_TOKEN_SECRET,
  })
);

app.get('/auth', (c) => {
  const payload = c.get('jwtPayload');

  const user = db.users.find((user) => user.id === payload.id);
  if (!user) return c.json({ message: 'user not found' }, 404);

  return c.json({
    user: {
      name: user.name,
    },
  });
});

serve({
  fetch: app.fetch,
  port: appConfig.port,
});

console.log(`Server is running at http://localhost:${appConfig.port}`);
