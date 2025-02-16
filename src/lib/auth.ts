import { hash, verify } from '@node-rs/argon2';

export type JWTPayload = {
  id: number;
  username: string;
};

export type Variables = {
  jwtPayload: JWTPayload;
};

const hashPassword = async (password: string) => {
  return await hash(password, {
    memoryCost: 19456,
    parallelism: 1,
  });
};

const verifyPassword = async (hashedPassword: string, plainTextPassword: string) => {
  return await verify(hashedPassword, plainTextPassword);
};

export { verifyPassword, hashPassword };
