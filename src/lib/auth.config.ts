import Google from "next-auth/providers/google";

import type { NextAuthConfig } from "next-auth";
import { prisma } from "./prisma";
import { signInSchema } from "./signInSchema";
import bcrypt from "bcryptjs";
import Credentials from "next-auth/providers/credentials";

export default {
  providers: [
    Google({
      clientId: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    }),
    Credentials({
      async authorize(credentials) {
        const parsedCredentials = signInSchema.safeParse(credentials);

        if (!parsedCredentials.success) return null;

        const { email, password } = parsedCredentials.data;
        const dbUser = await prisma.user.findUnique({
          where: { email },
        });

        if (!dbUser?.hashedPassword) return null;

        const passwordsMatch = await bcrypt.compare(
          password,
          dbUser.hashedPassword
        );
        if (!passwordsMatch) return null;

        return {
          id: dbUser.id,
          name: dbUser.name,
          email: dbUser.email,
          image: dbUser?.image,
        };
      },
    }),
  ],
} satisfies NextAuthConfig;
