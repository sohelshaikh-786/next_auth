import NextAuth from 'next-auth'
import GoogleProvider from 'next-auth/providers/google'
import CredentialsProvider from 'next-auth/providers/credentials'
import bcrypt from 'bcryptjs'
import dbConnect from '../../../../lib/mongodb'
import User from '../../../../model/user'
import { MongoDBAdapter } from '@next-auth/mongodb-adapter'
import clientPromise from '../../../../lib/mongodbadapter'

export const authOptions = {
  providers: [
    GoogleProvider({
      clientId: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      authorization: {
        params: {
          prompt: "consent",
          access_type: "offline",
          scope: "openid email profile"
        }
      }
    }),
    // Optional: Keep credentials provider if you want email/password login
    CredentialsProvider({
      name: 'Credentials',
      credentials: {
        email: { label: "Email", type: "email" },
        password: { label: "Password", type: "password" }
      },
      async authorize(credentials) {
        try {
          await dbConnect();
          const user = await User.findOne({ email: credentials.email });
          
          if (!user) {
            throw new Error('No user found');
          }

          const isPasswordValid = await bcrypt.compare(credentials.password, user.password);
          
          if (!isPasswordValid) {
            throw new Error('Invalid password');
          }

          return {
            id: user._id,
            name: user.name,
            email: user.email,
          };
        } catch (error) {
          throw new Error(error.message);
        }
      }
    })
  ],
  adapter: MongoDBAdapter(clientPromise),
  session: {
    strategy: 'jwt',
    maxAge: 30 * 24 * 60 * 60, // 30 days
  },
  callbacks: {
    async session({ session, token }) {
      // Add user ID to session
      session.user.id = token.sub;
      return session;
    },
    // Customize user creation for Google sign-in
    async signIn({ user, account }) {
      if (account.provider === 'google') {
        try {
          await dbConnect();
          
          // Check if user already exists
          let existingUser = await User.findOne({ email: user.email });
          
          // If user doesn't exist, create a new user
          if (!existingUser) {
            existingUser = await User.create({
              name: user.name,
              email: user.email,
              // You can add more fields as needed
            });
          }

          return true;
        } catch (error) {
          console.error('Google Sign-In Error:', error);
          return false;
        }
      }
      return true;
    }
  },
  pages: {
    signIn: '/signin',
    signUp: '/signup',
    error: '/auth/error', // Error code passed in query string as ?error=
  },
  secret: process.env.NEXTAUTH_SECRET
}

const handler = NextAuth(authOptions)

export { handler as GET, handler as POST }