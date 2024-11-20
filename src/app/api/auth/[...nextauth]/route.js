import NextAuth from 'next-auth';
import GoogleProvider from 'next-auth/providers/google';
import CredentialsProvider from 'next-auth/providers/credentials';
import bcrypt from 'bcryptjs';
import dbConnect from '../../../../lib/mongodb';
import User from '../../../../model/user';
import { MongoDBAdapter } from '@next-auth/mongodb-adapter';
import clientPromise from '../../../../lib/mongodbadapter';

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
            id: user._id.toString(),
            name: user.name,
            email: user.email,
          };
        } catch (error) {
          throw new Error(error.message);
        }
      }
    })
  ],
  // Remove the MongoDB adapter temporarily to debug the issue
  // adapter: MongoDBAdapter(clientPromise),
  session: {
    strategy: 'jwt',
    maxAge: 30 * 24 * 60 * 60, // 30 days
  },
  callbacks: {
    async signIn({ user, account, profile }) {
      if (account.provider === 'google') {
        try {
          await dbConnect();
          
          // Check if this is the first user ever
          const userCount = await User.countDocuments();
          const isFirstUser = userCount === 0;
          
          const existingUser = await User.findOne({ email: user.email });
          
          if (existingUser) {
            return true;
          }
          
          // Create new user, set as admin if first user
          const newUser = await User.create({
            name: user.name,
            email: user.email,
            role: isFirstUser ? 'admin' : 'user'
          });
          
          return true;
        } catch (error) {
          console.error("Error in signIn callback:", error);
          return false;
        }
      }
      return true;
    },
    
    async jwt({ token, user, account }) {
      if (user) {
        token.id = user.id;
        // Add user role to token
        const dbUser = await User.findOne({ email: user.email });
        if (dbUser) {
          token.role = dbUser.role;
        }
      }
      return token;
    },

    async redirect({ url, baseUrl }) {
      // // Get user from database
      // const user = await User.findOne({ email: session.user.email });
      
      // // Redirect based on user role
      // if (user.role === 'admin') return '/admin-dashboard'
      return '/'
    },
    async session({ session, token }) {
      if (token) {
        session.user.id = token.id;
        session.user.role = token.role; // Add role to session
      }
      return session;
    }
  },
  pages: {
    signIn: '/signin',
    error: '/auth/error',
  },
  secret: process.env.NEXTAUTH_SECRET,
  debug: true, // Enable debug messages
};

const handler = NextAuth(authOptions);
export { handler as GET, handler as POST };