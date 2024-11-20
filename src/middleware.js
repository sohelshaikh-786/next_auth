import { withAuth } from "next-auth/middleware";
import { NextResponse } from "next/server";

export default withAuth(
  function middleware(req) {
    // Get user's role from token
    const token = req.nextauth.token;
    
    // Protect admin routes
    if (req.nextUrl.pathname.startsWith("/admin") && token?.role !== "admin") {
      return NextResponse.redirect(new URL("/unauthorized", req.url));
    }
  },
  {
    callbacks: {
      authorized: ({ token }) => !!token // Require authentication
    }
  }
);

export const config = {
  matcher: ["/admin/:path*"]
};