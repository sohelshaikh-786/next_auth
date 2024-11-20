import bcrypt from 'bcryptjs'
import dbConnect from '../../../../lib/mongodb'
import User from '../../../../model/user'

export async function POST(request) {
  try {
    await dbConnect()

    // Parse the request body
    const { name, email, password } = await request.json()

    // Check if user exists
    const userExists = await User.findOne({ email })
    if (userExists) {
      return new Response(JSON.stringify({ message: 'User already exists' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      })
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10)

    // Check if this is the first user ever
    const userCount = await User.countDocuments()
    const isFirstUser = userCount === 0

    // Create user
    const user = await User.create({
      name,
      email,
      password: hashedPassword,
      role: isFirstUser ? 'admin' : 'user'
    })

    return new Response(
      JSON.stringify({
        message: 'User created successfully',
        user: {
          id: user._id,
          name: user.name,
          email: user.email
        }
      }),
      {
        status: 201,
        headers: { 'Content-Type': 'application/json' }
      }
    )
  } catch (error) {
    return new Response(JSON.stringify({ message: error.message }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    })
  }
}
