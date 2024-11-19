"use client"
import { useRouter } from 'next/navigation'

const SignUpButton = () => {
  const router = useRouter()

  return (
    <button
      className='rounded-md border border-stone-300 px-3 py-1 text-sm dark:border-stone-600'
      onClick={() => router.push('/signup')}
    >
      Sign Up
    </button>
  )
}

export default SignUpButton