'use client'

import { useRouter } from 'next/navigation'
import Button from './Button'

const SignInOrSignUpButton = ({ show }) => {
  const router = useRouter()

  return show === 'signin' ? (
    <Button className='w-full' onClick={() => router.push(`/signin`)}>
      Sign In
    </Button>
  ) : (
    <Button className='w-full' onClick={() => router.push(`/signup`)}>
      Sign Up
    </Button>
  )
}

export default SignInOrSignUpButton
