import Link from 'next/link'
import SignInButton from './SignInButton'

const Header = () => {
  return (
    <header className='bg-stone-100 py-4'>
      <nav className='container h-full'>
        <ul className='flex items-center justify-between gap-8 font-medium tracking-wider text-stone-500'>
          <li className='text-sm'>
            <Link href='/'>Home</Link>
          </li>
          <li className='text-sm'>
            <Link href='/protected/server'>Protected (server)</Link>
          </li>
          <li className='text-sm'>
            <Link href='/protected/client'>Protected (client)</Link>
          </li>

          <li className='flex justify-between items-center gap-6'>
            <SignInButton />
          </li>
        </ul>
      </nav>
    </header>
  )
}

export default Header
