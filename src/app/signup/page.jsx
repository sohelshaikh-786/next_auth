"use client"
import Button from '../components/Button';
import GoogleSignInButton from '../components/GoogleSignInButton';
import TextField from '../components/TextField';
import SignInOrSignUpButton from '../components/SignInOrSignUp';
import { useState } from 'react';
import { useSignup } from '../../hooks/useSignup';

const SignUpPage = () => {
  const { signup, loading, error, success } = useSignup();
  const [formData, setFormData] = useState({ name: '', email: '', password: '' });

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData({ ...formData, [name]: value });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    const result = await signup(formData);

    if (result) {
      alert('Signup successful!');
      setFormData({ name: '', email: '', password: '' });
    }
  };

  return (
    <section className='flex min-h-full overflow-hidden pt-16 sm:py-28'>
      <div className='mx-auto flex w-full max-w-2xl flex-col px-4 sm:px-6'>
        <div className='relative mt-12 sm:mt-16'>
          <h1 className='text-center text-2xl font-medium tracking-tight text-gray-900'>
            Sign up for your account
          </h1>
        </div>
        <div className='sm:rounded-5xl -mx-4 mt-10 flex-auto bg-white px-4 py-10 shadow-2xl shadow-gray-900/10 sm:mx-0 sm:flex-none sm:p-24'>
          <form onSubmit={handleSubmit}>
            <div className='space-y-2'>
              <TextField
                id='email'
                name='email'
                type='email'
                label='Sign up with your email'
                placeholder='hello@me.com'
                className={''}
                autoComplete='email'
                required
                value={formData.email}
                onChange={handleChange}
              />

              <TextField
                id='name'
                name='name'
                type='text'
                label='Enter your full name'
                placeholder='Nelson Mandela'
                className={''}
                required
                value={formData.name}
                onChange={handleChange}
              />

              <TextField
                id='password'
                name='password'
                type='password'
                label='Create a strong password'
                className={''}
                required
                value={formData.password}
                onChange={handleChange}
              />
            </div>
            <Button
              type='submit'
              variant='outline'
              color='gray'
              className='mt-3 w-full'
              disabled={loading}
            >
              {loading ? 'Signing Up...' : 'Create Account'}
            </Button>
          </form>
          {error && (
            <p className='mt-4 text-center text-red-500'>{error}</p>
          )}
          {success && (
            <p className='mt-4 text-center text-green-500'>
              Sign up successful! You can now sign in.
            </p>
          )}
          <div className='mx-auto my-10 flex w-full items-center justify-evenly before:mr-4 before:block before:h-px before:flex-grow before:bg-stone-400 after:ml-4 after:block after:h-px after:flex-grow after:bg-stone-400'>
            or
          </div>

          <div className='flex flex-col gap-4'>
            <SignInOrSignUpButton show={'signin'} />
            <GoogleSignInButton />
          </div>
        </div>
      </div>
    </section>
  );
};

export default SignUpPage;
