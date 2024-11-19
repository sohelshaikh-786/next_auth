import { useState } from 'react';

export const useSignup = () => {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(false);

  const signup = async ({ name, email, password }) => {
    setLoading(true);
    setError(null);
    setSuccess(false);

    try {
      const response = await fetch('/api/auth/signup', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ name, email, password }),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || 'Failed to sign up');
      }

      const data = await response.json();
      setSuccess(true);
      return data; // Return the response to handle in the component if needed
    } catch (err) {
      setError(err.message);
      console.error('Signup Error:', err.message);
      return null;
    } finally {
      setLoading(false);
    }
  };

  return { signup, loading, error, success };
};
