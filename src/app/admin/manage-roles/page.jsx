'use client';
import { useState, useEffect } from 'react';
import { useSession } from 'next-auth/react';

export default function ManageRoles() {
  const { data: session } = useSession();
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    fetchUsers();
  }, []);

  const fetchUsers = async () => {
    try {
      const response = await fetch('/api/admin/roles');
      const data = await response.json();
      
      if (!response.ok) throw new Error(data.error);
      
      setUsers(data.users);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const updateRole = async (userId, newRole) => {
    try {
      const response = await fetch('/api/admin/roles', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId, newRole })
      });

      const data = await response.json();
      
      if (!response.ok) throw new Error(data.error);
      
      // Refresh users list
      fetchUsers();
    } catch (err) {
      setError(err.message);
    }
  };

  if (loading) return <div>Loading...</div>;
  if (error) return <div>Error: {error}</div>;

  return (
    <div className="p-4">
      <h1 className="text-2xl font-bold mb-4">Manage User Roles</h1>
      <div className="space-y-4">
        {users.map((user) => (
          <div key={user._id} className="border p-4 rounded">
            <p>Name: {user.name}</p>
            <p>Email: {user.email}</p>
            <p>Current Role: {user.role}</p>
            <select
              value={user.role}
              onChange={(e) => updateRole(user._id, e.target.value)}
              className="mt-2 border rounded p-1"
              disabled={user._id === session?.user?.id}
            >
              <option value="user">User</option>
              <option value="moderator">Moderator</option>
              <option value="admin">Admin</option>
            </select>
          </div>
        ))}
      </div>
    </div>
  );
}