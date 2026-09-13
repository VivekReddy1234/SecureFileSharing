'use client';

import AuthGuard from '@/components/AuthGuard';
import { api } from '@/lib/api';
import { AdminUserListItem } from '@ciphervault/shared';
import { useEffect, useState } from 'react';

export default function AdminPage() {
  const [users, setUsers] = useState<AdminUserListItem[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchUsers = async () => {
    try {
      setLoading(true);
      const res = await api.adminGetUsers();
      setUsers(res.items || []);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchUsers();
  }, []);

  const toggleUserStatus = async (user: AdminUserListItem) => {
    try {
      await api.adminUpdateUser(user.id, { isDisabled: !user.isDisabled });
      fetchUsers();
    } catch (e) {
      alert('Failed to update user status');
    }
  };

  return (
    <AuthGuard requireAdmin>
      <div className="max-w-7xl mx-auto py-8 px-4 sm:px-6 lg:px-8">
        <div className="flex justify-between items-center mb-6">
          <div>
            <h2 className="text-2xl font-bold text-gray-900">Admin Console</h2>
            <p className="text-sm text-gray-500">Manage registered users and system security</p>
          </div>
          <a href="/dashboard" className="text-sm text-indigo-600 hover:text-indigo-800 font-medium">
            &larr; Back to Dashboard
          </a>
        </div>

        <div className="bg-white shadow-sm rounded-xl border border-gray-200 overflow-hidden">
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider">Email</th>
                <th className="px-6 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider">Role</th>
                <th className="px-6 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider">Status</th>
                <th className="px-6 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider">Joined</th>
                <th className="px-6 py-3 text-right text-xs font-semibold text-gray-500 uppercase tracking-wider">Actions</th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-200">
              {loading ? (
                <tr>
                  <td colSpan={5} className="px-6 py-8 text-center text-gray-500 text-sm">
                    Loading users...
                  </td>
                </tr>
              ) : users.length === 0 ? (
                <tr>
                  <td colSpan={5} className="px-6 py-8 text-center text-gray-500 text-sm">
                    No users found
                  </td>
                </tr>
              ) : (
                users.map((user) => (
                  <tr key={user.id} className="hover:bg-gray-50 transition">
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">{user.email}</td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      <span className={`px-2 py-0.5 text-xs font-semibold rounded-full ${user.role === 'ADMIN' ? 'bg-purple-100 text-purple-800' : 'bg-gray-100 text-gray-800'}`}>
                        {user.role}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm">
                      <span className={`px-2 py-0.5 text-xs font-semibold rounded-full ${user.isDisabled ? 'bg-red-100 text-red-800' : 'bg-green-100 text-green-800'}`}>
                        {user.isDisabled ? 'Disabled' : 'Active'}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{new Date(user.createdAt).toLocaleDateString()}</td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-right">
                      <button
                        onClick={() => toggleUserStatus(user)}
                        className={`text-sm font-medium ${user.isDisabled ? 'text-green-600 hover:text-green-800' : 'text-red-600 hover:text-red-800'}`}
                      >
                        {user.isDisabled ? 'Enable' : 'Disable'}
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </AuthGuard>
  );
}
