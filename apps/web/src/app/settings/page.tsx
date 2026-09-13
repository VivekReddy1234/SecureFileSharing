'use client';

import AuthGuard from '@/components/AuthGuard';
import { useAuth } from '@/lib/auth-context';

export default function SettingsPage() {
  const { user } = useAuth();

  return (
    <AuthGuard>
      <div className="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">
        <h2 className="text-2xl font-semibold text-gray-900 mb-6">Settings</h2>
        <div className="bg-white shadow sm:rounded-lg mb-6 p-6">
          <h3 className="text-lg leading-6 font-medium text-gray-900">Profile Information</h3>
          <div className="mt-3 text-sm text-gray-500">
            <p><strong>Email:</strong> {user?.email}</p>
            <p><strong>Role:</strong> {user?.role}</p>
          </div>
        </div>
        <div className="bg-white shadow sm:rounded-lg p-6">
          <h3 className="text-lg leading-6 font-medium text-gray-900 mb-4">Change Password</h3>
          <form className="space-y-4 max-w-md">
            <div>
              <label className="block text-sm font-medium text-gray-700">Current Password</label>
              <input type="password" required className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm" />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700">New Password</label>
              <input type="password" required className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm" />
            </div>
            <button type="button" className="bg-indigo-600 text-white px-4 py-2 rounded-md hover:bg-indigo-700">Update Password</button>
          </form>
        </div>
      </div>
    </AuthGuard>
  );
}
