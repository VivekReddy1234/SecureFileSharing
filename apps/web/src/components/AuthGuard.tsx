'use client';

import { useAuth } from '../lib/auth-context';
import { useRouter } from 'next/navigation';
import { useEffect } from 'react';

export default function AuthGuard({ children, requireAdmin = false }: { children: React.ReactNode, requireAdmin?: boolean }) {
  const { isAuthenticated, isLoading, user } = useAuth();
  const router = useRouter();

  useEffect(() => {
    if (!isLoading) {
      if (!isAuthenticated) {
        router.push('/login');
      } else if (requireAdmin && user?.role !== 'ADMIN') {
        router.push('/dashboard');
      }
    }
  }, [isLoading, isAuthenticated, user, router, requireAdmin]);

  if (isLoading || !isAuthenticated || (requireAdmin && user?.role !== 'ADMIN')) {
    return (
      <div className="flex h-screen w-full items-center justify-center">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-indigo-600"></div>
      </div>
    );
  }

  return <>{children}</>;
}
