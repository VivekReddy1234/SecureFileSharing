'use client';

import AuthGuard from '@/components/AuthGuard';
import { api } from '@/lib/api';
import { AuditLogEntry } from '@ciphervault/shared';
import { useEffect, useState } from 'react';

export default function AuditPage() {
  const [logs, setLogs] = useState<AuditLogEntry[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchAudit = async () => {
      try {
        const res = await api.getAuditLog();
        setLogs(res.items || []);
      } catch (e) {
        console.error(e);
      } finally {
        setLoading(false);
      }
    };
    fetchAudit();
  }, []);

  return (
    <AuthGuard>
      <div className="max-w-7xl mx-auto py-8 px-4 sm:px-6 lg:px-8">
        <div className="flex justify-between items-center mb-6">
          <div>
            <h2 className="text-2xl font-bold text-gray-900">Security Audit Trail</h2>
            <p className="text-sm text-gray-500">Immutable audit log of all events for your account</p>
          </div>
          <a href="/dashboard" className="text-sm text-indigo-600 hover:text-indigo-800 font-medium">
            &larr; Back to Dashboard
          </a>
        </div>

        {loading ? (
          <div className="text-center py-12 bg-white rounded-xl shadow-sm border border-gray-100">
            <div className="inline-block animate-spin rounded-full h-8 w-8 border-4 border-indigo-600 border-t-transparent mb-2" />
            <p className="text-sm text-gray-500">Loading audit events...</p>
          </div>
        ) : logs.length === 0 ? (
          <div className="text-center py-12 bg-white rounded-xl shadow-sm border border-gray-100">
            <p className="text-sm text-gray-500">No audit events recorded yet.</p>
          </div>
        ) : (
          <div className="bg-white shadow-sm rounded-xl border border-gray-200 overflow-hidden">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider">Event</th>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider">Status</th>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider">Resource</th>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider">IP Address</th>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider">Timestamp</th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {logs.map((log) => (
                  <tr key={log.id} className="hover:bg-gray-50 transition">
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">{log.eventType}</td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm">
                      <span className={`px-2 py-0.5 text-xs font-semibold rounded-full ${log.success ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'}`}>
                        {log.success ? 'Success' : 'Failed'}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 font-mono text-xs">{log.resourceId || '-'}</td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{log.ipAddress || '-'}</td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{new Date(log.createdAt).toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </AuthGuard>
  );
}
