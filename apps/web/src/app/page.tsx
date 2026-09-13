import Link from 'next/link';

export default function Home() {
  return (
    <div className="min-h-screen bg-gray-50 flex flex-col justify-center py-12 sm:px-6 lg:px-8">
      <div className="sm:mx-auto sm:w-full sm:max-w-md text-center">
        <h1 className="text-4xl font-extrabold text-gray-900 mb-4">CipherVault</h1>
        <p className="text-lg text-gray-600 mb-8">Secure, end-to-end encrypted file sharing.</p>
        
        <div className="space-y-4">
          <Link href="/register" className="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-700">
            Get Started
          </Link>
          <Link href="/login" className="w-full flex justify-center py-2 px-4 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 bg-white hover:bg-gray-50">
            Login
          </Link>
        </div>
      </div>
    </div>
  );
}
