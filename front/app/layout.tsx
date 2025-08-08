"use client";

import { AuthProvider } from '../contexts/AuthContext';
import Navbar from '../components/Navbar'; // Navbar 임포트
import 'bootstrap/dist/css/bootstrap.min.css';
import { useEffect } from 'react';

export default function RootLayout({ children }: { children: React.ReactNode }) {
  useEffect(() => {
    require('bootstrap/dist/js/bootstrap.bundle.min.js');
  }, []);

  return (
    <html lang="ko" suppressHydrationWarning>
      <body>
        <AuthProvider>
          <Navbar /> {/* Navbar 컴포넌트 추가 */}
          <main className="container">
            {children}
          </main>
        </AuthProvider>
      </body>
    </html>
  );
}

