"use client";

import { createContext, useState, useEffect, useContext, ReactNode } from 'react';
import axios from 'axios';

// ✨ [수정] User 인터페이스에 apiKeySet 추가
interface User {
  id: string;
  email: string;
  is_admin: boolean;
  apiKeySet: boolean; 
}

type AuthContextType = {
  user: User | null;
  isLoading: boolean;
  login: (userData: User) => void;
  logout: () => void;
  updateApiKeyStatus: (status: boolean) => void; // ✨ API 키 상태 업데이트 함수 추가
};

const AuthContext = createContext<AuthContextType | undefined>(undefined);

type AuthProviderProps = {
  children: ReactNode;
};

export function AuthProvider({ children }: AuthProviderProps) {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const checkUserSession = async () => {
      try {
        const response = await axios.get('/api/auth/session', {
          withCredentials: true,
        });
        if (response.data.isLoggedIn) {
          setUser(response.data.user);
        }
      } catch (error) {
        console.error("세션 확인 중 오류:", error);
        setUser(null);
      } finally {
        setIsLoading(false);
      }
    };
    checkUserSession();
  }, []);

  const login = (userData: User) => {
    setUser(userData);
  };

  const logout = async () => {
    try {
      await axios.post('/api/auth/logout', {}, { withCredentials: true });
      setUser(null);
    } catch (error) {
      console.error("로그아웃 중 오류:", error);
    }
  };

  // ✨ [추가] MY 페이지에서 API 키를 저장했을 때 호출할 함수
  const updateApiKeyStatus = (status: boolean) => {
    if (user) {
      setUser({ ...user, apiKeySet: status });
    }
  };

  const value = { user, isLoading, login, logout, updateApiKeyStatus };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}

