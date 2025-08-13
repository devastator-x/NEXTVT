"use client";

import Link from 'next/link';
import { useAuth } from '../contexts/AuthContext';
import { useRouter } from 'next/navigation';

export default function Navbar() {
  const { user, logout } = useAuth();
  const router = useRouter();

  const handleSignOut = async () => {
    await logout();
    router.push('/login');
  };

  return (
    <nav className="navbar navbar-expand-lg navbar-dark bg-dark mb-4">
      <div className="container-fluid">
        <Link href="/" className="navbar-brand">
          NEXTVT
        </Link>
        <button className="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
          <span className="navbar-toggler-icon"></span>
        </button>
        <div className="collapse navbar-collapse" id="navbarNav">
          <ul className="navbar-nav me-auto mb-2 mb-lg-0">
            {user && (
              <>
                <li className="nav-item">
                  <Link href="/" className="nav-link">
                    IP&DNS 스캔
                  </Link>
                </li>
                <li className="nav-item">
                  {/* ✨ 'ping 체크'를 'Ping 체크'로 변경 */}
                  <Link href="/ping" className="nav-link">
                    Ping 체크
                  </Link>
                </li>
                <li className="nav-item">
                  {/* ✨ '웹사이트 상태'를 'Health 체크'로 변경 */}
                  <Link href="/healthcheck" className="nav-link">
                    Health 체크
                  </Link>
                </li>
                <li className="nav-item">
                  <Link href="/ipcalc" className="nav-link">
                    ip 계산기
                  </Link>
                </li>
                <li className="nav-item">
                  <Link href="/cti" className="nav-link">
                    CTI
                  </Link>
                </li>
              </>
            )}
          </ul>
          <ul className="navbar-nav ms-auto mb-2 mb-lg-0">
            {user ? (
              <li className="nav-item dropdown">
                <a className="nav-link dropdown-toggle" href="#" role="button" data-bs-toggle="dropdown">
                  {user.email?.split('@')[0]}
                </a>
                <ul className="dropdown-menu dropdown-menu-end">
                  <li><Link href="/my" className="dropdown-item">MY 페이지</Link></li>
                  {user.is_admin && <li><Link href="/admin" className="dropdown-item">관리자</Link></li>}
                  <li><hr className="dropdown-divider" /></li>
                  <li>
                    <button onClick={handleSignOut} className="dropdown-item">
                      로그아웃
                    </button>
                  </li>
                </ul>
              </li>
            ) : (
              <>
                <li className="nav-item">
                  <Link href="/login" className="nav-link">
                    로그인
                  </Link>
                </li>
                <li className="nav-item">
                  <Link href="/signup" className="nav-link">
                    회원가입
                  </Link>
                </li>
              </>
            )}
          </ul>
        </div>
      </div>
    </nav>
  );
}

