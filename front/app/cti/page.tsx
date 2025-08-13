"use client";

import { useAuth } from '../../contexts/AuthContext';
import { useRouter } from 'next/navigation';
import { useEffect, useState } from 'react';
import axios from 'axios';

interface Indicator {
  id: number;
  value: string;
  type: 'domain' | 'ipv4' | 'email';
  source: string;
  description: string;
  added_at: string;
  country: string | null;
}

type FilterType = 'all' | 'domain' | 'ipv4' | 'email';

export default function CtiPage() {
  const { user, isLoading: authLoading } = useAuth();
  const router = useRouter();
  const [indicators, setIndicators] = useState<Indicator[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState<FilterType>('ipv4');
  const [isCopied, setIsCopied] = useState(false);
  const [checkedItems, setCheckedItems] = useState<Set<number>>(new Set());
  
  const [currentPage, setCurrentPage] = useState(1);
  const [itemsPerPage, setItemsPerPage] = useState(100);
  const [totalItems, setTotalItems] = useState(0);

  useEffect(() => {
    if (!authLoading && !user) {
      router.push('/login');
    }
  }, [user, authLoading, router]);

  useEffect(() => {
    if (user) {
      fetchData(filter, currentPage, itemsPerPage);
    }
  }, [user, filter, currentPage, itemsPerPage]);

  const fetchData = async (currentFilter: FilterType, page: number, limit: number) => {
    setLoading(true);
    setCheckedItems(new Set());
    try {
      const response = await axios.get('/api/cti', { 
        params: { type: currentFilter, page, limit },
        withCredentials: true 
      });
      if (response.data.success) {
        setIndicators(response.data.data);
        setTotalItems(response.data.total);
      }
    } catch (error) {
      console.error("Error fetching CTI data:", error);
    } finally {
      setLoading(false);
    }
  };

  const handleCheckChange = (id: number) => {
    const newCheckedItems = new Set(checkedItems);
    if (newCheckedItems.has(id)) {
      newCheckedItems.delete(id);
    } else {
      newCheckedItems.add(id);
    }
    setCheckedItems(newCheckedItems);
  };

  const handleSelectAll = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.checked) {
      const allIds = new Set(indicators.map(ind => ind.id));
      setCheckedItems(allIds);
    } else {
      setCheckedItems(new Set());
    }
  };

  const handleCopy = () => {
    const textToCopy = indicators
      .filter(ind => checkedItems.has(ind.id))
      .map(ind => {
        if (filter === 'email') return `${ind.value}\t${ind.description}`;
        return `${ind.value}\t${ind.country || ''}`;
      })
      .join('\n');
    
    if (!textToCopy) {
        alert('복사할 항목을 선택해주세요.');
        return;
    }

    navigator.clipboard.writeText(textToCopy).then(() => {
        setIsCopied(true);
        setTimeout(() => setIsCopied(false), 2000);
    });
  };
  
  const totalPages = Math.ceil(totalItems / itemsPerPage);

  if (authLoading) {
    return (
        <div className="d-flex justify-content-center align-items-center" style={{ height: '100vh' }}>
            <div className="spinner-border" role="status">
                <span className="visually-hidden">Loading...</span>
            </div>
        </div>
    );
  }

  return (
    <div className="card">
      <div className="card-header d-flex justify-content-between align-items-center">
        <h1 className="mb-0">CTI - 위협 정보</h1>
        <div>
          <button onClick={() => fetchData(filter, currentPage, itemsPerPage)} className="btn btn-sm btn-outline-primary me-2" disabled={loading}>
            {loading ? '갱신 중...' : '새로고침'}
          </button>
          <button onClick={handleCopy} className="btn btn-sm btn-outline-secondary" disabled={checkedItems.size === 0}>
            {isCopied ? '복사 완료!' : `선택 (${checkedItems.size}) 복사`}
          </button>
        </div>
      </div>
      <div className="card-body">
        <div className="d-flex justify-content-between align-items-center mb-3">
          <ul className="nav nav-tabs">
            <li className="nav-item">
              <button className={`nav-link ${filter === 'all' ? 'active' : ''}`} onClick={() => { setFilter('all'); setCurrentPage(1); }}>전체</button>
            </li>
            <li className="nav-item">
              <button className={`nav-link ${filter === 'domain' ? 'active' : ''}`} onClick={() => { setFilter('domain'); setCurrentPage(1); }}>도메인</button>
            </li>
            <li className="nav-item">
              <button className={`nav-link ${filter === 'ipv4' ? 'active' : ''}`} onClick={() => { setFilter('ipv4'); setCurrentPage(1); }}>IP 주소</button>
            </li>
            <li className="nav-item">
              <button className={`nav-link ${filter === 'email' ? 'active' : ''}`} onClick={() => { setFilter('email'); setCurrentPage(1); }}>이메일</button>
            </li>
          </ul>
          <div className="d-flex align-items-center">
            <select className="form-select form-select-sm" style={{width: '80px'}} value={itemsPerPage} onChange={e => { setItemsPerPage(Number(e.target.value)); setCurrentPage(1); }}>
                <option value="50">50</option>
                <option value="100">100</option>
                <option value="200">200</option>
                <option value="500">500</option>
            </select>
            <span className="ms-2 text-muted">개씩 보기</span>
          </div>
        </div>

        <div className="table-responsive">
          <table className="table table-hover">
            <thead className="table-light">
              <tr>
                <th style={{width: '5%'}}><input type="checkbox" className="form-check-input" onChange={handleSelectAll} checked={indicators.length > 0 && checkedItems.size === indicators.length}/></th>
                <th style={{width: '5%'}}>#</th>
                {filter === 'email' ? (
                  <>
                    <th>발신자</th>
                    <th>제목</th>
                  </>
                ) : (
                  <>
                    <th>지표 (Indicator)</th>
                    <th>국가</th>
                  </>
                )}
                <th>타입</th>
                <th>출처</th>
                <th>추가된 시간</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr><td colSpan={7} className="text-center"><div className="spinner-border spinner-border-sm" role="status"><span className="visually-hidden">Loading...</span></div></td></tr>
              ) : indicators.length > 0 ? (
                indicators.map((ind, index) => (
                  <tr key={ind.id}>
                    <td><input type="checkbox" className="form-check-input" checked={checkedItems.has(ind.id)} onChange={() => handleCheckChange(ind.id)}/></td>
                    <td className="text-muted">{(currentPage - 1) * itemsPerPage + index + 1}</td>
                    {filter === 'email' ? (
                        <>
                            <td><code>{ind.value}</code></td>
                            <td>{ind.description}</td>
                        </>
                    ) : (
                        <>
                            <td><code>{ind.value}</code></td>
                            <td>{ind.country}</td>
                        </>
                    )}
                    <td><span className={`badge ${ind.type === 'ipv4' ? 'bg-info' : (ind.type === 'domain' ? 'bg-primary' : 'bg-success')}`}>{ind.type}</span></td>
                    <td>{ind.source}</td>
                    <td>{new Date(ind.added_at).toLocaleString('ko-KR')}</td>
                  </tr>
                ))
              ) : (
                <tr><td colSpan={7} className="text-center">표시할 데이터가 없습니다.</td></tr>
              )}
            </tbody>
          </table>
        </div>

        <nav className="d-flex justify-content-center mt-3">
            <ul className="pagination">
                <li className={`page-item ${currentPage === 1 ? 'disabled' : ''}`}>
                    <button className="page-link" onClick={() => setCurrentPage(currentPage - 1)}>이전</button>
                </li>
                <li className="page-item active">
                    <span className="page-link">{currentPage} / {totalPages}</span>
                </li>
                <li className={`page-item ${currentPage === totalPages ? 'disabled' : ''}`}>
                    <button className="page-link" onClick={() => setCurrentPage(currentPage + 1)}>다음</button>
                </li>
            </ul>
        </nav>
      </div>
    </div>
  );
}

