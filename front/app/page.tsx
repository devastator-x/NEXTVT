"use client";

import { useAuth } from '../contexts/AuthContext';
import { useRouter } from 'next/navigation';
import { useEffect, useState, FormEvent, ChangeEvent } from 'react';
import axios from 'axios';

// ✨ [수정] API 응답 결과의 타입을 리스트 형태로 변경합니다.
interface ScanResult {
  ip: string; // IP 주소를 포함
  country: string;
  as_owner: string;
  malicious: string;
}

// ... (ColumnKey, ALL_COLUMNS 타입 정의는 기존과 동일) ...
type ColumnKey = 'country' | 'as_owner' | 'malicious';
const ALL_COLUMNS: Record<ColumnKey, string> = {
  country: '국가',
  as_owner: '소유자',
  malicious: '유해',
};

function IpScanner() {
  const [ips, setIps] = useState('');
  // ✨ [수정] results 상태를 ScanResult 배열로 변경합니다.
  const [results, setResults] = useState<ScanResult[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedColumns, setSelectedColumns] = useState<ColumnKey[]>(['country', 'as_owner', 'malicious']);
  const [isCopied, setIsCopied] = useState(false);

  // ... (handleScan, handleColumnChange 함수는 기존과 동일) ...
  const handleScan = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setResults(null);
    const ipList = ips.split('\n').map(ip => ip.trim()).filter(ip => ip);
    if (ipList.length === 0) {
      setError("조회할 IP 주소를 입력해주세요.");
      setLoading(false);
      return;
    }
    try {
      const response = await axios.post('/api/scan', 
        { ips: ipList },
        { withCredentials: true }
      );
      if (response.data.success) {
        setResults(response.data.results);
      } else {
        setError(response.data.message || '알 수 없는 오류가 발생했습니다.');
      }
    } catch (err: any) {
      setError(err.response?.data?.message || '서버에 연결할 수 없습니다. 백엔드 서버가 실행 중인지 확인해주세요.');
    } finally {
      setLoading(false);
    }
  };

  const handleColumnChange = (e: ChangeEvent<HTMLInputElement>) => {
    const { value, checked } = e.target;
    const columnKey = value as ColumnKey;
    setSelectedColumns(prev => 
      checked ? [...prev, columnKey] : prev.filter(col => col !== columnKey)
    );
  };

  const handleCopyResults = () => {
    if (!results) return;

    // ✨ [수정] 리스트 형식의 results를 처리하도록 수정합니다.
    const rows = results.map(info => {
      const rowData = [info.ip, ...selectedColumns.map(col => info[col])];
      return rowData.join('\t');
    });

    const textToCopy = rows.join('\n');
    
    navigator.clipboard.writeText(textToCopy).then(() => {
      setIsCopied(true);
      setTimeout(() => setIsCopied(false), 2000);
    });
  };

  return (
    <div className="card">
      <div className="card-body">
        {/* ... (폼 부분은 기존과 동일) ... */}
        <h1 className="card-title">IP 정보 조회</h1>
        <form onSubmit={handleScan}>
          <div className="mb-3">
            <label htmlFor="ips" className="form-label">IP 주소 (한 줄에 하나씩 입력)</label>
            <textarea
              id="ips"
              className="form-control"
              rows={10}
              placeholder={"8.8.8.8\n1.1.1.1"}
              value={ips}
              onChange={(e) => setIps(e.target.value)}
            />
          </div>
          <div className="mb-3">
            <label className="form-label">표시할 정보 선택</label>
            <div>
              {Object.entries(ALL_COLUMNS).map(([key, value]) => (
                <div className="form-check form-check-inline" key={key}>
                  <input
                    className="form-check-input"
                    type="checkbox"
                    id={key}
                    value={key}
                    checked={selectedColumns.includes(key as ColumnKey)}
                    onChange={handleColumnChange}
                  />
                  <label className="form-check-label" htmlFor={key}>{value}</label>
                </div>
              ))}
            </div>
          </div>
          <button type="submit" className="btn btn-primary" disabled={loading}>
            {loading ? '조회 중...' : '조회하기'}
          </button>
        </form>
        {error && <div className="alert alert-danger mt-3">{error}</div>}

        {results && (
          <div className="mt-4">
            <div className="d-flex justify-content-between align-items-center mb-3">
              <h2 className="mb-0">조회 결과</h2>
              <button onClick={handleCopyResults} className="btn btn-light" title="결과 복사하기">
                {isCopied ? (
                  <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" className="bi bi-check-lg" viewBox="0 0 16 16"><path d="M12.736 3.97a.733.733 0 0 1 1.047 0c.286.289.29.756.01 1.05L7.88 12.01a.733.733 0 0 1-1.065.02L3.217 8.384a.757.757 0 0 1 0-1.06.733.733 0 0 1 1.047 0l3.052 3.093 5.4-6.425a.247.247 0 0 1 .02-.022z"/></svg>
                ) : (
                  <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" className="bi bi-clipboard" viewBox="0 0 16 16"><path d="M4 1.5H3a2 2 0 0 0-2 2V14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V3.5a2 2 0 0 0-2-2h-1v1h1a1 1 0 0 1 1 1V14a1 1 0 0 1-1-1H3a1 1 0 0 1-1-1V3.5a1 1 0 0 1 1-1h1v-1z"/><path d="M9.5 1a.5.5 0 0 1 .5.5v1a.5.5 0 0 1-.5.5h-3a.5.5 0 0 1-.5-.5v-1a.5.5 0 0 1 .5-.5h3zm-3-1A1.5 1.5 0 0 0 5 1.5v1A1.5 1.5 0 0 0 6.5 4h3A1.5 1.5 0 0 0 11 2.5v-1A1.5 1.5 0 0 0 9.5 0h-3z"/></svg>
                )}
              </button>
            </div>
            <div className="table-responsive">
              <table className="table table-striped table-bordered">
                <thead className="table-dark">
                  <tr>
                    <th>IP</th>
                    {selectedColumns.map(col => <th key={col}>{ALL_COLUMNS[col]}</th>)}
                  </tr>
                </thead>
                <tbody>
                  {/* ✨ [수정] 리스트를 순회하며 결과를 표시합니다. */}
                  {results.map((info) => (
                    <tr key={info.ip}>
                      <td>{info.ip}</td>
                      {selectedColumns.map(col => (
                        <td key={col} style={col === 'malicious' ? { color: parseInt(info.malicious) >= 1 ? 'red' : 'black' } : {}}>
                          {info[col]}
                        </td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default function HomePage() {
  const { user, isLoading } = useAuth();
  const router = useRouter();

  useEffect(() => {
    if (!isLoading && !user) {
      router.push('/login');
    }
  }, [user, isLoading, router]);

  if (isLoading || !user) {
    return (
        <div className="d-flex justify-content-center align-items-center" style={{ height: '100vh' }}>
            <div className="spinner-border" role="status">
                <span className="visually-hidden">Loading...</span>
            </div>
        </div>
    );
  }

  return <IpScanner />;
}

