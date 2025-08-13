"use client";

import { useAuth } from '../contexts/AuthContext';
import { useRouter } from 'next/navigation';
import { useEffect, useState, FormEvent, ChangeEvent } from 'react';
import axios from 'axios';

// ===================================================================
// IP 스캔 컴포넌트 (기존 코드)
// ===================================================================
interface ScanResult {
  ip: string;
  country: string;
  as_owner: string;
  malicious: string;
}

type ColumnKey = 'country' | 'as_owner' | 'malicious';
const ALL_COLUMNS: Record<ColumnKey, string> = {
  country: '국가',
  as_owner: '소유자',
  malicious: '유해',
};

function IpScanner() {
  const [ips, setIps] = useState('');
  const [results, setResults] = useState<ScanResult[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedColumns, setSelectedColumns] = useState<ColumnKey[]>(['country', 'as_owner', 'malicious']);
  const [isCopied, setIsCopied] = useState(false);

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
      setError(err.response?.data?.message || '서버에 연결할 수 없습니다.');
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
    <div className="card h-100">
      <div className="card-body d-flex flex-column">
        <h1 className="card-title">IP 정보 조회</h1>
        <form onSubmit={handleScan}>
          <div className="mb-3">
            <label htmlFor="ips" className="form-label">IP 주소 (한 줄에 하나씩 입력)</label>
            <textarea
              id="ips"
              className="form-control"
              rows={5}
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
          <div className="mt-4 flex-grow-1" style={{ overflowY: 'auto' }}>
            <div className="d-flex justify-content-between align-items-center mb-3">
              <h2 className="mb-0">조회 결과</h2>
              <button onClick={handleCopyResults} className="btn btn-light" title="결과 복사하기">
                {isCopied ? '복사 완료!' : '복사'}
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

// ===================================================================
// DNS 조회 컴포넌트 (수정됨)
// ===================================================================
interface ARecord {
    ip: string;
    country: string | null;
}
interface DnsResults {
    [key: string]: string[] | ARecord[];
}

function DnsLookup() {
    const [domain, setDomain] = useState('');
    const [results, setResults] = useState<DnsResults | null>(null);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);

    const recordTypeColors: { [key: string]: string } = {
        A: 'bg-success',
        AAAA: 'bg-primary',
        MX: 'bg-info text-dark',
        NS: 'bg-warning text-dark',
        TXT: 'bg-secondary',
        CNAME: 'bg-dark',
        SOA: 'bg-danger',
    };

    const handleLookup = async (e: FormEvent) => {
        e.preventDefault();
        setLoading(true);
        setError(null);
        setResults(null);
        try {
            const response = await axios.post('/api/dnslookup', { domain }, { withCredentials: true });
            if (response.data.success) {
                setResults(response.data.data);
            } else {
                setError(response.data.message || 'DNS 조회 중 오류가 발생했습니다.');
            }
        } catch (err: any) {
            setError(err.response?.data?.message || '서버에 연결할 수 없습니다.');
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="card h-100">
            <div className="card-body d-flex flex-column">
                <h1 className="card-title">DNS 레코드 조회</h1>
                <form onSubmit={handleLookup}>
                    <div className="input-group mb-3">
                        <input
                            type="text"
                            className="form-control"
                            value={domain}
                            onChange={e => setDomain(e.target.value)}
                            placeholder="도메인 입력 (예: google.com)"
                            required
                        />
                        <button type="submit" className="btn btn-primary" disabled={loading}>
                            {loading ? '조회 중...' : '조회'}
                        </button>
                    </div>
                </form>
                {error && <div className="alert alert-danger">{error}</div>}

                {results && (
                    <div className="mt-3 flex-grow-1" style={{ overflowY: 'auto' }}>
                        {Object.entries(results).map(([type, records]) => (
                            records.length > 0 && (
                                <div key={type} className="mb-3">
                                    <h5><span className={`badge ${recordTypeColors[type] || 'bg-light text-dark'}`}>{type}</span></h5>
                                    <ul className="list-group">
                                        {records.map((record, index) => (
                                            <li key={index} className="list-group-item font-monospace" style={{fontSize: '0.875rem'}}>
                                                {type === 'A' && typeof record === 'object' ? (
                                                    <span>
                                                        {(record as ARecord).ip}
                                                        <span className="badge bg-light text-dark ms-2">{(record as ARecord).country || 'N/A'}</span>
                                                    </span>
                                                ) : (
                                                    record as string
                                                )}
                                            </li>
                                        ))}
                                    </ul>
                                </div>
                            )
                        ))}
                    </div>
                )}
            </div>
        </div>
    );
}

// ===================================================================
// Reverse DNS 조회 컴포넌트 (신규 추가)
// ===================================================================
function ReverseDnsLookup() {
    const [ip, setIp] = useState('');
    const [result, setResult] = useState<string | null>(null);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);

    const handleLookup = async (e: FormEvent) => {
        e.preventDefault();
        setLoading(true);
        setError(null);
        setResult(null);
        try {
            const response = await axios.post('/api/reversedns', { ip }, { withCredentials: true });
            if (response.data.success) {
                setResult(response.data.data);
            } else {
                setError(response.data.message);
            }
        } catch (err: any) {
            setError(err.response?.data?.message || '서버에 연결할 수 없습니다.');
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="card">
            <div className="card-body">
                <h1 className="card-title">Reverse DNS 조회</h1>
                 <form onSubmit={handleLookup}>
                    <div className="input-group mb-3">
                        <input
                            type="text"
                            className="form-control"
                            value={ip}
                            onChange={e => setIp(e.target.value)}
                            placeholder="IP 주소 입력 (예: 8.8.8.8)"
                            required
                        />
                        <button type="submit" className="btn btn-primary" disabled={loading}>
                            {loading ? '조회 중...' : '조회'}
                        </button>
                    </div>
                </form>
                {loading && <div className="spinner-border spinner-border-sm" role="status"><span className="visually-hidden">Loading...</span></div>}
                {error && <div className="alert alert-danger mt-2 p-2">{error}</div>}
                {/* ✨ "결과:"를 "hostname:"으로 변경 */}
                {result && <div className="alert alert-success mt-2 p-2"><strong>hostname:</strong> {result}</div>}
            </div>
        </div>
    );
}


// ===================================================================
// 메인 페이지 레이아웃
// ===================================================================
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

  return (
    <div className="container-fluid">
        <div className="row g-4">
            {/* IP 스캔 */}
            <div className="col-lg-6">
                <IpScanner />
            </div>
            {/* 오른쪽 컬럼 (DNS 및 Reverse DNS) */}
            <div className="col-lg-6">
                <div className="d-flex flex-column gap-4">
                    <DnsLookup />
                    <ReverseDnsLookup />
                </div>
            </div>
        </div>
    </div>
  );
}

