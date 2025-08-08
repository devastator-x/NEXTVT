"use client";

import { useAuth } from '../../contexts/AuthContext';
import { useRouter } from 'next/navigation';
import { useEffect, useState, useRef } from 'react';

export default function PingPage() {
    const { user, isLoading } = useAuth();
    const router = useRouter();
    const [target, setTarget] = useState('');
    const [count, setCount] = useState('0');
    const [results, setResults] = useState<string[]>([]);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);

    const abortControllerRef = useRef<AbortController | null>(null);

    useEffect(() => {
        if (!isLoading && !user) {
            router.push('/login');
        }
        return () => {
            abortControllerRef.current?.abort();
        };
    }, [user, isLoading, router]);

    const validateInput = (input: string) => {
        const regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$|^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)+([A-Za-z]|[A-Za-z][A-Za-z0-9\-]*[A-Za-z0-9])$/;
        return regex.test(input);
    };

    const handlePing = async () => {
        if (!validateInput(target)) {
            setError('유효한 IP 주소 또는 도메인 이름을 입력해주세요.');
            return;
        }

        const pingCount = parseInt(count, 10);
        if (isNaN(pingCount) || pingCount < 0 || pingCount > 500) {
            setError('Ping 횟수는 0 (무한) 또는 1에서 500 사이의 숫자여야 합니다.');
            return;
        }

        setLoading(true);
        setError(null);
        setResults([]);

        abortControllerRef.current = new AbortController();

        try {
            const response = await fetch('/api/ping', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target, count: pingCount }),
                credentials: 'include',
                signal: abortControllerRef.current.signal,
            });
            
            if (!response.ok) {
                const errorData = await response.json();
                setError(errorData.message || 'Ping 요청에 실패했습니다.');
                setLoading(false);
                return;
            }

            if (!response.body) return;

            const reader = response.body.getReader();
            const decoder = new TextDecoder();

            while (true) {
                const { value, done } = await reader.read();
                if (done) break;

                const chunk = decoder.decode(value, { stream: true });
                const lines = chunk.split('\n').filter(line => line.trim() !== '');
                
                const timestampedLines = lines.map(line => {
                    const now = new Date();
                    const timestamp = `[${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}-${String(now.getDate()).padStart(2, '0')} ${String(now.getHours()).padStart(2, '0')}:${String(now.getMinutes()).padStart(2, '0')}:${String(now.getSeconds()).padStart(2, '0')}]`;
                    return `${timestamp} ${line}`;
                });

                setResults(prev => [...prev, ...timestampedLines]);
            }
        } catch (err: any) {
            if (err.name !== 'AbortError') {
                setError('Ping 요청 중 오류가 발생했습니다.');
            }
        } finally {
            setLoading(false);
        }
    };

    const handleStop = () => {
        if (abortControllerRef.current) {
            abortControllerRef.current.abort();
            setLoading(false);
        }
    };
    
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
        <div className="card">
            <div className="card-body">
                <h1 className="card-title">Ping 체크</h1>
                {/* ✨ <form>을 <div>로 변경하고 버튼에 onClick 핸들러를 직접 연결 */}
                <div>
                    <div className="mb-3">
                        <label htmlFor="target" className="form-label">IP 주소 또는 도메인</label>
                        <input
                            type="text"
                            id="target"
                            className="form-control"
                            value={target}
                            onChange={(e) => setTarget(e.target.value)}
                            placeholder="예: 8.8.8.8 또는 google.com"
                            required
                            disabled={loading}
                        />
                    </div>
                    <div className="mb-3">
                        <label htmlFor="count" className="form-label">횟수 (0: 무한, 1-500)</label>
                        <input
                            type="number"
                            id="count"
                            className="form-control"
                            value={count}
                            onChange={(e) => setCount(e.target.value)}
                            min="0"
                            max="500"
                            required
                            disabled={loading}
                        />
                    </div>
                    
                    {!loading ? (
                         <button type="button" className="btn btn-primary" onClick={handlePing}>Ping 시작</button>
                    ) : (
                         <button type="button" className="btn btn-danger" onClick={handleStop}>중지</button>
                    )}
                </div>

                {error && <div className="alert alert-danger mt-3">{error}</div>}

                {results.length > 0 && (
                    <div className="mt-4">
                        <h2>Ping 결과</h2>
                        <pre className="bg-light p-3 rounded" style={{maxHeight: '400px', overflowY: 'auto'}}>
                            <code>
                                {results.join('\n')}
                            </code>
                        </pre>
                    </div>
                )}
            </div>
        </div>
    );
}
