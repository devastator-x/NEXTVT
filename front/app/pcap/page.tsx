"use client";

import { useAuth } from '../../contexts/AuthContext';
import { useRouter } from 'next/navigation';
import { useEffect, useState, useMemo } from 'react';
import axios from 'axios';

interface Packet {
  id: number;
  time: string;
  source_ip: string;
  dest_ip: string;
  protocol: string;
  info: string;
  type: Protocol;
}

type Protocol = 'http' | 'ssh' | 'ftp' | 'smb';

const PROTOCOLS: Protocol[] = ['http', 'ssh', 'ftp', 'smb'];

export default function PcapPage() {
    const { user, isLoading: isAuthLoading } = useAuth();
    const router = useRouter();
    const [file, setFile] = useState<File | null>(null);
    const [allPackets, setAllPackets] = useState<Packet[]>([]);
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [analysisCompleted, setAnalysisCompleted] = useState(false);
    const [selectedProtocols, setSelectedProtocols] = useState<Protocol[]>(['http']);

    useEffect(() => {
        if (!isAuthLoading && !user) {
            router.push('/login');
        }
    }, [user, isAuthLoading, router]);

    const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        if (e.target.files && e.target.files[0]) {
            setFile(e.target.files[0]);
        }
    };

    const handleProtocolChange = (protocol: Protocol) => {
        setSelectedProtocols(prev =>
            prev.includes(protocol)
                ? prev.filter(p => p !== protocol)
                : [...prev, protocol]
        );
    };

    const handleAnalyze = async () => {
        if (!file) {
            setError('분석할 파일을 선택해주세요.');
            return;
        }

        setIsLoading(true);
        setError(null);
        setAllPackets([]);
        setAnalysisCompleted(false);

        const formData = new FormData();
        formData.append('pcap_file', file);

        try {
            const response = await axios.post('/api/pcap/analyze', formData, {
                headers: { 'Content-Type': 'multipart/form-data' },
                withCredentials: true,
            });

            if (response.data.success) {
                setAllPackets(response.data.data);
            } else {
                setError(response.data.message || '패킷 분석에 실패했습니다.');
            }
        } catch (err: any) {
            setError(err.response?.data?.message || '서버와 통신 중 오류가 발생했습니다.');
        } finally {
            setIsLoading(false);
            setAnalysisCompleted(true);
        }
    };

    const filteredPackets = useMemo(() => {
        if (!analysisCompleted) return [];
        return allPackets
            .filter(packet => selectedProtocols.includes(packet.type))
            .sort((a, b) => new Date(a.time).getTime() - new Date(b.time).getTime());
    }, [allPackets, selectedProtocols, analysisCompleted]);
    
    if (isAuthLoading || !user) {
        return (
            <div className="d-flex justify-content-center align-items-center" style={{ height: '100vh' }}>
                <div className="spinner-border" role="status" />
            </div>
        );
    }

    return (
        <div className="card">
            <style>{`
                .info-cell {
                    max-width: 400px;
                    overflow-x: hidden;
                    white-space: nowrap;
                }
                .info-cell:hover {
                    overflow-x: auto;
                }
                /* ✨ 컬럼 너비 조정을 위한 스타일 추가 */
                .table th.time-col, .table td.time-col {
                    width: 220px; /* 너비를 좀 더 확보 */
                }
                .table th.ip-col, .table td.ip-col {
                    width: 150px; /* 너비를 좀 더 확보 */
                }
            `}</style>
            <div className="card-body">
                <h1 className="card-title">패킷 분석</h1>
                <p className="card-subtitle mb-3 text-muted">.pcap 또는 .pcapng 파일을 업로드하여 패킷을 분석하고, 원하는 프로토콜만 필터링하여 확인하세요.</p>

                <div className="input-group mb-3">
                    <input type="file" className="form-control" onChange={handleFileChange} accept=".pcap,.pcapng" disabled={isLoading} />
                    <button className="btn btn-primary" onClick={handleAnalyze} disabled={isLoading || !file}>
                        {isLoading ? '분석 중...' : '분석 시작'}
                    </button>
                </div>

                {error && <div className="alert alert-danger">{error}</div>}

                {analysisCompleted && !isLoading && (
                    <>
                        <hr />
                        <div className="mb-3">
                            <label className="form-label">표시할 정보 선택:</label>
                            <div className="d-flex flex-wrap">
                                {PROTOCOLS.map((proto) => (
                                    <div className="form-check form-check-inline" key={proto}>
                                        <input
                                            className="form-check-input"
                                            type="checkbox"
                                            id={`check-${proto}`}
                                            value={proto}
                                            checked={selectedProtocols.includes(proto)}
                                            onChange={() => handleProtocolChange(proto)}
                                        />
                                        <label className="form-check-label" htmlFor={`check-${proto}`}>
                                            {proto.toUpperCase()}
                                        </label>
                                    </div>
                                ))}
                            </div>
                        </div>

                        <div className="mt-4">
                            <h2>분석 결과</h2>
                            {filteredPackets.length > 0 ? (
                                <div className="table-responsive">
                                    <table className="table table-striped table-hover table-sm">
                                        <thead>
                                            <tr>
                                                <th>#</th>
                                                {/* ✨ 헤더명 변경 및 너비 조정을 위한 클래스 추가 */}
                                                <th className="time-col">Time</th>
                                                <th className="ip-col">Src IP</th>
                                                <th className="ip-col">Dst IP</th>
                                                <th>Protocol</th>
                                                <th>Info</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {filteredPackets.map((packet, index) => (
                                                <tr key={packet.id}>
                                                    <th>{index + 1}</th>
                                                    {/* ✨ 너비 조정을 위한 클래스 추가 */}
                                                    <td className="time-col" style={{ whiteSpace: 'nowrap' }}>{new Date(packet.time).toLocaleString()}</td>
                                                    <td className="ip-col">{packet.source_ip}</td>
                                                    <td className="ip-col">{packet.dest_ip}</td>
                                                    <td>{packet.protocol}</td>
                                                    <td className="info-cell">
                                                        {packet.info}
                                                    </td>
                                                </tr>
                                            ))}
                                        </tbody>
                                    </table>
                                </div>
                            ) : (
                                <div className="alert alert-info">
                                    {allPackets.length > 0
                                        ? "선택된 프로토콜에 해당하는 패킷이 없습니다."
                                        : "분석된 파일에서 유효한 프로토콜(HTTP, SSH, FTP, SMB) 패킷을 찾을 수 없습니다."
                                    }
                                </div>
                            )}
                        </div>
                    </>
                )}
            </div>
        </div>
    );
}

