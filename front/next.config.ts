import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // rewrites 함수를 추가하여 프록시 설정을 합니다.
  async rewrites() {
    return [
      {
        // source: 프론트엔드에서 사용할 API 경로 패턴입니다.
        // '/api/'로 시작하는 모든 경로를 의미합니다.
        source: "/api/:path*",
        // destination: 실제 요청을 전달할 백엔드 서버 주소입니다.
        // .env.local 파일에 설정된 값을 사용합니다.
        destination: `${process.env.NEXT_PUBLIC_API_BASE_URL}/api/:path*`,
      },
    ];
  },
};

export default nextConfig;

