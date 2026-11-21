import {useState} from 'react';

const suppliedImage = `${import.meta.env.BASE_URL}uet-logo-original.png`;

export default function UETLogo({variant = 'sidebar'}) {
  const [failed, setFailed] = useState(false);

  return (
    <span className={`uet-image-tile uet-image-tile--${variant}`}>
      {failed ? (
        <span className="uet-image-unavailable" role="img" aria-label="Không tải được logo UET">Logo chưa tải được</span>
      ) : (
        <img
          src={suppliedImage}
          alt="Logo Trường Đại học Công nghệ - Đại học Quốc gia Hà Nội"
          onError={() => setFailed(true)}
        />
      )}
    </span>
  );
}