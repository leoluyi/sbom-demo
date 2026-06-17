import './globals.css';

export const metadata = {
  title: 'SBOM PoC Dashboard',
  description: 'Frontend dashboard for the SBOM multi-layer proof of concept',
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
