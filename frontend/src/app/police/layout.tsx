// /police (Command Center + login) uses the same Saqr tokens as /citizen (light by default,
// a saved `saqr-theme` choice wins; theme colour comes from the root layout). See DESIGN.md.
export default function PoliceLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return children;
}
