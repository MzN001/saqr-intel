// Shared by the server layout (inline <head> script) and lib/theme.tsx.
// Kept out of the "use client" module so the server layout gets the real string.
export const THEME_STORAGE_KEY = "saqr-theme";

/** Routes that keep the legacy Night Grid look (palette, fonts, dark by default) until they are redesigned. */
export const LEGACY_SCOPE_CLASS = "brand-night-grid";
export const LEGACY_ROUTE_RE = /^\/police(\/|$)/;

// Runs before first paint, so no route ever flashes the wrong theme.
// - A saved choice ("light" / "dark" in localStorage) always wins.
// - Otherwise: light everywhere (the Saqr default), dark on /police (legacy Night Grid default).
// - On /police it also puts the legacy scope class on <html> (see globals.css).
export const THEME_INIT_SCRIPT = `(function(){var d=document.documentElement,p=${LEGACY_ROUTE_RE}.test(location.pathname),s=null;if(p)d.classList.add("${LEGACY_SCOPE_CLASS}");try{s=localStorage.getItem("${THEME_STORAGE_KEY}")}catch(e){}if(s==="dark"||(s!=="light"&&p))d.setAttribute("data-theme","dark");else d.removeAttribute("data-theme")})()`;
