// Shared by the server layout (inline <head> script) and lib/theme.tsx.
// Kept out of the "use client" module so the server layout gets the real string.
export const THEME_STORAGE_KEY = "saqr-theme";

// Runs before first paint, so no route ever flashes the wrong theme.
// - A saved choice ("light" / "dark" in localStorage) always wins.
// - Otherwise: light everywhere (the Saqr default), /police included.
export const THEME_INIT_SCRIPT = `(function(){var d=document.documentElement,s=null;try{s=localStorage.getItem("${THEME_STORAGE_KEY}")}catch(e){}if(s==="dark")d.setAttribute("data-theme","dark");else d.removeAttribute("data-theme")})()`;
