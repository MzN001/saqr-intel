// Shared by the server layout (inline <head> script) and lib/theme.tsx.
// Kept out of the "use client" module so the server layout gets the real string.
export const THEME_STORAGE_KEY = "saqr-theme";

// Runs before first paint. Dark ("Night Grid") is the default; only a saved "light" choice opts out,
// so a first visit never flashes the light theme.
export const THEME_INIT_SCRIPT = `(function(){var d=document.documentElement;try{if(localStorage.getItem("${THEME_STORAGE_KEY}")!=="light")d.setAttribute("data-theme","dark")}catch(e){d.setAttribute("data-theme","dark")}})()`;
