// Shared by the server layout (inline <head> script) and lib/theme.tsx.
// Kept out of the "use client" module so the server layout gets the real string.
export const THEME_STORAGE_KEY = "saqr-theme";

// Runs before first paint so a saved dark theme never flashes white on reload.
export const THEME_INIT_SCRIPT = `(function(){try{if(localStorage.getItem("${THEME_STORAGE_KEY}")==="dark")document.documentElement.setAttribute("data-theme","dark")}catch(e){}})()`;
