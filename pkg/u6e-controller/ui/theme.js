// The theme picked with the header's button, set before the page first paints
// (a module would run after it); without one the system's scheme applies.
try {
  const t = localStorage.getItem('theme');
  if (t === 'light' || t === 'dark') document.documentElement.dataset.theme = t;
} catch {}
