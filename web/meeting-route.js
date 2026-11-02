// Select the invitation shell before the first paint; never hide browser zoom controls.
if (/^#meeting=[0-9a-f]{64}(?:&|$)/.test(location.hash)) document.documentElement.classList.add('meeting-route');
