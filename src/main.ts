import './style.css';
import { mountApp } from './ui.ts';

mountApp(document.querySelector<HTMLDivElement>('#app')!);

(function initThemeToggle() {
	const button = document.getElementById('theme-toggle') as HTMLButtonElement | null;
	if (!button) return;

	function apply(theme: string): void {
		document.documentElement.setAttribute('data-theme', theme);
		localStorage.setItem('theme', theme);
		const isDark = theme === 'dark';
		const label = isDark ? 'Switch to light mode' : 'Switch to dark mode';
		button!.textContent = isDark ? '🌙' : '☀️';
		button!.setAttribute('aria-label', label);
		button!.setAttribute('title', label);
		button!.setAttribute('aria-pressed', String(isDark));
	}

	const current = document.documentElement.getAttribute('data-theme') ?? 'dark';
	apply(current);

	button.addEventListener('click', () => {
		const next = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
		apply(next);
	});
})();
