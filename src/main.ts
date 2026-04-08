import { poly1305 } from '@noble/ciphers/_poly1305.js';
import './style.css';
import { mountApp } from './ui.ts';

void poly1305;

mountApp(document.querySelector<HTMLDivElement>('#app')!);
