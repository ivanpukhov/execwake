import './app.css';
import { mount } from 'svelte';
import App from './App.svelte';

performance.mark('execwake-app-start');
mount(App, {
  target: document.getElementById('app')!
});
