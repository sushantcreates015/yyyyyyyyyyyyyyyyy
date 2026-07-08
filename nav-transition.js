/**
 * nav-transition.js
 * Intercepts navigation between app pages and plays a smooth
 * instant-fade + slide-up transition so it feels like a native app.
 * Drop this script at the end of <body> on every page.
 */
(function () {
  'use strict';

  // Pages that belong to the app shell (bottom-nav pages)
  const APP_PAGES = ['home.html', 'card.html', 'index.html', 'activty.html', 'activity.html', 'profile.html', 'contact-pay.html'];

  // Track whether we're currently in a transition to block double-taps
  let transitioning = false;

  /* ─── Inject global transition styles once ─── */
  if (!document.getElementById('nav-transition-style')) {
    const style = document.createElement('style');
    style.id = 'nav-transition-style';
    style.textContent = `
      /* Outgoing page slides down + fades */
      @keyframes _ntFadeOut {
        from { opacity: 1;  transform: translateY(0)    scale(1);    }
        to   { opacity: 0;  transform: translateY(6px)  scale(0.985); }
      }
      /* Incoming page slides up + fades in */
      @keyframes _ntFadeIn {
        from { opacity: 0;  transform: translateY(10px) scale(0.985); }
        to   { opacity: 1;  transform: translateY(0)    scale(1);    }
      }
      body._nt-out {
        animation: _ntFadeOut 0.18s ease-in forwards;
        pointer-events: none;
      }
      body._nt-in {
        animation: _ntFadeIn 0.22s cubic-bezier(0.22, 1, 0.36, 1) forwards;
      }
      /* Prevent white flash on the incoming page – background is locked to
         whatever the current page body bg is via inline style set in JS */
      html._nt-loading, html._nt-loading body {
        background: var(--_nt-bg, #000) !important;
      }
    `;
    document.head.appendChild(style);
  }

  /**
   * Given an <a> href, decide if it's an in-app page nav link.
   */
  function isAppLink(href) {
    if (!href || href === '#' || href.startsWith('http') || href.startsWith('mailto') || href.startsWith('tel')) return false;
    const clean = href.split('?')[0].split('#')[0].split('/').pop() || '';
    return APP_PAGES.some(p => p === clean || clean === '');
  }

  /**
   * Navigate to `url` with a smooth animation.
   */
  function navigateTo(url) {
    if (transitioning) return;
    transitioning = true;

    // Capture the current background so the incoming page doesn't flash white
    const bg = getComputedStyle(document.body).backgroundColor || '#000';
    document.documentElement.style.setProperty('--_nt-bg', bg);

    // Animate current body out
    document.body.classList.add('_nt-out');

    setTimeout(() => {
      // Set the bg hint before loading so there's no flash
      document.documentElement.classList.add('_nt-loading');
      window.location.href = url;
    }, 160); // slightly less than animation duration for snappiness
  }

  /**
   * On page load, play the "in" animation.
   */
  function playEnterAnimation() {
    // Skip if this was a same-page reload (performance.navigation)
    document.body.classList.add('_nt-in');
    document.body.addEventListener('animationend', function onEnd(e) {
      if (e.animationName === '_ntFadeIn') {
        document.body.classList.remove('_nt-in');
        document.body.removeEventListener('animationend', onEnd);
      }
    });
  }

  /**
   * Intercept all clicks on anchor tags.
   * Works even for anchors added dynamically (event delegation on document).
   */
  document.addEventListener('click', function (e) {
    // Walk up from the actual target to find an <a>
    let el = e.target;
    while (el && el !== document) {
      if (el.tagName === 'A') break;
      el = el.parentElement;
    }
    if (!el || el.tagName !== 'A') return;

    const href = el.getAttribute('href');
    if (!isAppLink(href)) return;

    // Don't intercept if it's the current page (href="#" or same filename)
    const currentPage = window.location.pathname.split('/').pop() || 'index.html';
    const targetPage  = href.split('?')[0].split('#')[0].split('/').pop() || '';
    if (targetPage === currentPage || href === '#') return;

    e.preventDefault();
    navigateTo(href);
  }, true); // capture phase so it fires before any onclick handlers

  /* Also patch window.location.replace / assign used in some pages */
  const _origReplace = window.location.replace.bind(window.location);
  const _origAssign  = window.location.assign.bind(window.location);

  function patchedNav(url, original) {
    if (typeof url === 'string' && isAppLink(url)) {
      navigateTo(url);
    } else {
      original(url);
    }
  }

  try {
    // Note: location.replace / assign can't be fully overridden on all browsers
    // but we can wrap them on the object property level
    Object.defineProperty(window.location, 'replace', {
      configurable: true,
      value: function (url) { patchedNav(url, _origReplace); }
    });
    Object.defineProperty(window.location, 'assign', {
      configurable: true,
      value: function (url) { patchedNav(url, _origAssign); }
    });
  } catch (e) { /* some browsers block this — graceful fallback */ }

  // Play the entrance animation as soon as the DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', playEnterAnimation);
  } else {
    // Already ready (script at end of body)
    playEnterAnimation();
  }

  // Reset transition lock on page show (back/forward cache)
  window.addEventListener('pageshow', function (e) {
    transitioning = false;
    document.body.classList.remove('_nt-out');
    if (e.persisted) {
      // Page restored from bfcache — replay enter animation
      playEnterAnimation();
    }
  });

})();
