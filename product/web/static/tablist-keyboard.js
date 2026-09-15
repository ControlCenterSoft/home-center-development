(() => {
  'use strict';

  const HOME = 'Home';
  const END = 'End';
  const PREVIOUS = 'ArrowLeft';
  const NEXT = 'ArrowRight';

  function enhanceTablist(selector) {
    const tabs = Array.from(document.querySelectorAll(selector));
    if (tabs.length < 2) return;

    tabs.forEach((tab) => {
      tab.addEventListener('keydown', (event) => {
        if (![HOME, END, PREVIOUS, NEXT].includes(event.key)) return;
        event.preventDefault();

        let target;
        if (event.key === HOME) {
          target = tabs[0];
        } else if (event.key === END) {
          target = tabs[tabs.length - 1];
        } else {
          const current = tabs.indexOf(tab);
          const offset = event.key === NEXT ? 1 : -1;
          target = tabs[(current + offset + tabs.length) % tabs.length];
        }

        target.click();
        target.focus();
      });
    });
  }

  function init() {
    enhanceTablist('#mode-switch [role="tab"]');
    enhanceTablist('.cozy-nav [role="tab"]');
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init, {once: true});
  } else {
    init();
  }
})();
