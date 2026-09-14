(() => {
  'use strict';

  const HOME = 'Home';
  const END = 'End';

  function enhanceTablist(selector) {
    const tabs = Array.from(document.querySelectorAll(selector));
    if (tabs.length < 2) return;

    tabs.forEach((tab) => {
      tab.addEventListener('keydown', (event) => {
        if (event.key !== HOME && event.key !== END) return;
        event.preventDefault();

        const target = event.key === HOME ? tabs[0] : tabs[tabs.length - 1];
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
