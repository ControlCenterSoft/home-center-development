(() => {
  'use strict';

  const AUTH_FOCUS_TARGETS = [
    ['login-view', 'password'],
    ['password-view', 'current-password'],
  ];

  function focusVisibleAuthView() {
    for (const [viewId, targetId] of AUTH_FOCUS_TARGETS) {
      const view = document.getElementById(viewId);
      if (!view || view.hidden) continue;
      if (view.contains(document.activeElement)) return;

      const target = document.getElementById(targetId);
      if (target && typeof target.focus === 'function') target.focus();
      return;
    }
  }

  function init() {
    const views = AUTH_FOCUS_TARGETS
      .map(([viewId]) => document.getElementById(viewId))
      .filter(Boolean);
    if (!views.length) return;

    const observer = new MutationObserver(focusVisibleAuthView);
    views.forEach((view) => observer.observe(view, {
      attributes: true,
      attributeFilter: ['hidden'],
    }));
    focusVisibleAuthView();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init, {once: true});
  } else {
    init();
  }
})();
