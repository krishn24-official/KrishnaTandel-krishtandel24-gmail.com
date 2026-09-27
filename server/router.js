// Router implementation
const PARAM = /^:(.+)$/;

// Create HTTP router
export function createRouter() {
  const routes = [];

  // Register route
  function add(method, pattern, handler) {
    routes.push({ method, segments: split(pattern), handler });
  }

  // Match route
  function match(method, pathname) {
    const parts = split(pathname);

    for (const r of routes) {
      if (r.method !== method || r.segments.length !== parts.length) continue;

      const params = {};
      let ok = true;

      for (let i = 0; i < r.segments.length; i++) {
        const seg = r.segments[i];
        const param = PARAM.exec(seg);
        if (param) {
          params[param[1]] = decodeURIComponent(parts[i]);
        } else if (seg !== parts[i]) {
          ok = false;
          break;
        }
      }

      if (ok) return { handler: r.handler, params, pattern: r.segments.length ? '/' + r.segments.join('/') : '/' };
    }

    return null;
  }

  return {
    get: (p, h) => add('GET', p, h),
    post: (p, h) => add('POST', p, h),
    patch: (p, h) => add('PATCH', p, h),
    delete: (p, h) => add('DELETE', p, h),
    match,
    get routes() { return routes; },
  };
}

// Split URL path
function split(path) {
  return path.split('/').filter(Boolean);
}
