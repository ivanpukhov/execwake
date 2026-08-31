'use strict';

const diagnostics = require('node:diagnostics_channel');
const fs = require('node:fs');

const controlName = 'EXECWAKE_NODE_EVENT_FILE';
const originalEnvironment = process.env;
const eventPath = originalEnvironment[controlName];

if (eventPath) {
  let descriptor;
  try {
    descriptor = fs.openSync(eventPath, 'a', 0o600);
  } catch {
    descriptor = undefined;
  }

  if (descriptor !== undefined) {
    let emitting = false;

    function emit(event) {
      if (emitting) return;
      emitting = true;
      try {
        const line = `${JSON.stringify({
          version: 1,
          pid: process.pid,
          monotonicNs: process.hrtime.bigint().toString(),
          ...event,
        })}\n`;
        if (Buffer.byteLength(line) <= 4096) fs.writeSync(descriptor, line);
      } catch {
        // Enrichment must not change the traced program's error path.
      } finally {
        emitting = false;
      }
    }

    function cleanMethod(value) {
      if (typeof value !== 'string' || value.length === 0 || value.length > 32) return undefined;
      if (!/^[A-Za-z0-9!#$%&'*+\-.^_`|~]+$/.test(value)) return undefined;
      return value.toUpperCase();
    }

    function cleanHost(value) {
      if (typeof value !== 'string' || value.length === 0 || value.length > 1024) return undefined;
      if (/[\s\u0000-\u001f\u007f\\/@?#]/.test(value)) return undefined;
      return value.toLowerCase();
    }

    function cleanPath(value) {
      if (typeof value !== 'string' || !value.startsWith('/')) return '/';
      const boundary = value.search(/[?#]/);
      const path = boundary === -1 ? value : value.slice(0, boundary);
      if (path.length > 2048 || /[\u0000-\u001f\u007f\\]/.test(path)) return undefined;
      return path || '/';
    }

    function emitHttp(methodValue, hostValue, pathValue) {
      const method = cleanMethod(methodValue);
      const host = cleanHost(hostValue);
      const path = cleanPath(pathValue);
      if (method && host && path) emit({ kind: 'http', method, host, path });
    }

    diagnostics.channel('http.client.request.start').subscribe(({ request }) => {
      emitHttp(request.method, request.host, request.path);
    });

    diagnostics.channel('undici:request:create').subscribe(({ request }) => {
      try {
        const origin = new URL(String(request.origin));
        emitHttp(request.method, origin.host, request.path);
      } catch {
        // Invalid runtime metadata is omitted rather than approximated.
      }
    });

    const seenEnvironmentNames = new Set();
    try {
      process.env = new Proxy(originalEnvironment, {
        get(target, property) {
          if (
            typeof property === 'string' &&
            property !== controlName &&
            property.length <= 1024 &&
            !property.includes('=') &&
            !/[\u0000-\u001f\u007f]/.test(property) &&
            !seenEnvironmentNames.has(property)
          ) {
            seenEnvironmentNames.add(property);
            emit({ kind: 'environment', name: property });
          }
          return Reflect.get(target, property, target);
        },
      });
    } catch {
      // HTTP diagnostics remain active if process.env cannot be wrapped.
    }
  }
}
