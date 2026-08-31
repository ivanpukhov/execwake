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
    const maxEvents = 50_000;
    const maxEventBytes = 4 * 1024;
    const maxEventFileBytes = 16 * 1024 * 1024;
    let disabled = false;
    let emittedEvents = 0;
    let emitting = false;

    function eventBuffer(event) {
      return Buffer.from(`${JSON.stringify({
        version: 1,
        pid: process.pid,
        monotonicNs: process.hrtime.bigint().toString(),
        ...event,
      })}\n`);
    }

    function write(buffer, maximumSize) {
      if (buffer.length > maxEventBytes) return false;
      const currentSize = fs.fstatSync(descriptor).size;
      if (currentSize + buffer.length > maximumSize) return false;
      return fs.writeSync(descriptor, buffer, 0, buffer.length) === buffer.length;
    }

    function stopWithLoss() {
      if (disabled) return;
      disabled = true;
      try {
        write(eventBuffer({ kind: 'loss', count: 1 }), maxEventFileBytes);
      } catch {
        // The reader also treats a truncated or oversized stream as lost evidence.
      }
    }

    function emit(event) {
      if (disabled || emitting) return;
      emitting = true;
      try {
        if (emittedEvents >= maxEvents) {
          stopWithLoss();
          return;
        }
        const buffer = eventBuffer(event);
        if (!write(buffer, maxEventFileBytes - maxEventBytes)) {
          stopWithLoss();
          return;
        }
        emittedEvents += 1;
      } catch {
        stopWithLoss();
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
      if (typeof value !== 'string' || !value.startsWith('/')) return undefined;
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

    function subscribe(name, callback) {
      try {
        diagnostics.channel(name).subscribe((message) => {
          try {
            callback(message);
          } catch {
            // Malformed channel messages are ignored without affecting the publisher.
          }
        });
      } catch {
        // The traced program continues if a diagnostics channel is unavailable.
      }
    }

    subscribe('http.client.request.start', (message) => {
      const request = message && message.request;
      if (request) emitHttp(request.method, request.host, request.path);
    });

    subscribe('undici:request:create', (message) => {
      const request = message && message.request;
      if (!request) return;
      const origin = new URL(String(request.origin));
      emitHttp(request.method, origin.host, request.path);
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
            !disabled &&
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
