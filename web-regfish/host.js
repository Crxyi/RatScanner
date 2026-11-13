"use strict";
(() => {
  if (window.parent === window) return;
  const worker = new Worker("/worker.js?v=15");
  const channel = new MessageChannel();
  worker.postMessage({ cmd: "port" }, [channel.port2]);
  worker.onerror = e => parent.postMessage({ type: "rs-engine-crash", error: e.message || "Scanner crashed" }, location.origin);
  parent.postMessage({ type: "rs-engine" }, location.origin, [channel.port1]);
})();
