/** Browser SSH terminal (xterm.js) over the Device Access Gateway WebSocket.
 *  The browser never talks to the device and never sees a credential: it asks the gateway for a one-time ticket
 *  (POST /api/nms/access/devices/{id}/sessions), opens /api/nms/access/ws, and sends the ticket as its first message. */
import { useEffect, useRef, useState } from "react";
import { Terminal as XTerm } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import "@xterm/xterm/css/xterm.css";
import { api } from "../../lib/api";

export type TermState = "connecting" | "connected" | "closed" | "failed";

export function wsUrl(path: string, loc: { protocol: string; host: string } = window.location): string {
  return `${loc.protocol === "https:" ? "wss" : "ws"}://${loc.host}${path}`;
}

export function DeviceTerminal({ sid, mode = "read_only", changeId, protocol = "ssh", consolePortId, onState, onSession }: {
  sid: number; mode?: "read_only" | "change"; changeId?: number; protocol?: "ssh" | "telnet" | "console"; consolePortId?: number;
  onState?: (s: TermState, reason?: string) => void; onSession?: (id: string) => void;
}) {
  const host = useRef<HTMLDivElement>(null);
  const term = useRef<XTerm | null>(null);
  const sock = useRef<WebSocket | null>(null);
  const log = useRef<string[]>([]);
  const [state, setState] = useState<TermState>("connecting");
  const [reason, setReason] = useState("");
  const [info, setInfo] = useState<{ session?: string; latency?: number; recording?: string; cleartext?: boolean }>({});
  const [gen, setGen] = useState(0);              // bump to reconnect with a new session

  const update = (s: TermState, r = "") => { setState(s); setReason(r); onState?.(s, r); };

  useEffect(() => {
    const t = new XTerm({ cursorBlink: true, fontSize: 13, fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace", scrollback: 5000, convertEol: false });
    const fit = new FitAddon();
    t.loadAddon(fit);
    term.current = t;
    if (host.current) { t.open(host.current); try { fit.fit(); } catch { /* not visible yet */ } }
    let closed = false;
    update("connecting");
    t.writeln("\x1b[90mRequesting a session from the access gateway…\x1b[0m");
    (async () => {
      let s: any;
      try {
        s = await api<any>(`/nms/access/devices/${sid}/sessions`, { method: "POST", body: { mode, change_id: changeId, protocol, console_port_id: consolePortId, cols: t.cols, rows: t.rows } });
      } catch (e) {
        t.writeln(`\x1b[31m${(e as Error).message}\x1b[0m`);
        update("failed", (e as Error).message);
        return;
      }
      if (closed) {   // unmounted while the ticket was being issued: give the session back instead of leaving it pending
        api(`/nms/access/sessions/${s.session_id}/terminate`, { method: "POST" }).catch(() => undefined);
        return;
      }
      setInfo({ session: s.session_id, recording: s.recording });
      onSession?.(s.session_id);
      const ws = new WebSocket(wsUrl(s.ws_path));
      sock.current = ws;
      ws.onopen = () => ws.send(JSON.stringify({ t: "auth", session: s.session_id, ticket: s.ticket, cols: t.cols, rows: t.rows }));
      ws.onmessage = (ev) => {
        let m: any;
        try { m = JSON.parse(ev.data); } catch { return; }
        if (m.t === "o") { t.write(m.d); log.current.push(m.d); if (log.current.length > 20000) log.current.splice(0, 5000); }
        else if (m.t === "status") { setInfo((x) => ({ ...x, latency: m.latency_ms, cleartext: m.cleartext })); update("connected"); t.focus(); }
        else if (m.t === "blocked") t.write(`\r\n\x1b[41;97m blocked \x1b[0m \x1b[33m${m.risk}: ${m.reason}\x1b[0m\r\n`);
        else if (m.t === "closed") { t.writeln(`\r\n\x1b[90m[session closed: ${m.reason}]\x1b[0m`); update("closed", m.reason); }
      };
      ws.onclose = () => { setState((cur) => { if (cur === "connecting" || cur === "connected") onState?.("closed", "connection closed"); return cur === "failed" ? cur : "closed"; }); };
      t.onData((d) => { if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ t: "i", d })); });
      t.onResize(({ cols, rows }) => { if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ t: "r", cols, rows })); });
    })();
    const ro = new ResizeObserver(() => { if (host.current && host.current.offsetWidth > 0) { try { fit.fit(); } catch { /* not measurable yet */ } } });
    if (host.current) ro.observe(host.current);
    const ping = window.setInterval(() => { if (sock.current?.readyState === WebSocket.OPEN) sock.current.send(JSON.stringify({ t: "ping" })); }, 25000);
    return () => {
      closed = true;
      window.clearInterval(ping);
      ro.disconnect();
      try { sock.current?.send(JSON.stringify({ t: "close" })); } catch { /* already closed */ }
      sock.current?.close();
      // xterm queues viewport refreshes on timers; disposing synchronously (React unmount, StrictMode re-mount) lets one fire
      // on a disposed renderer ("reading 'dimensions'"), so dispose after the queue has drained
      window.setTimeout(() => t.dispose(), 250);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sid, mode, changeId, protocol, consolePortId, gen]);

  const text = () => log.current.join("").replace(/\x1b\[[0-9;?]*[A-Za-z]/g, "").replace(/\r/g, "");
  const copy = async () => { const sel = term.current?.getSelection(); await navigator.clipboard?.writeText(sel || text()); };
  const download = () => {
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([text()], { type: "text/plain" }));
    a.download = `session-${info.session || sid}.txt`;
    a.click();
    URL.revokeObjectURL(a.href);
  };
  const disconnect = () => { try { sock.current?.send(JSON.stringify({ t: "close" })); } catch { /* closed */ } };

  return <div className="space-y-2">
    <div className="flex flex-wrap items-center gap-2 text-xs">
      <span className={`pill ${state === "connected" ? "text-emerald-300" : state === "connecting" ? "bg-slate-800 text-slate-300" : "text-red-300"}`}>{state}</span>
      {mode === "change" && <span className="pill text-amber-300">change session #{changeId}</span>}
      {protocol !== "ssh" && <span className="pill bg-slate-800 text-slate-300">{protocol}</span>}
      {info.cleartext && <span className="pill text-red-300" title="Telnet sends the login and everything typed unencrypted">clear text</span>}
      {info.latency != null && <span className="text-muted">login {info.latency} ms</span>}
      {info.recording && <span className="text-muted">recording: {info.recording}</span>}
      {reason && state !== "connected" && <span className="text-muted truncate max-w-[28rem]" title={reason}>{reason}</span>}
      <span className="ml-auto flex gap-2">
        <button className="btn py-0.5" onClick={copy}>Copy</button>
        <button className="btn py-0.5" onClick={download}>Download</button>
        {state === "connected" ? <button className="btn py-0.5" onClick={disconnect}>Disconnect</button>
          : state !== "connecting" && <button className="btn py-0.5" onClick={() => setGen((g) => g + 1)}>Reconnect</button>}
      </span>
    </div>
    <div ref={host} className="h-[28rem] w-full rounded-md border border-line bg-slate-950 p-1" aria-label="Device terminal" />
    <p className="text-[11px] text-muted">Read-only session: commands that change the configuration, clear state or reboot are blocked by the gateway
      (the device's own AAA still applies). Lines recalled with ↑ / ↓ or edited with ← / → are refused; press Ctrl-U and type them again.</p>
  </div>;
}

export default DeviceTerminal;
