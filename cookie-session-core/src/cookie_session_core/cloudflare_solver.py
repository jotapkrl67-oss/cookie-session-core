from __future__ import annotations

import asyncio
import logging
import re
import time
from contextlib import suppress as _suppress_ctx
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import urlparse

import httpx

from .config import CfSolverProvider, Settings
from .metrics import metrics

logger = logging.getLogger("cookie_session_core.cloudflare_solver")


_CF_TURNSTILE_SITEKEY_RE = re.compile(
    r"""['"]?sitekey['"]?\s*[:=]\s*['"]([0-9A-Za-z_-]{20,})['"]""",
    re.IGNORECASE,
)
_CF_RAY_RE = re.compile(r"cf-ray=([0-9a-fA-F-]+)")
_CF_CHALLENGE_FORM_RE = re.compile(
    r'<form[^>]*id=["\']challenge-form["\'][^>]*action=["\']([^"\']+)["\'][^>]*>',
    re.IGNORECASE | re.DOTALL,
)
_CF_R_TOKEN_RE = re.compile(r'name=["\']r["\'][^>]*value=["\']([^"\']*)["\']')
_CF_VERIFY_RE = re.compile(r"window\.__cf_chl_rt\s*=\s*['\"]([^'\"]+)['\"]")


@dataclass
class CfChallengeInfo:
    url: str
    domain: str
    status: int
    body: bytes
    headers: Any
    sitekey: str | None = None
    ray_id: str | None = None
    form_action: str | None = None
    r_token: str | None = None
    cf_chl_rt: str | None = None


@dataclass
class CfSolveResult:
    success: bool
    provider: CfSolverProvider
    cf_clearance: str | None = None
    clearance_ttl: int | None = None
    turnstile_token: str | None = None
    error: str | None = None
    raw: dict[str, Any] | None = None

    def log_summary(self) -> None:
        if self.success:
            parts = [f"provider={self.provider.value}"]
            if self.cf_clearance:
                parts.append("cf_clearance=obtained")
                if self.clearance_ttl:
                    parts.append(f"ttl={self.clearance_ttl}s")
            if self.turnstile_token:
                parts.append("turnstile=obtained")
            logger.info("Cloudflare solve OK: %s", " ".join(parts))
        else:
            logger.warning(
                "Cloudflare solve FAILED provider=%s error=%s",
                self.provider.value,
                self.error,
            )


def extract_challenge_info(url: str, status: int, body: bytes, headers: Any) -> CfChallengeInfo:
    domain = (urlparse(url).hostname or "").lower()
    text = body.decode("utf-8", errors="replace")

    sitekey: str | None = None
    m = _CF_TURNSTILE_SITEKEY_RE.search(text)
    if m:
        sitekey = m.group(1)
    else:
        for pattern in (
            r"render/([0-9A-Za-z_-]{20,})",
            r"cf-turnstile[^>]*\bdata-sitekey=['\"]([^'\"]+)['\"]",
        ):
            m2 = re.search(pattern, text, re.IGNORECASE)
            if m2:
                sitekey = m2.group(1)
                break

    ray_id: str | None = None
    hdr_ray = (
        getattr(headers, "get", lambda _k: None)("cf-ray") if hasattr(headers, "get") else None
    )
    if hdr_ray:
        ray_id = str(hdr_ray).split("-")[0] if "-" in str(hdr_ray) else str(hdr_ray)
    else:
        m3 = _CF_RAY_RE.search(text)
        if m3:
            ray_id = m3.group(1)

    form_action: str | None = None
    m4 = _CF_CHALLENGE_FORM_RE.search(text)
    if m4:
        form_action = m4.group(1)

    r_token: str | None = None
    m5 = _CF_R_TOKEN_RE.search(text)
    if m5:
        r_token = m5.group(1)

    cf_chl_rt: str | None = None
    m6 = _CF_VERIFY_RE.search(text)
    if m6:
        cf_chl_rt = m6.group(1)

    return CfChallengeInfo(
        url=url,
        domain=domain,
        status=status,
        body=body,
        headers=headers,
        sitekey=sitekey,
        ray_id=ray_id,
        form_action=form_action,
        r_token=r_token,
        cf_chl_rt=cf_chl_rt,
    )


class CfChallengeSolver(Protocol):
    provider: CfSolverProvider

    async def solve(
        self,
        info: CfChallengeInfo,
        *,
        timeout: float,
    ) -> CfSolveResult: ...


class _BaseApiSolver:
    def __init__(self, api_key: str, endpoint: str, http_client: httpx.AsyncClient | None = None):
        self.api_key = api_key
        self.endpoint = endpoint.rstrip("/")
        self._owns_client = http_client is None
        self._http = http_client or httpx.AsyncClient(timeout=60.0)

    async def aclose(self) -> None:
        if self._owns_client and self._http is not None:
            with _suppress_ctx(Exception):
                await self._http.aclose()

    @staticmethod
    def _make_payload(info: CfChallengeInfo, **extra: Any) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "websiteURL": info.url,
            "websiteKey": info.sitekey or "0x4AAAAAAAC3DHQRLN9Gjjtg",
            "pageAction": "managed",
            "metadata": {"ray": info.ray_id or ""},
        }
        payload.update(extra)
        return payload

    async def _poll_until(
        self,
        *,
        create_url: str,
        create_payload: dict[str, Any],
        result_url: str,
        poll_field: str,
        timeout: float,
        poll_interval: float = 2.0,
        result_task_field: str = "taskId",
    ) -> CfSolveResult:
        t0 = time.monotonic()
        create_payload["clientKey"] = self.api_key
        try:
            resp = await self._http.post(
                create_url, json=create_payload, timeout=min(30.0, timeout)
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:
            return CfSolveResult(
                success=False,
                provider=self.provider,
                error=f"create request failed: {exc}",
            )
        if not data:
            return CfSolveResult(
                success=False, provider=self.provider, error="empty create response"
            )
        task_id = data.get(result_task_field) or data.get("taskId") or data.get("requestId")
        if not task_id:
            err = data.get("errorDescription") or data.get("error") or str(data)
            return CfSolveResult(success=False, provider=self.provider, error=f"no task id: {err}")
        deadline = t0 + timeout
        poll_payload = {"clientKey": self.api_key, poll_field: task_id}
        last_result: dict[str, Any] | None = None
        while time.monotonic() < deadline:
            try:
                r = await self._http.post(result_url, json=poll_payload, timeout=min(30.0, timeout))
                r.raise_for_status()
                last_result = r.json()
            except Exception:
                await asyncio.sleep(poll_interval)
                continue
            status = str(last_result.get("status") or "").lower()
            if status in {"ready", "success"}:
                solution = last_result.get("solution") or {}
                cf_clearance = None
                cookies = solution.get("cookies") or []
                for c in cookies:
                    if isinstance(c, dict) and str(c.get("name", "")).lower() == "cf_clearance":
                        cf_clearance = str(c.get("value", ""))
                        break
                if not cf_clearance:
                    cf_clearance = (
                        solution.get("cf_clearance") or last_result.get("cf_clearance") or None
                    )
                turnstile = (
                    solution.get("token")
                    or solution.get("gRecaptchaResponse")
                    or last_result.get("token")
                    or None
                )
                ttl = None
                for c in cookies or []:
                    if isinstance(c, dict) and str(c.get("name", "")).lower() == "cf_clearance":
                        ma = c.get("maxAge") or c.get("max_age")
                        if ma:
                            try:
                                ttl = int(ma)
                            except (TypeError, ValueError):
                                ttl = None
                        break
                return CfSolveResult(
                    success=True,
                    provider=self.provider,
                    cf_clearance=cf_clearance,
                    clearance_ttl=ttl,
                    turnstile_token=turnstile,
                    raw=last_result,
                )
            if status in {"processing", "idle", "waiting", "queued"}:
                await asyncio.sleep(poll_interval)
                continue
            err = (
                last_result.get("errorDescription") or last_result.get("error") or str(last_result)
            )
            return CfSolveResult(
                success=False, provider=self.provider, error=f"solve failed: {err}"
            )
        return CfSolveResult(
            success=False,
            provider=self.provider,
            error=f"timeout after {timeout:.0f}s; last={last_result}",
        )


class CapSolver(_BaseApiSolver):
    provider = CfSolverProvider.CAPSOLVER

    DEFAULT_ENDPOINT = "https://api.capsolver.com"

    def __init__(
        self,
        api_key: str,
        endpoint: str | None = None,
        http_client: httpx.AsyncClient | None = None,
    ):
        super().__init__(api_key, endpoint or self.DEFAULT_ENDPOINT, http_client)

    async def solve(self, info: CfChallengeInfo, *, timeout: float) -> CfSolveResult:
        task_type = "AntiCloudflareTask" if not info.sitekey else "CloudflareTurnstileTask"
        task = self._make_payload(info, type=task_type)
        if info.sitekey:
            task["websiteKey"] = info.sitekey
        payload = {"clientKey": self.api_key, "task": task, "appId": None}
        return await self._poll_until(
            create_url=f"{self.endpoint}/createTask",
            create_payload=payload,
            result_url=f"{self.endpoint}/getTaskResult",
            poll_field="taskId",
            timeout=timeout,
            result_task_field="taskId",
        )


class AntiCaptcha(_BaseApiSolver):
    provider = CfSolverProvider.ANTICAPTCHA

    DEFAULT_ENDPOINT = "https://api.anti-captcha.com"

    def __init__(
        self,
        api_key: str,
        endpoint: str | None = None,
        http_client: httpx.AsyncClient | None = None,
    ):
        super().__init__(api_key, endpoint or self.DEFAULT_ENDPOINT, http_client)

    async def solve(self, info: CfChallengeInfo, *, timeout: float) -> CfSolveResult:
        task_type = "AntiCloudflareTask" if not info.sitekey else "TurnstileTask"
        task = self._make_payload(info, type=task_type)
        if info.sitekey:
            task["websiteKey"] = info.sitekey
        payload = {"clientKey": self.api_key, "task": task}
        return await self._poll_until(
            create_url=f"{self.endpoint}/createTask",
            create_payload=payload,
            result_url=f"{self.endpoint}/getTaskResult",
            poll_field="taskId",
            timeout=timeout,
            result_task_field="taskId",
        )


class YesCaptcha(_BaseApiSolver):
    provider = CfSolverProvider.YESCAPTCHA

    DEFAULT_ENDPOINT = "https://api.yescaptcha.com"

    def __init__(
        self,
        api_key: str,
        endpoint: str | None = None,
        http_client: httpx.AsyncClient | None = None,
    ):
        super().__init__(api_key, endpoint or self.DEFAULT_ENDPOINT, http_client)

    async def solve(self, info: CfChallengeInfo, *, timeout: float) -> CfSolveResult:
        task_type = "AntiCloudflareTask" if not info.sitekey else "TurnstileTaskProxyless"
        task = self._make_payload(info, type=task_type)
        if info.sitekey:
            task["websiteKey"] = info.sitekey
        payload = {"clientKey": self.api_key, "task": task}
        return await self._poll_until(
            create_url=f"{self.endpoint}/createTask",
            create_payload=payload,
            result_url=f"{self.endpoint}/getTaskResult",
            poll_field="taskId",
            timeout=timeout,
            result_task_field="taskId",
        )


class TwoCaptcha(_BaseApiSolver):
    provider = CfSolverProvider.TWOCAPTCHA

    DEFAULT_ENDPOINT = "https://2captcha.com"

    def __init__(
        self,
        api_key: str,
        endpoint: str | None = None,
        http_client: httpx.AsyncClient | None = None,
    ):
        super().__init__(api_key, endpoint or self.DEFAULT_ENDPOINT, http_client)

    async def solve(self, info: CfChallengeInfo, *, timeout: float) -> CfSolveResult:
        task_type = "cloudflare_new" if not info.sitekey else "turnstile"
        method_payload: dict[str, Any] = {
            "key": self.api_key,
            "method": task_type,
            "pageurl": info.url,
            "json": 1,
            "soft_id": 2622,
        }
        if info.sitekey:
            method_payload["sitekey"] = info.sitekey
        if info.ray_id:
            method_payload["ray"] = info.ray_id
        t0 = time.monotonic()
        try:
            resp = await self._http.post(
                f"{self.endpoint}/in.php", data=method_payload, timeout=min(30.0, timeout)
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:
            return CfSolveResult(
                success=False,
                provider=self.provider,
                error=f"in.php failed: {exc}",
            )
        if data.get("status") not in (1, "1"):
            err = data.get("request") or data.get("error_text") or str(data)
            return CfSolveResult(success=False, provider=self.provider, error=f"create: {err}")
        task_id = data.get("request")
        if not task_id or not str(task_id).isdigit():
            return CfSolveResult(
                success=False, provider=self.provider, error=f"bad task id: {task_id}"
            )
        deadline = t0 + timeout
        while time.monotonic() < deadline:
            await asyncio.sleep(2.0)
            try:
                r = await self._http.get(
                    f"{self.endpoint}/res.php",
                    params={
                        "key": self.api_key,
                        "action": "get",
                        "id": task_id,
                        "json": 1,
                    },
                    timeout=min(30.0, timeout),
                )
                r.raise_for_status()
                result = r.json()
            except Exception as exc:
                logger.debug("Solver returned a non-JSON status response: %s", type(exc).__name__)
                continue
            status = result.get("status")
            if status in (1, "1"):
                req = result.get("request") or {}
                cf_clearance = None
                ttl = None
                turnstile = None
                if isinstance(req, dict):
                    cookies = req.get("cookies") or {}
                    cf_clearance = cookies.get("cf_clearance") or req.get("cf_clearance") or None
                    ttl = cookies.get("expire") or req.get("expire")
                    if ttl:
                        try:
                            ttl = int(ttl)
                        except (TypeError, ValueError):
                            ttl = None
                    turnstile = req.get("token") or req.get("turnstile")
                elif isinstance(req, str) and len(req) > 50:
                    turnstile = req
                return CfSolveResult(
                    success=True,
                    provider=self.provider,
                    cf_clearance=cf_clearance,
                    clearance_ttl=ttl,
                    turnstile_token=turnstile,
                    raw=result,
                )
            if status in (0, "0") and str(result.get("request", "")) not in {
                "CAPCHA_NOT_READY",
                "CAPTCHA_NOT_READY",
            }:
                err = result.get("request") or str(result)
                return CfSolveResult(success=False, provider=self.provider, error=f"poll: {err}")
        return CfSolveResult(
            success=False, provider=self.provider, error=f"timeout after {timeout:.0f}s"
        )


class CustomEndpointSolver(_BaseApiSolver):
    provider = CfSolverProvider.CUSTOM

    def __init__(
        self,
        api_key: str,
        endpoint: str,
        http_client: httpx.AsyncClient | None = None,
    ):
        if not endpoint:
            raise ValueError("CUSTOM solver requires cf_solver_api_endpoint")
        super().__init__(api_key, endpoint, http_client)

    async def solve(self, info: CfChallengeInfo, *, timeout: float) -> CfSolveResult:
        payload = {
            "clientKey": self.api_key,
            "url": info.url,
            "domain": info.domain,
            "sitekey": info.sitekey,
            "ray": info.ray_id,
            "body": info.body.decode("utf-8", errors="replace")[:100_000],
        }
        try:
            resp = await self._http.post(self.endpoint, json=payload, timeout=timeout)
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:
            return CfSolveResult(
                success=False,
                provider=self.provider,
                error=f"custom endpoint failed: {exc}",
            )
        if isinstance(data, dict) and (
            data.get("success") or data.get("status") in {"ready", "success", 1}
        ):
            solution = data.get("solution") or data
            return CfSolveResult(
                success=True,
                provider=self.provider,
                cf_clearance=solution.get("cf_clearance") or data.get("cf_clearance"),
                clearance_ttl=solution.get("ttl") or data.get("ttl"),
                turnstile_token=solution.get("token") or data.get("token"),
                raw=data,
            )
        err = (
            data.get("error")
            or data.get("errorDescription")
            or data.get("message")
            or str(data)[:200]
        )
        return CfSolveResult(success=False, provider=self.provider, error=err)


_SOLVER_CTORS: dict[CfSolverProvider, type[_BaseApiSolver]] = {
    CfSolverProvider.CAPSOLVER: CapSolver,
    CfSolverProvider.ANTICAPTCHA: AntiCaptcha,
    CfSolverProvider.YESCAPTCHA: YesCaptcha,
    CfSolverProvider.TWOCAPTCHA: TwoCaptcha,
    CfSolverProvider.CUSTOM: CustomEndpointSolver,
}


class CloudflareSolverOrchestrator:
    """Coordinates provider selection, retries, and clearance injection.

    This class does NOT use a browser or any JS runtime. It:

      1. Parses challenge HTML for sitekey / ray / form metadata.
      2. Calls a configured third-party solving service over pure HTTP APIs
         (CapSolver, AntiCaptcha, YesCaptcha, 2Captcha, or a custom endpoint).
      3. Polls that API until it returns a cf_clearance cookie and/or
         turnstile token.
      4. Stores the cf_clearance into the caller-provided ClearanceCache so
         every subsequent request to the same host automatically carries it.

    If no provider is configured (CF_SOLVER_PROVIDER=none / empty API key) the
    orchestrator is a no-op and returns success=False with a descriptive
    error.
    """

    def __init__(self, settings: Settings, clearance_cache: Any):
        self.settings = settings
        self.clearance = clearance_cache
        self._solvers: dict[CfSolverProvider, CfChallengeSolver] = {}
        self._solver_lock = asyncio.Lock()
        self._challenge_lock = asyncio.Lock()
        self._inflight: dict[tuple[str, str], asyncio.Task[CfSolveResult]] = {}
        self._solved_challenges: dict[tuple[str, str], tuple[float, CfSolveResult]] = {}

    async def aclose(self) -> None:
        async with self._solver_lock:
            for solver in self._solvers.values():
                if hasattr(solver, "aclose"):
                    with _suppress_ctx(Exception):
                        await solver.aclose()
            self._solvers.clear()

    async def _get_solver(self, provider: CfSolverProvider) -> CfChallengeSolver | None:
        if provider == CfSolverProvider.NONE:
            return None
        api_key = self.settings.cf_solver_api_keys.get(
            provider.value, self.settings.cf_solver_api_key
        )
        if not api_key and provider != CfSolverProvider.CUSTOM:
            logger.warning(
                "cf_solver_provider=%s but cf_solver_api_key is empty — skipping solver",
                provider.value,
            )
            return None
        async with self._solver_lock:
            if provider not in self._solvers:
                ctor = _SOLVER_CTORS.get(provider)
                if ctor is None:
                    return None
                endpoint = (
                    str(self.settings.cf_solver_api_endpoint)
                    if self.settings.cf_solver_api_endpoint
                    else None
                )
                try:
                    self._solvers[provider] = ctor(
                        api_key=api_key,
                        endpoint=endpoint,
                    )
                except Exception as exc:
                    logger.error("Failed to construct %s solver: %s", provider.value, exc)
                    return None
            return self._solvers.get(provider)

    async def try_solve(
        self,
        url: str,
        status: int,
        body: bytes,
        headers: Any,
    ) -> CfSolveResult:
        info = extract_challenge_info(url, status, body, headers)
        key = (info.domain, info.ray_id or f"status:{status}")
        now = time.monotonic()
        async with self._challenge_lock:
            cached = self._solved_challenges.get(key)
            if cached and cached[0] > now:
                return cached[1]
            task = self._inflight.get(key)
            if task is None:
                task = asyncio.create_task(self._try_solve_info(info))
                self._inflight[key] = task
        try:
            result = await asyncio.shield(task)
        finally:
            async with self._challenge_lock:
                if self._inflight.get(key) is task and task.done():
                    self._inflight.pop(key, None)
        if result.success:
            async with self._challenge_lock:
                self._solved_challenges[key] = (time.monotonic() + 300.0, result)
        return result

    async def _try_solve_info(self, info: CfChallengeInfo) -> CfSolveResult:
        providers = self.settings.solver_provider_list
        if not providers:
            return CfSolveResult(
                success=False,
                provider=self.settings.cf_solver_provider,
                error="no solver configured",
            )
        last: CfSolveResult | None = None
        for provider in providers:
            solver = await self._get_solver(provider)
            if solver is None:
                logger.warning("Cloudflare provider unavailable provider=%s", provider.value)
                continue
            timeout = float(
                self.settings.cf_solver_provider_timeouts.get(
                    provider.value, self.settings.cf_solver_timeout_seconds
                )
            )
            logger.info(
                "Starting Cloudflare solve domain=%s ray=%s provider=%s timeout=%ss",
                info.domain,
                info.ray_id,
                provider.value,
                timeout,
            )
            for attempt in range(1, max(1, self.settings.cf_solver_max_retries) + 1):
                metrics.increment("cf_solver_calls")
                try:
                    last = await asyncio.wait_for(
                        solver.solve(info, timeout=timeout), timeout=timeout + 1.0
                    )
                except TimeoutError:
                    last = CfSolveResult(
                        success=False,
                        provider=provider,
                        error=f"provider timeout after {timeout:.0f}s",
                    )
                last.log_summary()
                if last.success:
                    metrics.increment("cf_solver_success")
                    if last.cf_clearance and info.domain:
                        ttl = last.clearance_ttl or 2700
                        self.clearance.set(info.domain, last.cf_clearance, ttl=ttl)
                    return last
                metrics.increment("cf_solver_errors")
                logger.warning(
                    "Cloudflare provider failed provider=%s attempt=%s error=%s; trying fallback",
                    provider.value,
                    attempt,
                    last.error,
                )
                if attempt < max(1, self.settings.cf_solver_max_retries):
                    await asyncio.sleep(1.0 * attempt)
        return last or CfSolveResult(
            success=False,
            provider=providers[-1],
            error="solver exhausted retries",
        )
