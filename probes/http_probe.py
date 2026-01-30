"""HTTP/HTTPS probe"""

import aiohttp
import base64
from typing import Dict, Any
from urllib.parse import urljoin
from .base_probe import BaseProbe

# Optional playwright for screenshots
try:
    from playwright.async_api import async_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False


class HTTPProbe(BaseProbe):
    """HTTP/HTTPS reconnaissance"""

    async def scan(self) -> Dict[str, Any]:
        """Perform HTTP reconnaissance"""
        self.logger.info(f"  → Testing HTTP/HTTPS connectivity for {self.target}")

        results = {
            "http": {},
            "https": {},
            "findings": [],
            "redirects": []
        }

        # Test both HTTP and HTTPS endpoints
        for scheme in ['http', 'https']:
            self.logger.info(f"  → Probing {scheme.upper()} endpoint...")
            url = f"{scheme}://{self.target}"
            probe_result = await self._probe_url(url)
            results[scheme] = probe_result

            # Analyze security of accessible endpoints
            if probe_result.get("accessible"):
                self.logger.info(f"  ✓ {scheme.upper()} is accessible (Status: {probe_result.get('status_code')})")
                self._analyze_http_response(scheme, probe_result, results["findings"])
            else:
                self.logger.info(f"  ✗ {scheme.upper()} is not accessible")

        # Check for HTTP to HTTPS redirect
        if results["http"].get("accessible") and results["https"].get("accessible"):
            if results["http"].get("final_url", "").startswith("https"):
                results["findings"].append(
                    self._create_finding(
                        "info",
                        "HTTP redirects to HTTPS",
                        "HTTP traffic is properly redirected to HTTPS"
                    )
                )
            else:
                results["findings"].append(
                    self._create_finding(
                        "high",
                        "No HTTP to HTTPS redirect",
                        "HTTP site does not redirect to HTTPS",
                        recommendation="Implement HTTP to HTTPS redirect"
                    )
                )

        # Check for robots.txt file and analyze directives
        self.logger.info(f"  → Checking robots.txt...")
        results["robots_txt"] = await self._check_robots_txt()

        # Check sitemap
        self.logger.info(f"  → Checking sitemap...")
        results["sitemap"] = await self._check_sitemap()

        # Capture screenshot of homepage
        self.logger.info(f"  → Capturing homepage screenshot...")
        results["screenshot"] = await self._capture_screenshot()

        self.logger.info(f"  ✓ HTTP probe completed")
        return results

    async def _probe_url(self, url: str) -> Dict[str, Any]:
        """Probe a specific URL with timeout protection"""
        result = {
            "accessible": False,
            "status_code": None,
            "headers": {},
            "server": None,
            "powered_by": None,
            "final_url": None
        }

        try:
            # Set 10 second timeout for HTTP requests
            timeout = aiohttp.ClientTimeout(total=10)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url, allow_redirects=True) as response:
                    result["accessible"] = True
                    result["status_code"] = response.status
                    result["headers"] = dict(response.headers)
                    result["server"] = response.headers.get("Server")
                    result["powered_by"] = response.headers.get("X-Powered-By")
                    result["final_url"] = str(response.url)
                    result["content_type"] = response.headers.get("Content-Type")

        except aiohttp.ClientError as e:
            # Network or HTTP protocol errors
            result["error"] = str(e)
        except Exception as e:
            # Catch-all for unexpected errors
            result["error"] = str(e)
            self.logger.debug(f"HTTP probe error for {url}: {e}")

        return result

    def _analyze_http_response(self, scheme: str, probe_result: Dict, findings: List):
        """Analyze HTTP response for security issues"""

        headers = probe_result.get("headers", {})

        # Check for information disclosure
        server = probe_result.get("server")
        if server:
            findings.append(
                self._create_finding(
                    "low",
                    "Server header exposed",
                    f"Server header reveals: {server}",
                    recommendation="Consider hiding or obfuscating server information"
                )
            )

        powered_by = probe_result.get("powered_by")
        if powered_by:
            findings.append(
                self._create_finding(
                    "low",
                    "X-Powered-By header exposed",
                    f"Technology stack revealed: {powered_by}",
                    recommendation="Remove X-Powered-By header"
                )
            )

        # Check for HTTPS availability
        if scheme == "http" and probe_result.get("accessible"):
            findings.append(
                self._create_finding(
                    "info",
                    "HTTP service available",
                    f"Site is accessible via HTTP on {scheme}://{self.target}"
                )
            )

    async def _check_robots_txt(self) -> Dict[str, Any]:
        """Check for robots.txt"""
        result = {"exists": False, "content": None, "findings": []}

        for scheme in ['https', 'http']:
            url = f"{scheme}://{self.target}/robots.txt"
            try:
                timeout = aiohttp.ClientTimeout(total=5)
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    async with session.get(url) as response:
                        if response.status == 200:
                            content = await response.text()
                            result["exists"] = True
                            result["content"] = content[:1000]  # First 1000 chars

                            # Check for interesting paths
                            if "Disallow:" in content:
                                disallowed = [line.split("Disallow:")[1].strip()
                                            for line in content.split("\n")
                                            if line.strip().startswith("Disallow:")]
                                result["findings"].append({
                                    "type": "info",
                                    "message": f"Found {len(disallowed)} disallowed paths",
                                    "data": disallowed[:10]  # First 10 paths
                                })
                            break
            except Exception as e:
                self.logger.debug(f"Error checking robots.txt: {e}")

        return result

    async def _check_sitemap(self) -> Dict[str, Any]:
        """Check for sitemap"""
        result = {"exists": False, "url": None}

        for scheme in ['https', 'http']:
            for sitemap_path in ['/sitemap.xml', '/sitemap_index.xml']:
                url = f"{scheme}://{self.target}{sitemap_path}"
                try:
                    timeout = aiohttp.ClientTimeout(total=5)
                    async with aiohttp.ClientSession(timeout=timeout) as session:
                        async with session.get(url) as response:
                            if response.status == 200:
                                result["exists"] = True
                                result["url"] = url
                                return result
                except Exception:
                    continue

        return result

    async def _capture_screenshot(self) -> Dict[str, Any]:
        """Capture screenshot of homepage"""
        result = {"success": False, "data": None, "error": None}

        if not PLAYWRIGHT_AVAILABLE:
            result["error"] = "Playwright not installed"
            return result

        try:
            # Try HTTPS first, then HTTP
            for scheme in ['https', 'http']:
                url = f"{scheme}://{self.target}"
                try:
                    # Use async context manager for automatic cleanup
                    async with async_playwright() as p:
                        browser = await p.chromium.launch(headless=True)
                        try:
                            context = await browser.new_context(
                                viewport={'width': 1280, 'height': 720},
                                user_agent='Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36'
                            )
                            page = await context.new_page()

                            # Navigate with timeout
                            await page.goto(url, wait_until='networkidle', timeout=15000)

                            # Take screenshot
                            screenshot_bytes = await page.screenshot(full_page=False)

                            # Convert to base64
                            screenshot_base64 = base64.b64encode(screenshot_bytes).decode('utf-8')

                            result["success"] = True
                            result["data"] = screenshot_base64
                            result["url"] = url
                            break

                        finally:
                            # Ensure browser is always closed
                            await browser.close()

                except Exception as e:
                    self.logger.debug(f"Screenshot failed for {url}: {e}")
                    continue

            if not result["success"]:
                result["error"] = "Unable to capture screenshot"

        except Exception as e:
            result["error"] = str(e)
            self.logger.debug(f"Screenshot capture error: {e}")

        return result
