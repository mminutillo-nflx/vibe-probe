"""HTTP/HTTPS probe"""

import aiohttp
from typing import Dict, Any
from urllib.parse import urljoin
from .base_probe import BaseProbe


class HTTPProbe(BaseProbe):
    """HTTP/HTTPS reconnaissance"""

    async def scan(self) -> Dict[str, Any]:
        """Perform HTTP reconnaissance"""
        results = {
            "http": {},
            "https": {},
            "findings": [],
            "redirects": []
        }

        # Try both HTTP and HTTPS
        for scheme in ['http', 'https']:
            url = f"{scheme}://{self.target}"
            probe_result = await self._probe_url(url)
            results[scheme] = probe_result

            if probe_result.get("accessible"):
                self._analyze_http_response(scheme, probe_result, results["findings"])

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

        # Check robots.txt
        results["robots_txt"] = await self._check_robots_txt()

        # Check sitemap
        results["sitemap"] = await self._check_sitemap()

        return results

    async def _probe_url(self, url: str) -> Dict[str, Any]:
        """Probe a specific URL"""
        result = {
            "accessible": False,
            "status_code": None,
            "headers": {},
            "server": None,
            "powered_by": None,
            "final_url": None
        }

        try:
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
            result["error"] = str(e)
        except Exception as e:
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
