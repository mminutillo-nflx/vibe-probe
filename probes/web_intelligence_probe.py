"""Web intelligence gathering probe"""

import aiohttp
from datetime import datetime, timedelta
from typing import Dict, Any, List
from .base_probe import BaseProbe


class WebIntelProbe(BaseProbe):
    """Web intelligence gathering from news, articles, and search results"""

    TRUSTED_SOURCES = [
        'reuters.com', 'bbc.com', 'cnn.com', 'theguardian.com',
        'nytimes.com', 'wsj.com', 'bloomberg.com', 'forbes.com',
        'techcrunch.com', 'wired.com', 'arstechnica.com',
        'krebsonsecurity.com', 'bleepingcomputer.com', 'threatpost.com',
        'securityweek.com', 'darkreading.com'
    ]

    async def scan(self) -> Dict[str, Any]:
        """Gather web intelligence"""
        results = {
            "news_articles": [],
            "blog_posts": [],
            "security_mentions": [],
            "findings": []
        }

        # Search for news articles
        results["news_articles"] = await self._search_news()

        # Search for security-related content
        results["security_mentions"] = await self._search_security_content()

        # Search for general web content
        results["blog_posts"] = await self._search_web_content()

        # Analyze and prioritize findings
        self._analyze_intelligence(results)

        return results

    async def _search_news(self) -> List[Dict[str, Any]]:
        """Search for news articles about the target domain"""
        articles = []

        # Check if NewsAPI key is available
        api_key = self.config.get_api_key("newsapi")
        if not api_key:
            self.logger.debug("NewsAPI key not found, skipping news search")
            return articles

        try:
            url = "https://newsapi.org/v2/everything"
            params = {
                "q": self.target,
                "sortBy": "publishedAt",
                "language": "en",
                "pageSize": 20,
                "apiKey": api_key
            }

            timeout = aiohttp.ClientTimeout(total=15)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        for article in data.get("articles", []):
                            # Calculate recency score
                            published = datetime.fromisoformat(
                                article["publishedAt"].replace("Z", "+00:00")
                            )
                            days_old = (datetime.now(published.tzinfo) - published).days

                            # Calculate trust score based on source
                            source_domain = self._extract_domain(article.get("url", ""))
                            trust_score = 10 if any(trusted in source_domain
                                                   for trusted in self.TRUSTED_SOURCES) else 5

                            articles.append({
                                "title": article.get("title"),
                                "description": article.get("description"),
                                "url": article.get("url"),
                                "source": article.get("source", {}).get("name"),
                                "published_at": article.get("publishedAt"),
                                "days_old": days_old,
                                "trust_score": trust_score,
                                "recency_score": max(0, 10 - (days_old / 7))  # Decay over weeks
                            })

        except Exception as e:
            self.logger.debug(f"Error searching news: {e}")

        return sorted(articles, key=lambda x: (x["trust_score"], x["recency_score"]), reverse=True)

    async def _search_security_content(self) -> List[Dict[str, Any]]:
        """Search for security-related mentions"""
        security_content = []

        # Search terms focused on security
        security_terms = [
            f"{self.target} vulnerability",
            f"{self.target} breach",
            f"{self.target} security",
            f"{self.target} hack",
            f"{self.target} exploit",
            f"{self.target} CVE"
        ]

        for term in security_terms:
            try:
                # Using a simple web search approach
                # In production, you'd use Google Custom Search API or similar
                results = await self._web_search(term, security_focused=True)
                security_content.extend(results)
            except Exception as e:
                self.logger.debug(f"Error searching security content for '{term}': {e}")

        # Deduplicate and sort by relevance
        seen_urls = set()
        unique_content = []
        for item in security_content:
            if item["url"] not in seen_urls:
                seen_urls.add(item["url"])
                unique_content.append(item)

        return sorted(unique_content, key=lambda x: x.get("relevance_score", 0), reverse=True)

    async def _search_web_content(self) -> List[Dict[str, Any]]:
        """Search for general web content and blog posts"""
        web_content = []

        try:
            # General search about the domain
            results = await self._web_search(f"{self.target} news OR blog OR article")
            web_content.extend(results)

            # Company/brand mentions
            results = await self._web_search(f'"{self.target}" company OR organization')
            web_content.extend(results)

        except Exception as e:
            self.logger.debug(f"Error searching web content: {e}")

        # Deduplicate
        seen_urls = set()
        unique_content = []
        for item in web_content:
            if item["url"] not in seen_urls:
                seen_urls.add(item["url"])
                unique_content.append(item)

        return unique_content[:50]  # Limit to top 50 results

    async def _web_search(self, query: str, security_focused: bool = False) -> List[Dict[str, Any]]:
        """Perform web search (placeholder for actual implementation)"""
        results = []

        # NOTE: In production, integrate with:
        # - Google Custom Search API
        # - Bing Web Search API
        # - DuckDuckGo API
        # - Shodan for security content

        # For now, return empty list with a note
        self.logger.debug(f"Web search for '{query}' - API integration required")

        return results

    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL"""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            return parsed.netloc
        except Exception:
            return ""

    def _analyze_intelligence(self, results: Dict):
        """Analyze gathered intelligence for key findings"""
        findings = results["findings"]

        # Analyze news articles
        news = results["news_articles"]
        if news:
            recent_news = [a for a in news if a["days_old"] < 30]
            high_trust_news = [a for a in news if a["trust_score"] >= 8]

            if recent_news:
                findings.append(
                    self._create_finding(
                        "info",
                        f"{len(recent_news)} recent news articles found",
                        f"Found {len(recent_news)} news articles from the last 30 days",
                        data=recent_news[:5]  # Top 5
                    )
                )

            if high_trust_news:
                findings.append(
                    self._create_finding(
                        "info",
                        f"{len(high_trust_news)} articles from trusted sources",
                        f"Found coverage in trusted news sources",
                        data=high_trust_news[:5]
                    )
                )

        # Analyze security mentions
        security = results["security_mentions"]
        if security:
            # Any security mentions are potentially important
            findings.append(
                self._create_finding(
                    "high" if len(security) > 5 else "medium",
                    f"{len(security)} security-related mentions found",
                    "Found content related to security, vulnerabilities, or breaches",
                    data=security[:10],
                    recommendation="Review security-related content for potential risks"
                )
            )

        # Overall visibility
        total_mentions = len(news) + len(results["blog_posts"])
        if total_mentions > 100:
            findings.append(
                self._create_finding(
                    "info",
                    "High online visibility",
                    f"Found {total_mentions} online mentions of the domain"
                )
            )
        elif total_mentions < 10:
            findings.append(
                self._create_finding(
                    "low",
                    "Low online visibility",
                    f"Limited online presence detected ({total_mentions} mentions)",
                    recommendation="Low visibility may indicate a new or inactive domain"
                )
            )
