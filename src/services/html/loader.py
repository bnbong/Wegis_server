# --------------------------------------------------------------------------
# HTML loader module
#
# @author bnbong bbbong9@gmail.com
# --------------------------------------------------------------------------
import logging

from selenium import webdriver
from selenium.common.exceptions import TimeoutException
from selenium.webdriver.chrome.options import Options

from src.core.config import settings
from src.exceptions import BackendExceptions

logger = logging.getLogger("main")


class HTMLLoader:
    def __init__(self):
        self.chrome_options = Options()

        self.chrome_options.add_argument("--headless")
        self.chrome_options.add_argument("--no-sandbox")
        self.chrome_options.add_argument("--disable-dev-shm-usage")
        self.chrome_options.add_argument("--disable-gpu")
        self.chromedriver_path = settings.CHROMEDRIVER_PATH
        self.timeout = settings.HTML_LOAD_TIMEOUT
        self.retries = settings.HTML_LOAD_RETRIES

    def _init_driver(self):
        try:
            service = webdriver.ChromeService(executable_path=self.chromedriver_path)
            driver = webdriver.Chrome(service=service, options=self.chrome_options)
            driver.set_page_load_timeout(self.timeout)
            return driver
        except Exception as e:
            logger.error(f"Failed to initialize WebDriver: {e}")
            raise BackendExceptions("Failed to initialize WebDriver")

    # TODO : Handle case of short url or redirect url

    def __load_url(self, driver, url: str) -> str:
        # ``url`` is used verbatim. The caller normalized and SSRF-validated
        # this exact string, so rewriting it here (scheme, host) would drive the
        # browser to a target the guard never inspected.
        if not url.startswith(("http://", "https://")):
            raise BackendExceptions(f"URL must be an absolute http(s) URL: {url}")
        try:
            driver.get(url)
            return url
        except TimeoutException:
            logger.error(f"Timeout while loading URL: {url}")
            raise BackendExceptions("Timeout while loading URL")
        except Exception as e:
            logger.error(f"Error loading URL {url}: {e}")
            raise BackendExceptions(e)

    def load(self, url: str) -> str | None:
        """Load ``url`` in a headless browser and return its page source.

        ``url`` must already be an absolute http(s) URL that the caller has
        SSRF-validated; it reaches ``driver.get`` unchanged.
        """
        for attempt in range(self.retries):
            driver = None
            try:
                driver = self._init_driver()
                self.__load_url(driver, url)
                return driver.page_source
            except Exception as e:
                logger.warning(f"Attempt {attempt + 1} failed: {e}")
                if attempt == self.retries - 1:
                    raise BackendExceptions(
                        f"Failed to load URL after {self.retries} attempts"
                    )
            finally:
                if driver:
                    try:
                        driver.quit()
                    except Exception:
                        pass
        return ""
