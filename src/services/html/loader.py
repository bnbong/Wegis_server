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

    def _normalize_url(self, url: str) -> str:
        if url.startswith("http://"):
            protocol = "http://"
            rest = url[7:]
        elif url.startswith("https://"):
            protocol = "https://"
            rest = url[8:]
        else:
            protocol = ""
            rest = url
        if not rest.startswith("www."):
            rest = "www." + rest
        if not rest.endswith("/") and ("?" not in rest and "#" not in rest):
            rest += "/"
        return protocol + rest

    def __load_url(self, driver, url: str) -> str:
        url = self._normalize_url(url)
        try:
            if not (url.startswith("http://") or url.startswith("https://")):
                # Try HTTP first
                try:
                    http_url = f"http://{url}"
                    driver.get(http_url)
                    return http_url
                except TimeoutException:
                    # If HTTP fails, try HTTPS
                    https_url = f"https://{url}"
                    driver.get(https_url)
                    return https_url
            else:
                driver.get(url)
                return url
        except TimeoutException:
            logger.error(f"Timeout while loading URL: {url}")
            raise BackendExceptions("Timeout while loading URL")
        except Exception as e:
            logger.error(f"Error loading URL {url}: {e}")
            raise BackendExceptions(e)

    def load(self, url: str) -> str | None:
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

    def __del__(self):
        return None

    @staticmethod
    def get_instance():
        return HTMLLoader()
