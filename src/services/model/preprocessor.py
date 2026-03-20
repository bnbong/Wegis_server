# --------------------------------------------------------------------------
# Preprocessor module
#
# @author bnbong bbbong9@gmail.com
# --------------------------------------------------------------------------
import logging
import re
from functools import lru_cache

from html2text import HTML2Text
from langdetect import detect  # type: ignore
from torch import device
from transformers import BertTokenizer

from src.services.model.tokenizer import QbertUrlTokenizer

logger = logging.getLogger("main")


class DataPreprocessor:
    def __init__(
        self,
        url: str,
        html: str,
        html_tokenizer: BertTokenizer | None = None,
        url_tokenizer: QbertUrlTokenizer | None = None,
    ):
        self.url = url
        self.html = html
        self.html_tokenizer = html_tokenizer or get_html_tokenizer()
        self.url_tokenizer = url_tokenizer or get_url_tokenizer()
        self.max_length = 512

    def preprocess(self, device: device):
        converter = HTML2Text()
        converter.ignore_links = True
        converter.ignore_images = True
        converter.ignore_tables = True

        content = converter.handle(self.html)
        sentences = re.split(r"(?<=[.!?]) +", content)

        contents = [s for s in sentences if s.strip()]
        merged = " ".join(contents[:20])
        try:
            if merged and detect(merged) != "en":
                contents = contents[:10]
        except Exception:
            contents = contents[:10]

        text = "[CLS]" + "[SEP]".join(contents)
        html_tokens = self.html_tokenizer(
            text,
            return_tensors="pt",
            padding="max_length",
            max_length=self.max_length,
            truncation=True,
        )

        url_tokens = self.url_tokenizer.tokenize(
            [[self.url]], max_length=self.max_length
        )

        return {
            "url_input_ids": url_tokens["input_ids"].to(device),
            "url_attention_mask": url_tokens["attention_mask"].to(device),
            "html_input_ids": html_tokens["input_ids"].to(device),
            "html_attention_mask": html_tokens["attention_mask"].to(device),
        }


@lru_cache(maxsize=1)
def get_html_tokenizer() -> BertTokenizer:
    return BertTokenizer.from_pretrained("bert-base-uncased")


@lru_cache(maxsize=1)
def get_url_tokenizer() -> QbertUrlTokenizer:
    return QbertUrlTokenizer()
