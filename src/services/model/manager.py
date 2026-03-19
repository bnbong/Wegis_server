# --------------------------------------------------------------------------
# AI Model Load module
#
# @author bnbong bbbong9@gmail.com
# --------------------------------------------------------------------------
import logging
from typing import Any
from time import perf_counter

import torch

from src.exceptions import AIException
from src.services.model.preprocessor import DataPreprocessor
from src.services.model.qbert import QsingBertModel
from src.services.model.preprocessor import get_html_tokenizer, get_url_tokenizer

logger = logging.getLogger("main")


class PhishingDetector:
    def __init__(self, model_path: str):
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.model = QsingBertModel().to(self.device)

        try:
            checkpoint = torch.load(model_path, map_location=self.device)
            self.model.load_state_dict(checkpoint["model"])
            self.model.eval()
            logger.info("Model loaded successfully")
        except Exception as e:
            logger.error(f"Failed to load model: {str(e)}")
            raise AIException(e)

        self.url_tokenizer = get_url_tokenizer()
        self.bert_tokenizer = get_html_tokenizer()

    def predict_from_html(self, url: str, html: str) -> dict[str, Any]:
        logger.info(f"Predicting URL: {url}")
        if not html:
            return {"result": None, "confidence": None}

        preprocess_started = perf_counter()
        preprocessor = DataPreprocessor(
            url,
            html,
            html_tokenizer=self.bert_tokenizer,
            url_tokenizer=self.url_tokenizer,
        )
        inputs = preprocessor.preprocess(self.device)
        preprocess_ms = (perf_counter() - preprocess_started) * 1000

        infer_started = perf_counter()
        with torch.no_grad():
            _, prob = self.model(inputs)
        infer_ms = (perf_counter() - infer_started) * 1000

        return {
            "result": float(prob) >= 0.5,
            "confidence": float(prob),
            "preprocess_ms": round(preprocess_ms, 3),
            "infer_ms": round(infer_ms, 3),
        }

    def predict(self, url: str) -> dict[str, Any]:
        return {"result": None, "confidence": None, "url": url}
