# --------------------------------------------------------------------------
# QBERT tokenizer
#
# refer (준철님 구현체) : https://github.com/capston-qrcode/capstone-qshing-ml-jck/blob/master/preprocessor/tokenizer.py
#
# @author bnbong bbbong9@gmail.com
# --------------------------------------------------------------------------
import torch


class QbertUrlTokenizer:
    def __init__(self):
        self.idx_to_token = {}
        self.token_to_idx = {}

        special_chars = [
            " ",
            "!",
            '"',
            "#",
            "$",
            "%",
            "&",
            "'",
            "(",
            ")",
            "*",
            "+",
            ",",
            "-",
            ".",
            ";",
            "<",
            "=",
            ">",
            "?",
            "@",
            "[",
            "\\",
            "]",
            "^",
            "_",
            "`",
            "{",
            "|",
            "}",
        ]

        custom_tokens = {
            ":": 92,
            "/": 93,
            "[PAD]": 94,
            "[NONE]": 95,
            "[CLS]": 96,
            "[SEP]": 97,
        }

        self.token_to_idx.update({char: i for i, char in enumerate(special_chars)})
        self.token_to_idx.update(
            {chr(char): i + 30 for i, char in enumerate(range(48, 58))}
        )
        self.token_to_idx.update(
            {chr(char): i + 40 for i, char in enumerate(range(65, 91))}
        )
        self.token_to_idx.update(
            {chr(char): i + 66 for i, char in enumerate(range(97, 123))}
        )
        self.token_to_idx.update(custom_tokens)

        for k, v in self.token_to_idx.items():
            self.idx_to_token[v] = k

    def tokenize(self, url_list, max_length=None, masking_ratio=0.0):
        # Split characters one by one and convert to token indices
        token_ids = []
        mask = []
        for urls in url_list:
            url_item = []
            mask_item = []
            for idx, url in enumerate(urls):
                tokens = [
                    self.token_to_idx.get(ch, self.token_to_idx["[NONE]"]) for ch in url
                ]
                if len(tokens) == 0:
                    continue
                url_item.append(
                    self.token_to_idx["[CLS]"]
                    if idx == 0
                    else self.token_to_idx["[SEP]"]
                )
                url_item.extend(tokens)
            mask_item = [1] * len(url_item)

            if max_length is not None:
                if len(url_item) > max_length:
                    url_item = url_item[:max_length]  # Truncate
                    mask_item = mask_item[:max_length]
                elif len(url_item) < max_length:
                    # Padding
                    url_item += [self.token_to_idx["[PAD]"]] * (
                        max_length - len(url_item)
                    )
                    mask_item += [0] * (max_length - len(mask_item))
            token_ids.append(url_item)
            mask.append(mask_item)

        return {
            "input_ids": torch.tensor(token_ids),
            "attention_mask": torch.tensor(mask),
        }

    def __len__(self):
        return len(self.idx_to_token)
