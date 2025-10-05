# --------------------------------------------------------------------------
# QBERT model
#
# refer (준철님 구현체) : https://github.com/capston-qrcode/capstone-qshing-ml-jck/blob/master/model/qbert.py
#
# @author bnbong bbbong9@gmail.com
# --------------------------------------------------------------------------
import torch
import torch.nn as nn
from transformers import MobileBertModel


class UrlCnnModel(nn.Module):
    def __init__(
        self, vocab_size, embed_dim=128, hidden_dim=256, output_dim=768, padding_idx=0
    ):
        super().__init__()
        self.embedding = nn.Embedding(
            num_embeddings=vocab_size, embedding_dim=embed_dim, padding_idx=padding_idx
        )

        # Example: Multiple Conv1D with different kernel_size
        self.conv3 = nn.Conv1d(
            in_channels=embed_dim, out_channels=hidden_dim, kernel_size=3, padding=1
        )
        self.conv5 = nn.Conv1d(
            in_channels=embed_dim, out_channels=hidden_dim, kernel_size=5, padding=2
        )

        # Combine channels to final dimension (768 for BERT)
        self.projection = nn.Linear(hidden_dim * 2, output_dim)

        self.relu = nn.ReLU()

    def forward(self, input_ids, attention_mask=None):
        x = self.embedding(input_ids)  # (batch_size, seq_len, embed_dim)

        if attention_mask is not None:
            # attention_mask: (batch_size, seq_len) -> (batch_size, seq_len, 1)
            x = x * attention_mask.unsqueeze(-1)

        # 3) Convert to (batch_size, embed_dim, seq_len) for CNN input
        x = x.permute(0, 2, 1)

        x3 = self.relu(self.conv3(x))
        x5 = self.relu(self.conv5(x))

        # 5) Global Max Pooling → (batch_size, hidden_dim)
        x3_pool = torch.max(x3, dim=2).values
        x5_pool = torch.max(x5, dim=2).values

        # 6) Concat two results → (batch_size, hidden_dim*2)
        x_cat = torch.cat([x3_pool, x5_pool], dim=1)

        # 7) Project to desired output dimension (e.g. 768)
        out = self.projection(x_cat)  # (batch_size, output_dim)
        return out


class QsingBertModel(nn.Module):
    def __init__(self):
        super(QsingBertModel, self).__init__()

        # self.bert_urls = BertModel.from_pretrained('bert-base-uncased')
        self.bert_urls = UrlCnnModel(98, output_dim=512)
        self.bert_html = MobileBertModel.from_pretrained("google/mobilebert-uncased")

        self.fc = nn.Linear(512 * 2, 512)
        self.gelu = nn.GELU()
        self.output_layer = nn.Linear(512, 1)
        self.sigmoid = nn.Sigmoid()

    def median_pooling(self, outputs):
        return torch.median(outputs, dim=1).values

    def forward(self, input):
        url_input_ids = input["url_input_ids"]
        url_attention_mask = input["url_attention_mask"]
        html_input_ids = input["html_input_ids"]
        html_attention_mask = input["html_attention_mask"]

        url_cls_embedding = self.bert_urls(
            input_ids=url_input_ids, attention_mask=url_attention_mask
        )

        html_output = self.bert_html(
            input_ids=html_input_ids, attention_mask=html_attention_mask
        )
        html_cls_embedding = self.median_pooling(html_output.last_hidden_state)

        combined = torch.cat((url_cls_embedding, html_cls_embedding), dim=1)

        x = self.fc(combined)
        x = self.gelu(x)

        logits = self.output_layer(x)
        output = self.sigmoid(logits)

        return logits.squeeze(), output.squeeze()
