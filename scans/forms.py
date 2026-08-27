from django import forms


class URLScanForm(forms.Form):
    url = forms.CharField(
        label="URL to inspect",
        max_length=2048,
        strip=True,
        widget=forms.URLInput(
            attrs={
                "class": "form-control form-control--mono",
                "placeholder": "https://example.com/account/verify",
                "autocomplete": "off",
                "spellcheck": "false",
                "aria-describedby": "url-help",
            }
        ),
        help_text="Submit the address as text. It will not be opened or connected to.",
    )


class EmailScanForm(forms.Form):
    sender = forms.EmailField(
        label="Sender",
        max_length=320,
        required=False,
        widget=forms.EmailInput(
            attrs={
                "class": "form-control",
                "placeholder": "sender@example.com",
                "autocomplete": "email",
            }
        ),
    )
    reply_to = forms.EmailField(
        label="Reply-To",
        max_length=320,
        required=False,
        widget=forms.EmailInput(
            attrs={
                "class": "form-control",
                "placeholder": "reply@example.com",
                "autocomplete": "email",
            }
        ),
    )
    subject = forms.CharField(
        label="Subject",
        max_length=500,
        required=False,
        widget=forms.TextInput(
            attrs={
                "class": "form-control",
                "placeholder": "Your account requires attention",
            }
        ),
    )
    body = forms.CharField(
        label="Email body",
        max_length=30000,
        required=False,
        widget=forms.Textarea(
            attrs={
                "class": "form-control form-control--textarea",
                "rows": 10,
                "placeholder": "Paste the message body here...",
                "spellcheck": "true",
            }
        ),
    )
    attachment_names = forms.CharField(
        label="Attachment names",
        max_length=2000,
        required=False,
        widget=forms.TextInput(
            attrs={
                "class": "form-control",
                "placeholder": "invoice.pdf, instructions.docm",
                "autocomplete": "off",
            }
        ),
        help_text="Optional. Enter names only, separated by commas. Do not upload or open files.",
    )
