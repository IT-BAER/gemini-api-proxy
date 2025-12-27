# Gemini API Proxy

A reverse proxy for the Google Gemini Code Assist API that exposes it as an OpenAI and Anthropic compatible service. This allows you to use Gemini Code Assist with any tool that supports the OpenAI Chat Completions API or the Anthropic Messages API.

> Inspired by [copilot-api](https://github.com/ericc-ch/copilot-api)

>[!WARNING]
>
> This project uses Google's internal Code Assist API endpoints that are not publicly documented. Using this proxy may violate Google's Terms of Service.
> **Potential risks to your Google account:**
>
> - **Rate limit enforcement** - Exceeding usage limits may trigger restrictions
> - **API access suspension** - Google may temporarily or permanently suspend API access
> - **Account review** - Unusual usage patterns may flag your account for manual review
> - **Account termination** - Serious or repeated violations could result in account closure
>
> **From Google's policies:**
>
> - Reverse engineering APIs is prohibited
> - Circumventing usage limits can result in account suspension
> - Google monitors API usage and may take enforcement action without notice
>
> **Use at your own risk.** This project is for educational purposes. The authors are not responsible for any consequences to your Google account.

## Features

- **OpenAI & Anthropic Compatibility**: Exposes Gemini Code Assist as OpenAI-compatible (`/v1/chat/completions`, `/v1/models`) and Anthropic-compatible (`/v1/messages`) endpoints.
- **Dynamic Model Listing**: Automatically defines an Anthropic-compatible model list (e.g., `claude-3-opus`, `gemini-2.5-pro`) when the `x-api-key` header is detected, resolving compatibility issues with tools like n8n.
- **Detailed Usage Dashboard**: Web-based dashboard displaying real-time request status, authentic token direction (`Input ↑ / Output ↓`), and error logs.
- **Streaming Token Estimation**: Implements a character-based fallback calculation (char/4) for streaming responses since the upstream API does not provide token usage metadata in stream chunks.
- **Rate Limit Control**: Configurable request throttling (`RATE_LIMIT` env var) and smart queuing (`WAIT_MODE`) to prevent 429 errors.
- **Flexible Model Aliasing**: Maps standard OpenAI/Anthropic model names to internal Google model IDs transparently.
- **Mock Embeddings**: Includes a deterministic, hash-based embedding endpoint (`/v1/embeddings`) to satisfy client library validation checks (Note: Does not generate semantic vectors).

## Prerequisites

- Python 3.11+
- Google account with Gemini Code Assist access (free tier included with Google accounts)

## Installation

### Using Docker (Recommended)

```bash
# Clone the repository
git clone https://github.com/IT-BAER/gemini-api-proxy.git
cd gemini-api-proxy

# Start the container
docker-compose up -d

# View logs for authentication URL
docker-compose logs -f
```

### Linux (Debian/Ubuntu) - Automated
```bash
git clone https://github.com/IT-BAER/gemini-api-proxy.git
cd gemini-api-proxy
sudo chmod +x setup.sh
sudo ./setup.sh
```
#### Removal
```bash
sudo systemctl stop gemini-api-proxy && sudo systemctl disable gemini-api-proxy && sudo rm /etc/systemd/system/gemini-api-proxy.service && sudo systemctl daemon-reload && sudo rm -rf /opt/gemini-api-proxy
```

#### Configuration (Service)
To change the Port or Host after installation:

**Option 1: Override (Recommended)**
```bash
sudo systemctl edit gemini-api-proxy
```
Add the following lines to override:
```ini
[Service]
Environment="PORT=9000"
Environment="HOST=127.0.0.1"
```

**Option 2: Direct Edit**
Edit `/etc/systemd/system/gemini-api-proxy.service`, modify the parameters, then run:
```bash
sudo systemctl daemon-reload
sudo systemctl restart gemini-api-proxy
```

### Manual Installation (Cross-Platform)

```bash
git clone https://github.com/IT-BAER/gemini-api-proxy.git
cd gemini-api-proxy
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py
```



## Authentication

1. Start the server and open the setup page:
   - **Docker**: `http://localhost:8080/setup`
   - **Service/Manual**: `http://localhost:8081/setup`
2. Click "Sign in with Google" and authorize the application
3. Copy the authorization code and paste it into the form
4. The proxy is now ready to use

## API Endpoints

### OpenAI Compatible

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/v1/models` | List available models |
| GET | `/v1/models/{id}` | Get model details |
| POST | `/v1/chat/completions` | Create chat completion |
| POST | `/v1/embeddings` | Create embeddings (Mock/Deterministic) |

### Anthropic Compatible

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/v1/messages` | Create message |
| POST | `/v1/messages/count_tokens` | Count tokens (Est.) |

### Monitoring

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Usage dashboard |
| GET | `/usage` | Usage statistics (JSON) |
| GET | `/health` | Health check |

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8081` | Server port (Docker default: 8080) |
| `HOST` | `0.0.0.0` | Listening interface (use `127.0.0.1` for local only) |
| `TOKEN_FILE` | `google_token.json` | Token storage location |
| `RATE_LIMIT` | `0` | Seconds between requests (0 = disabled) |
| `WAIT_MODE` | `false` | Queue requests instead of rejecting |
| `SHOW_TOKEN` | `false` | Display token in logs |

## Available Models

Models are subject to change based on Google's offerings. Current models include variations of Gemini 2.5 and Gemini 3 (preview). Use `/v1/models` to see the current list.


## Usage Limits Examples

Usage limits depend on your Google account subscription, for example:

| Plan | Description |
|------|-------------|
| Free | Included with Google account, subject to daily limits |
| Google AI Pro | Higher limits with paid subscription |

Check [Google's documentation](https://cloud.google.com/gemini/docs/codeassist/overview) for current quota information.
<br>

## 💜 Support Development

If this project helps you, consider supporting future work, which heavily relies on coffee:

<div align="center">
<a href="https://www.buymeacoffee.com/itbaer" target="_blank"><img src="https://github.com/user-attachments/assets/64107f03-ba5b-473e-b8ad-f3696fe06002" alt="Buy Me A Coffee" style="height: 60px; max-width: 217px;"></a>
<br>
<a href="https://www.paypal.com/donate/?hosted_button_id=5XXRC7THMTRRS" target="_blank">Donate via PayPal</a>
</div>

<br>

## License

MIT
