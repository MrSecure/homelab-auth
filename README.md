# homelab-auth

[![CI](https://github.com/MrSecure/homelab-auth/actions/workflows/commit.yml/badge.svg)](https://github.com/MrSecure/homelab-auth/actions/workflows/commit.yml)

Welcome to homelab-auth

## Getting Started

First, you need to ensure you have `brew`, `task`, `docker`, `git`, and `uv` installed locally, and the `docker` daemon is running.

Then, you can setup your local environment via:

```bash
# Install the dependencies
task init

# Build the image
task build

# Run the image
docker run --rm -ti -p 55000:55000 MrSecure/homelab-auth:0.8.0
```

If you'd like to build all of the supported docker images, you can set the `PLATFORM` env var to `all` like this:

```bash
PLATFORM=all task build
```

You can also specify a single platform of either `linux/arm64` or `linux/amd64`

## Development

For local development, you can run the service directly with:

```bash
task run
```

This starts the Flask development server on `http://127.0.0.1:55000`.

## WSGI / Production

This project includes a dedicated WSGI entrypoint for running under production WSGI servers such as `gunicorn`.

### Quick Start with Gunicorn

Run the application locally with gunicorn using the task runner:

```bash
task run-gunicorn
```

This is equivalent to:

```bash
HOMELAB_AUTH_CONFIG_FILE=support/wsgi-config.yaml \
  HOMELAB_AUTH_HASHING_KEY="homelab-auth-dev-key" \
  gunicorn --bind 0.0.0.0:8000 --workers 4 --timeout 120 \
    --access-logfile - --error-logfile - src.wsgi:app
```

### WSGI Architecture

- **Entry module:** [src/wsgi.py](src/wsgi.py) — exports the Flask application as `app` for WSGI servers.
- **Behavior:** The WSGI module prepares a controlled `sys.argv` so the application initializes from environment variables instead of arbitrary CLI args. It also applies a compatibility fix for newer `bcrypt`/`passlib` versions used at startup.
- **Key feature:** Environment variable-driven configuration allows for zero-CLI-args deployment in containerized environments.

### Configuration via Environment Variables

The WSGI entrypoint accepts the following environment variables:

|Variable|Default|Purpose|
|--------|-------|-------|
|`HOMELAB_AUTH_CONFIG_FILE`|`config.yaml`|Path to the configuration file|
|`HOMELAB_AUTH_HASHING_KEY`|*(auto-generated)*|Session signing key (highest precedence)|

### Session Hashing Key Precedence

The application supports three methods for providing the hashing key (in order of precedence):

1. **Environment Variable** (for WSGI deployment):

```bash
export HOMELAB_AUTH_HASHING_KEY="your-secret-key"
gunicorn -w 4 -b 0.0.0.0:55000 src.wsgi:app
```

2. **CLI Argument** (for direct Python execution):

```bash
python src/main.py config.yaml --hashing-key "your-secret-key"
```

3. **Auto-generated Fallback**:
   If neither option is provided, the application generates a SHA1 hash of the configuration file. This is useful for development but **should not be used in production** where stability across deployments is required.

### Production Deployment Example

```bash
# Using gunicorn directly
HOMELAB_AUTH_CONFIG_FILE=/path/to/config.yaml \
  HOMELAB_AUTH_HASHING_KEY="your-stable-production-key" \
  gunicorn \
    --workers 4 \
    --worker-class sync \
    --bind 0.0.0.0:55000 \
    --timeout 30 \
    --keep-alive 5 \
    --max-requests 1000 \
    --max-requests-jitter 100 \
    --graceful-timeout 10 \
    --access-logfile - \
    --error-logfile - \
    src.wsgi:app
```

### Docker WSGI Deployment

The Docker image includes an optimized entrypoint (`support/entrypoint.sh`) that runs gunicorn with production-recommended settings. The container:

- Uses gunicorn with 4 workers by default
- Configures proper timeouts for long-running requests
- Maintains connection pooling via `--keep-alive`
- Recycles workers periodically via `--max-requests`
- Streams logs to stdout/stderr for container orchestration

See [docs/WSGI_DEPLOYMENT.md](docs/WSGI_DEPLOYMENT.md) for detailed WSGI deployment patterns.

## Configuration

For configuration file structure and validation, see [docs/WSGI_DEPLOYMENT.md](docs/WSGI_DEPLOYMENT.md) for detailed guidance on config file setup.

## Optional setup

If you'd like to be able to run `task license-check` locally, you will need to install `grant` and ensure it's in your `PATH`.

## Troubleshooting

If you're troubleshooting the results of any of the tasks, you can add `-v` to enable debug `task` logging, for instance:

```bash
task -v build
```

## API Endpoints

- **GET/POST `/logout`** - Invalidates the user session cookie and logs out the user

## Automated Dependency Management

This project is configured with automated dependency management:

- **Dependabot**: Automatically creates pull requests for Python, GitHub Actions, and Docker dependency updates
- **Renovate**: Provides more advanced dependency update management with grouping and scheduling capabilities

Both tools are pre-configured and will start working once the repository is pushed to GitHub.

## FAQs

For frequently asked questions including release workflow troubleshooting, see our [FAQ documentation](./FAQ.md).

*This project was generated with 🤟 by [Zenable](https://zenable.io)*

Initial htpasswd file created via

```bash
htpasswd -nbB randomly-generated "$(openssl rand -base64 78)"
```
