# Template System

The ban and captcha templates support dynamic variable substitution and conditional logic.

## Available Variables

The following variables are automatically available in ban templates:

| Variable | Description |
|----------|-------------|
| `{{client_ip}}` | Client's IP address |
| `{{client_port}}` | Client's port |
| `{{request_id}}` | Unique request identifier |
| `{{request_uri}}` | Requested URI path |
| `{{request_method}}` | HTTP method (GET, POST, etc.) |
| `{{host}}` | Host header value |
| `{{server_name}}` | Server name |
| `{{scheme}}` | Request scheme (http/https) |
| `{{user_agent}}` | Client's User-Agent header |
| `{{referer}}` | Referer header |
| `{{timestamp}}` | Human-readable timestamp (YYYY-MM-DD HH:MM:SS) |
| `{{timestamp_iso}}` | ISO 8601 timestamp |
| `{{timestamp_unix}}` | Unix timestamp |
| `{{server_addr}}` | Server IP address |
| `{{server_port}}` | Server port |

## Conditional Logic

Templates support if/else conditionals:

```html
{{#if variable}}
  Content shown when variable is truthy
{{else}}
  Content shown when variable is falsy
{{/if}}
```

The `{{else}}` block is optional:

```html
{{#if client_ip}}
  Your IP: {{client_ip}}
{{/if}}
```

### Negation

Use `!` to negate a condition:

```html
{{#if !user_agent}}
  No User-Agent provided
{{/if}}
```

### Truthy Values

A value is considered truthy if it is:
- A non-empty string
- A non-zero number
- A boolean `true`
- A non-empty table

## Example Ban Template

```html
<!DOCTYPE html>
<html>
<head>
    <title>Access Denied</title>
</head>
<body>
    <h1>Access Forbidden</h1>
    <p>Your request has been blocked.</p>

    <div class="details">
        <p>Request ID: {{request_id}}</p>
        {{#if client_ip}}
        <p>Your IP: {{client_ip}}</p>
        {{/if}}
        <p>Time: {{timestamp}}</p>
    </div>

    {{#if custom_message}}
    <div class="message">{{custom_message}}</div>
    {{else}}
    <p>Please contact the administrator if you believe this is an error.</p>
    {{/if}}
</body>
</html>
```

## Captcha Template Variables

The captcha template uses these additional variables:

| Variable | Description |
|----------|-------------|
| `{{captcha_site_key}}` | Public site key for captcha provider |
| `{{captcha_frontend_js}}` | JavaScript URL for captcha provider |
| `{{captcha_frontend_key}}` | CSS class for captcha container |
