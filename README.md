# PHP Web Scraper

A powerful, feature-rich web scraping tool built with PHP that provides a modern web interface for extracting content from websites. This tool offers comprehensive scraping capabilities with built-in security features, caching, and a responsive user interface.

<img width="1202" height="878" alt="image" src="https://github.com/user-attachments/assets/ddae001d-1f18-4ac6-85dd-51bb6c4bdd69" />
<img width="1210" height="685" alt="image" src="https://github.com/user-attachments/assets/b5d1ff9a-54b9-4fc0-9ae6-99008b74469f" />

## ✨ Features

### 🔍 **Comprehensive Scraping Capabilities**
- **Whole Site Download** - Extract complete HTML content with metadata
- **Image Extraction** - Find and catalog all images with preview functionality
- **Video Detection** - Locate embedded videos from YouTube, Vimeo, and other platforms
- **Link Harvesting** - Extract all links with metadata and categorization
- **Text Content Extraction** - Clean text extraction with word count statistics

### 🛡️ **Advanced Security Features**
- **Rate Limiting** - Configurable requests per minute to prevent abuse
- **IP Blocking** - Block access to local network addresses for security
- **Bot Detection** - Advanced detection of anti-bot measures and captcha systems
- **Request Validation** - Comprehensive URL validation and sanitization
- **Error Logging** - Detailed logging system for monitoring and debugging

### ⚡ **Performance & Caching**
- **Intelligent Caching** - Configurable cache system with TTL support
- **Progress Tracking** - Real-time progress updates for large operations
- **Timeout Management** - Configurable timeouts to prevent hanging requests
- **File Size Limits** - Configurable maximum file size limits
- **Memory Optimization** - Efficient memory usage for large content processing

### 🎨 **Modern User Interface**
- **Responsive Design** - Mobile-friendly interface that works on all devices
- **Dark Theme** - Modern dark theme with gradient effects
- **Tabbed Interface** - Organized interface with scraper, configuration, and statistics tabs
- **Real-time Feedback** - Live status updates and progress indicators
- **Interactive Previews** - Image previews with hover effects

### ⚙️ **Configuration Management**
- **Environment Variables** - Support for environment-based configuration
- **JSON Configuration** - Persistent configuration storage
- **Runtime Settings** - Modify settings without server restart
- **Debug Mode** - Comprehensive debugging information when enabled

## 🚀 Installation

### Prerequisites
- PHP 7.4 or higher
- cURL extension enabled
- Write permissions for cache and logs directories

### Quick Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/PHP-Web-Scraper.git
   cd PHP-Web-Scraper
   ```

2. **Set up permissions**
   ```bash
   chmod 755 .
   chmod 777 cache logs  # These directories will be created automatically
   ```

3. **Configure your web server**
   - **Apache**: Place in your web directory (e.g., `/var/www/html/scraper/`)
   - **Nginx**: Configure location block for PHP processing
   - **Local Development**: Use PHP's built-in server:
     ```bash
     php -S localhost:8000
     ```

4. **Access the application**
   - Open your browser and navigate to `http://localhost:8000` (or your configured URL)

### Environment Configuration (Optional)

Create a `.env` file or set environment variables:
```bash
SCRAPER_MAX_SIZE=52428800      # 50MB max file size
SCRAPER_TIMEOUT=30             # 30 second timeout
SCRAPER_RATE_LIMIT=10          # 10 requests per minute
SCRAPER_CACHE=300              # 5 minute cache duration
SCRAPER_DEBUG=false            # Debug mode off by default
```

## 📖 Usage

### Basic Web Scraping

1. **Enter a URL** in the input field (e.g., `https://example.com`)
2. **Choose your scraping method**:
   - 📄 **Download Whole Site** - Get complete HTML source
   - 🖼️ **Extract Images** - Find all images with metadata
   - 🎥 **Extract Videos** - Locate embedded videos
   - 🔗 **Extract Links** - Harvest all links
   - 📝 **Extract Text Content** - Get clean text content

3. **View Results** - Results display with download options and previews
4. **Download Content** - Use download buttons to save extracted content

### Configuration Management

Access the **Configuration** tab to adjust:

- **Performance Settings**
  - Maximum file size limits
  - Request timeouts
  - Cache duration

- **Security Settings**
  - Rate limiting rules
  - Local network blocking
  - Error logging preferences

- **Feature Settings**
  - Cache enable/disable
  - Debug mode toggle

### Statistics & Monitoring

The **Statistics** tab provides:
- Cache usage statistics
- Error log counts
- Current configuration overview
- Real-time progress tracking

## 🔧 Configuration Options

### Core Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `max_file_size` | 50MB | Maximum size of content to download |
| `timeout` | 30s | Request timeout duration |
| `rate_limit` | 10/min | Maximum requests per minute per IP |
| `cache_duration` | 300s | How long to cache responses |
| `enable_cache` | true | Enable response caching |
| `log_errors` | true | Enable error logging |
| `block_local_ips` | true | Block access to local networks |
| `debug_mode` | false | Enable detailed debugging |

### Advanced Configuration

Create `scraper_config.json` for persistent settings:
```json
{
    "max_file_size": 52428800,
    "timeout": 30,
    "rate_limit": 10,
    "cache_duration": 300,
    "debug_mode": false,
    "enable_cache": true,
    "log_errors": true,
    "block_local_ips": true,
    "max_redirects": 5
}
```

## 🛡️ Security Features

### Built-in Protections

- **Rate Limiting**: Prevents abuse with configurable request limits
- **IP Validation**: Blocks access to local/private networks
- **Content Filtering**: Detects and handles bot protection systems
- **Size Limits**: Prevents memory exhaustion with large files
- **Error Handling**: Comprehensive error catching and logging

### Best Practices

- Always respect `robots.txt` files
- Use reasonable delays between requests
- Check website terms of service before scraping
- Be aware of legal implications in your jurisdiction
- Monitor error logs regularly

## 📊 Supported Content Types

### Websites
- Standard HTML websites
- WordPress sites
- Drupal sites
- Next.js applications
- Single Page Applications (SPA)

### Media Types
- **Images**: JPG, PNG, GIF, WebP, SVG
- **Videos**: MP4, WebM, embedded players
- **Platforms**: YouTube, Vimeo, Dailymotion, Twitch

### Content Detection
- Automatic CMS detection
- Bot protection identification
- Content type analysis
- Metadata extraction

## 🐛 Troubleshooting

### Common Issues

**"Rate limit exceeded"**
- Wait for the rate limit window to reset
- Adjust rate limit in configuration if you own the server

**"Content too large"**
- Increase `max_file_size` in configuration
- Check available server memory

**"Site appears to be blocking automated requests"**
- The target site has anti-bot measures
- Try accessing the site manually to verify it's accessible
- Some sites require JavaScript rendering (not supported)

**"cURL Error"**
- Ensure cURL extension is installed: `php -m | grep curl`
- Check firewall settings
- Verify SSL certificate settings

### Debug Mode

Enable debug mode for detailed information:
1. Go to Configuration tab
2. Enable "Debug Mode"
3. Save configuration
4. Check debug output for detailed request/response information

### Log Files

Check log files for detailed error information:
- `logs/scraper_errors.log` - Error details with timestamps
- Cache files in `cache/` directory for debugging cache issues

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Legal Disclaimer

This tool is intended for educational and research purposes. Users are responsible for ensuring their use complies with:

- Website terms of service
- Local and international laws
- Data protection regulations (GDPR, etc.)
- Copyright and intellectual property rights

Always obtain permission before scraping websites and respect rate limits and robots.txt files.

---
