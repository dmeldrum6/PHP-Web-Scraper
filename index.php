<?php
// PHP Web Scraper Tool
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Enable output buffering for better error handling
ob_start();

// Configuration Class
class ScraperConfig {
    private static $config = null;
    
    public static function init() {
        if (self::$config === null) {
            // Default configuration
            self::$config = [
                'max_file_size' => $_ENV['SCRAPER_MAX_SIZE'] ?? 50 * 1024 * 1024, // 50MB
                'timeout' => $_ENV['SCRAPER_TIMEOUT'] ?? 30,
                'rate_limit' => $_ENV['SCRAPER_RATE_LIMIT'] ?? 10, // per minute
                'cache_duration' => $_ENV['SCRAPER_CACHE'] ?? 300, // 5 minutes
                'debug_mode' => $_ENV['SCRAPER_DEBUG'] ?? false,
                'max_redirects' => 5,
                'enable_cache' => true,
                'log_errors' => true,
                'block_local_ips' => true
            ];
            
            // Load from config file if exists
            if (file_exists('scraper_config.json')) {
                $file_config = json_decode(file_get_contents('scraper_config.json'), true);
                if ($file_config) {
                    self::$config = array_merge(self::$config, $file_config);
                }
            }
        }
        return self::$config;
    }
    
    public static function get($key) {
        $config = self::init();
        return $config[$key] ?? null;
    }
    
    public static function set($key, $value) {
        $config = self::init();
        self::$config[$key] = $value;
        self::save();
    }
    
    public static function save() {
        file_put_contents('scraper_config.json', json_encode(self::$config, JSON_PRETTY_PRINT));
    }
    
    public static function getUserAgent() {
        return 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 (compatible; PHPScraper/2.0)';
    }
}

// Initialize config
ScraperConfig::init();

// Create necessary directories
if (!file_exists('cache')) mkdir('cache', 0755, true);
if (!file_exists('logs')) mkdir('logs', 0755, true);

// Logging function
function logError($message, $context = []) {
    if (!ScraperConfig::get('log_errors')) return;
    
    $log_entry = [
        'timestamp' => date('Y-m-d H:i:s'),
        'message' => $message,
        'context' => $context,
        'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
        'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown'
    ];
    
    error_log(json_encode($log_entry) . "\n", 3, 'logs/scraper_errors.log');
}

// Rate limiting function
function checkRateLimit($ip) {
    $rate_limit_file = 'cache/rate_limit.json';
    $max_requests = ScraperConfig::get('rate_limit');
    
    $data = file_exists($rate_limit_file) ? json_decode(file_get_contents($rate_limit_file), true) : [];
    $now = time();
    $minute_ago = $now - 60;
    
    // Clean old entries
    $data = array_filter($data, function($entry) use ($minute_ago) {
        return $entry['timestamp'] > $minute_ago;
    });
    
    // Count requests from this IP
    $ip_requests = array_filter($data, function($entry) use ($ip) {
        return $entry['ip'] === $ip;
    });
    
    if (count($ip_requests) >= $max_requests) {
        throw new Exception("Rate limit exceeded. Maximum {$max_requests} requests per minute. Please wait before making more requests.");
    }
    
    // Add current request
    $data[] = ['ip' => $ip, 'timestamp' => $now];
    file_put_contents($rate_limit_file, json_encode($data));
}

// URL validation function
function validateUrl($url) {
    if (!filter_var($url, FILTER_VALIDATE_URL)) {
        throw new Exception('Invalid URL format');
    }
    
    if (!ScraperConfig::get('block_local_ips')) {
        return true;
    }
    
    $parsed = parse_url($url);
    $host = $parsed['host'] ?? '';
    
    // Block local/private networks
    if (in_array(strtolower($host), ['localhost', '127.0.0.1', '0.0.0.0', '::1']) || 
        preg_match('/^192\.168\./', $host) || 
        preg_match('/^10\./', $host) ||
        preg_match('/^172\.(1[6-9]|2[0-9]|3[01])\./', $host) ||
        preg_match('/^169\.254\./', $host)) {
        throw new Exception('Local network URLs are not allowed for security reasons');
    }
    
    return true;
}

// Cache functions
function getCacheKey($url, $action) {
    return md5($url . $action);
}

function getCachedResult($cache_key) {
    if (!ScraperConfig::get('enable_cache')) return null;
    
    $cache_file = "cache/{$cache_key}.json";
    $cache_duration = ScraperConfig::get('cache_duration');
    
    if (file_exists($cache_file) && (time() - filemtime($cache_file)) < $cache_duration) {
        return json_decode(file_get_contents($cache_file), true);
    }
    return null;
}

function setCachedResult($cache_key, $data) {
    if (!ScraperConfig::get('enable_cache')) return;
    
    file_put_contents("cache/{$cache_key}.json", json_encode($data));
}

// Content type detection
function detectContentType($html) {
    $types = [];
    
    if (strpos($html, 'wp-content') !== false) $types[] = 'WordPress';
    if (strpos($html, 'Drupal') !== false) $types[] = 'Drupal';
    if (strpos($html, '_next') !== false) $types[] = 'Next.js';
    if (preg_match('/cloudflare|captcha|bot.detection/i', $html)) $types[] = 'Bot Protection';
    
    return $types;
}

// Progress tracking
function updateProgress($current, $total, $action) {
    $progress = $total > 0 ? round(($current / $total) * 100) : 0;
    file_put_contents('cache/progress.json', json_encode([
        'action' => $action,
        'progress' => $progress,
        'current' => $current,
        'total' => $total,
        'timestamp' => time()
    ]));
}

// Enhanced headers
$default_headers = [
    'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
    'Accept-Language: en-US,en;q=0.9',
    'Accept-Encoding: gzip, deflate, br',
    'DNT: 1',
    'Connection: keep-alive',
    'Upgrade-Insecure-Requests: 1',
    'Sec-Fetch-Dest: document',
    'Sec-Fetch-Mode: navigate',
    'Sec-Fetch-Site: none',
    'Cache-Control: max-age=0'
];

// Initialize variables
$url = '';
$action = '';
$results = [];
$status = '';
$error = '';
$debug_info = '';
$cache_used = false;

// Handle configuration updates
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['update_config'])) {
    try {
        $config_updates = [
            'max_file_size' => (int)($_POST['max_file_size'] ?? 50) * 1024 * 1024,
            'timeout' => (int)($_POST['timeout'] ?? 30),
            'rate_limit' => (int)($_POST['rate_limit'] ?? 10),
            'cache_duration' => (int)($_POST['cache_duration'] ?? 300),
            'enable_cache' => isset($_POST['enable_cache']),
            'log_errors' => isset($_POST['log_errors']),
            'block_local_ips' => isset($_POST['block_local_ips']),
            'debug_mode' => isset($_POST['debug_mode'])
        ];
        
        foreach ($config_updates as $key => $value) {
            ScraperConfig::set($key, $value);
        }
        
        $status = 'Configuration updated successfully!';
        logError('Configuration updated', $config_updates);
    } catch (Exception $e) {
        $error = 'Failed to update configuration: ' . $e->getMessage();
        logError('Config update failed', ['error' => $e->getMessage()]);
    }
}

// Process scraping requests
if ($_SERVER['REQUEST_METHOD'] === 'POST' && !isset($_POST['update_config'])) {
    $url = filter_var($_POST['url'] ?? '', FILTER_SANITIZE_URL);
    $action = $_POST['action'] ?? '';
    $client_ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    
    $debug_info = ScraperConfig::get('debug_mode') ? 
        "URL: $url, Action: $action, IP: $client_ip, POST data: " . print_r($_POST, true) : '';
    
    if (empty($url)) {
        $error = 'Please enter a URL';
    } elseif (empty($action)) {
        $error = 'No action specified';
    } else {
        try {
            // Rate limiting
            checkRateLimit($client_ip);
            
            // URL validation
            validateUrl($url);
            
            // Check cache first
            $cache_key = getCacheKey($url, $action);
            $cached_result = getCachedResult($cache_key);
            
            if ($cached_result) {
                $results = $cached_result['results'];
                $status = $cached_result['status'] . ' (from cache)';
                $cache_used = true;
            } else {
                switch ($action) {
                    case 'whole_site':
                        $results = scrapeWholeSite($url);
                        break;
                    case 'images':
                        $results = scrapeImages($url);
                        break;
                    case 'videos':
                        $results = scrapeVideos($url);
                        break;
                    case 'links':
                        $results = scrapeLinks($url);
                        break;
                    case 'text':
                        $results = scrapeText($url);
                        break;
                    default:
                        throw new Exception("Invalid action: '$action'");
                }
                
                // Cache the results
                setCachedResult($cache_key, ['results' => $results, 'status' => $status]);
            }
            
        } catch (Exception $e) {
            $error = $e->getMessage();
            logError('Scraping failed', [
                'url' => $url,
                'action' => $action,
                'error' => $error,
                'ip' => $client_ip
            ]);
        }
    }
}

// Fetch function
function fetchHTML($url) {
    $timeout = ScraperConfig::get('timeout');
    $max_file_size = ScraperConfig::get('max_file_size');
    $user_agent = ScraperConfig::getUserAgent();
    $max_redirects = ScraperConfig::get('max_redirects');
    
    global $default_headers;
    
    if (function_exists('curl_init')) {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, $timeout);
        curl_setopt($ch, CURLOPT_USERAGENT, $user_agent);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_MAXREDIRS, $max_redirects);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($ch, CURLOPT_ENCODING, 'gzip, deflate');
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 10);
        
        // Check content length before downloading
        curl_setopt($ch, CURLOPT_NOBODY, true);
        curl_setopt($ch, CURLOPT_HEADER, true);
        $headers = curl_exec($ch);
        $content_length = curl_getinfo($ch, CURLINFO_CONTENT_LENGTH_DOWNLOAD);
        
        if ($content_length > $max_file_size) {
            curl_close($ch);
            throw new Exception("Content too large. Maximum size: " . round($max_file_size / 1024 / 1024) . "MB");
        }
        
        // Now get the actual content
        curl_setopt($ch, CURLOPT_NOBODY, false);
        curl_setopt($ch, CURLOPT_HEADER, false);
        curl_setopt($ch, CURLOPT_HTTPHEADER, array_merge($default_headers, [
            'User-Agent: ' . $user_agent
        ]));
        
        $html = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_error($ch);
        $final_url = curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
        curl_close($ch);
        
        if ($html === false) {
            throw new Exception("cURL Error: $error");
        }
        
        if ($httpCode >= 400) {
            throw new Exception("HTTP Error: $httpCode - Server returned an error");
        }
        
        // Enhanced bot detection
        if (stripos($html, 'redirecting you to a lite version') !== false ||
            stripos($html, 'please enable javascript') !== false ||
            stripos($html, 'cloudflare') !== false ||
            stripos($html, 'captcha') !== false ||
            stripos($html, 'access denied') !== false ||
            stripos($html, 'blocked') !== false) {
            
            $content_types = detectContentType($html);
            $warning = "Site appears to be blocking automated requests.";
            if (!empty($content_types)) {
                $warning .= " Detected: " . implode(', ', $content_types);
            }
            throw new Exception($warning);
        }
        
        return $html;
    }
    
    throw new Exception('cURL extension is required but not available');
}

// Function to convert relative URLs to absolute
function makeAbsoluteUrl($relativeUrl, $baseUrl) {
    if (empty($relativeUrl)) return '';
    if (parse_url($relativeUrl, PHP_URL_SCHEME) != '') return $relativeUrl;
    
    $base = parse_url($baseUrl);
    
    if ($relativeUrl[0] == '/') {
        return $base['scheme'] . '://' . $base['host'] . $relativeUrl;
    }
    
    $path = isset($base['path']) ? dirname($base['path']) : '';
    if ($path == '.') $path = '';
    
    return $base['scheme'] . '://' . $base['host'] . $path . '/' . $relativeUrl;
}

// Safe basename function
function safeBasename($path, $suffix = '') {
    if (empty($path) || $path === null) {
        return 'unknown';
    }
    
    $parsed = parse_url($path);
    $pathComponent = $parsed['path'] ?? '';
    
    if (empty($pathComponent) || $pathComponent === '/') {
        return 'index';
    }
    
    return basename($pathComponent, $suffix) ?: 'file';
}

// Scraping functions
function scrapeWholeSite($url) {
    global $status;
    $html = fetchHTML($url);
    $content_types = detectContentType($html);
    
    $status_msg = 'Successfully fetched HTML content (' . number_format(strlen($html)) . ' characters)';
    if (!empty($content_types)) {
        $status_msg .= '. Detected: ' . implode(', ', $content_types);
    }
    $status = $status_msg;
    
    return [
        [
            'type' => 'html',
            'content' => $html,
            'filename' => 'website_' . date('Y-m-d_H-i-s') . '.html',
            'size' => strlen($html),
            'detected_types' => $content_types
        ]
    ];
}

function scrapeImages($url) {
    global $status;
    $html = fetchHTML($url);
    $dom = new DOMDocument();
    @$dom->loadHTML($html);
    
    $images = [];
    $imgTags = $dom->getElementsByTagName('img');
    $total = $imgTags->length;
    
    foreach ($imgTags as $index => $img) {
        updateProgress($index + 1, $total, 'images');
        
        $src = $img->getAttribute('src') ?: 
               $img->getAttribute('data-src') ?: 
               $img->getAttribute('data-lazy') ?:
               $img->getAttribute('data-original');
               
        if ($src) {
            $absoluteUrl = makeAbsoluteUrl($src, $url);
            $alt = $img->getAttribute('alt') ?: 'No alt text';
            $filename = safeBasename($absoluteUrl) ?: 'image.jpg';
            
            $images[] = [
                'type' => 'image',
                'url' => $absoluteUrl,
                'alt' => $alt,
                'filename' => $filename,
                'width' => $img->getAttribute('width'),
                'height' => $img->getAttribute('height')
            ];
        }
    }
    
    $unique_images = array_unique($images, SORT_REGULAR);
    $status = 'Found ' . count($unique_images) . ' unique images (of ' . $total . ' total)';
    return $unique_images;
}

function scrapeVideos($url) {
    global $status;
    $html = fetchHTML($url);
    $dom = new DOMDocument();
    @$dom->loadHTML($html);
    
    $videos = [];
    
    // Video tags
    $videoTags = $dom->getElementsByTagName('video');
    foreach ($videoTags as $video) {
        $src = $video->getAttribute('src');
        if (!$src) {
            $sources = $video->getElementsByTagName('source');
            if ($sources->length > 0) {
                $src = $sources->item(0)->getAttribute('src');
            }
        }
        
        if ($src) {
            $absoluteUrl = makeAbsoluteUrl($src, $url);
            $filename = safeBasename($absoluteUrl) ?: 'video.mp4';
            
            $videos[] = [
                'type' => 'video',
                'url' => $absoluteUrl,
                'filename' => $filename,
                'source' => 'video_tag',
                'controls' => $video->getAttribute('controls') ? 'yes' : 'no'
            ];
        }
    }
    
    // Embedded videos
    $iframes = $dom->getElementsByTagName('iframe');
    foreach ($iframes as $iframe) {
        $src = $iframe->getAttribute('src');
        if ($src && (strpos($src, 'youtube.com') !== false || 
                     strpos($src, 'vimeo.com') !== false || 
                     strpos($src, 'dailymotion.com') !== false ||
                     strpos($src, 'twitch.tv') !== false)) {
            $videos[] = [
                'type' => 'embedded',
                'url' => $src,
                'filename' => 'embedded_video',
                'source' => 'iframe',
                'platform' => extractPlatform($src)
            ];
        }
    }
    
    $status = 'Found ' . count($videos) . ' videos';
    return $videos;
}

function extractPlatform($url) {
    if (strpos($url, 'youtube.com') !== false) return 'YouTube';
    if (strpos($url, 'vimeo.com') !== false) return 'Vimeo';
    if (strpos($url, 'dailymotion.com') !== false) return 'Dailymotion';
    if (strpos($url, 'twitch.tv') !== false) return 'Twitch';
    return 'Unknown';
}

function scrapeLinks($url) {
    global $status;
    $html = fetchHTML($url);
    $dom = new DOMDocument();
    @$dom->loadHTML($html);
    
    $links = [];
    $linkTags = $dom->getElementsByTagName('a');
    $total = $linkTags->length;
    
    foreach ($linkTags as $index => $link) {
        updateProgress($index + 1, $total, 'links');
        
        $href = $link->getAttribute('href');
        if ($href && $href !== '#') {
            $absoluteUrl = makeAbsoluteUrl($href, $url);
            $text = trim($link->textContent) ?: 'No text';
            $filename = safeBasename($absoluteUrl) ?: 'link';
            
            $links[] = [
                'type' => 'link',
                'url' => $absoluteUrl,
                'text' => $text,
                'filename' => $filename,
                'title' => $link->getAttribute('title'),
                'target' => $link->getAttribute('target')
            ];
        }
    }
    
    // Remove duplicates
    $uniqueLinks = [];
    $seen = [];
    foreach ($links as $link) {
        if (!in_array($link['url'], $seen)) {
            $uniqueLinks[] = $link;
            $seen[] = $link['url'];
        }
    }
    
    $status = 'Found ' . count($uniqueLinks) . ' unique links (of ' . $total . ' total)';
    return $uniqueLinks;
}

function scrapeText($url) {
    global $status;
    $html = fetchHTML($url);
    $dom = new DOMDocument();
    @$dom->loadHTML($html);
    
    // Remove unwanted elements
    $xpath = new DOMXPath($dom);
    $unwanted = $xpath->query('//script | //style | //nav | //header | //footer | //aside');
    foreach ($unwanted as $node) {
        if ($node->parentNode) {
            $node->parentNode->removeChild($node);
        }
    }
    
    $text = $dom->textContent;
    $cleanText = preg_replace('/\s+/', ' ', trim($text));
    
    // Extract some metadata
    $word_count = str_word_count($cleanText);
    $char_count = strlen($cleanText);
    
    $status = "Extracted {$word_count} words ({$char_count} characters) of clean text";
    
    return [
        [
            'type' => 'text',
            'content' => $cleanText,
            'filename' => 'extracted_text_' . date('Y-m-d_H-i-s') . '.txt',
            'size' => $char_count,
            'word_count' => $word_count
        ]
    ];
}

// Handle downloads
if (isset($_GET['download']) && isset($_GET['url']) && isset($_GET['type'])) {
    $downloadUrl = $_GET['url'];
    $downloadType = $_GET['type'];
    $filename = $_GET['filename'] ?? 'download';
    
    if (filter_var($downloadUrl, FILTER_VALIDATE_URL)) {
        try {
            if ($downloadType === 'file') {
                $content = fetchHTML($downloadUrl);
                header('Content-Type: application/octet-stream');
                header('Content-Disposition: attachment; filename="' . $filename . '"');
                header('Content-Length: ' . strlen($content));
                echo $content;
                exit;
            } else {
                header('Location: ' . $downloadUrl);
                exit;
            }
        } catch (Exception $e) {
            $error = 'Download failed: ' . $e->getMessage();
        }
    }
}

// Handle content downloads
if (isset($_POST['download_content']) && isset($_POST['content']) && isset($_POST['filename'])) {
    $content = $_POST['content'];
    $filename = $_POST['filename'];
    
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="' . $filename . '"');
    header('Content-Length: ' . strlen($content));
    echo $content;
    exit;
}

// Clear cache endpoint
if (isset($_POST['clear_cache'])) {
    $cache_files = glob('cache/*.json');
    $cleared = 0;
    foreach ($cache_files as $file) {
        if (unlink($file)) $cleared++;
    }
    $status = "Cleared {$cleared} cache files";
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PHP Web Scraper Tool</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #0f0f23 0%, #1a1a2e 50%, #16213e 100%);
            min-height: 100vh;
            padding: 20px;
            color: #e4e4e7;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: rgba(15, 15, 35, 0.95);
            backdrop-filter: blur(20px);
            border-radius: 20px;
            padding: 30px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.3);
            border: 1px solid rgba(255, 255, 255, 0.1);
        }

        h1 {
            text-align: center;
            color: #ffffff;
            margin-bottom: 30px;
            font-size: 2.5em;
            font-weight: 300;
            text-shadow: 0 0 20px rgba(139, 92, 246, 0.5);
        }

        .header-controls {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            flex-wrap: wrap;
            gap: 10px;
        }

        .php-badge {
            background: linear-gradient(45deg, #8b5cf6, #06b6d4);
            color: white;
            padding: 8px 16px;
            border-radius: 25px;
            font-size: 12px;
            font-weight: 600;
            box-shadow: 0 4px 15px rgba(139, 92, 246, 0.3);
        }

        .control-buttons {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }

        .control-btn {
            background: rgba(255, 255, 255, 0.1);
            border: 1px solid rgba(255, 255, 255, 0.2);
            color: #e4e4e7;
            padding: 8px 16px;
            border-radius: 25px;
            font-size: 12px;
            cursor: pointer;
            transition: all 0.3s ease;
        }

        .control-btn:hover {
            background: rgba(255, 255, 255, 0.15);
            border-color: rgba(139, 92, 246, 0.5);
        }

        .control-btn.active {
            background: linear-gradient(45deg, #8b5cf6, #06b6d4);
            border-color: transparent;
            box-shadow: 0 4px 15px rgba(139, 92, 246, 0.3);
        }

        .tabs {
            display: flex;
            margin-bottom: 20px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.2);
        }

        .tab {
            padding: 12px 24px;
            cursor: pointer;
            background: transparent;
            border: none;
            color: #9ca3af;
            font-size: 14px;
            font-weight: 600;
            transition: all 0.3s ease;
            border-bottom: 2px solid transparent;
        }

        .tab.active {
            color: #8b5cf6;
            border-bottom-color: #8b5cf6;
        }

        .tab:hover {
            color: #ffffff;
        }

        .tab-content {
            display: none;
        }

        .tab-content.active {
            display: block;
            animation: fadeIn 0.3s ease;
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .config-section {
            background: rgba(30, 30, 46, 0.8);
            padding: 25px;
            border-radius: 15px;
            margin-bottom: 20px;
            border: 1px solid rgba(255, 255, 255, 0.1);
        }

        .config-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
        }

        .config-group {
            background: rgba(15, 15, 35, 0.9);
            padding: 20px;
            border-radius: 12px;
            border: 1px solid rgba(255, 255, 255, 0.1);
        }

        .config-group h3 {
            color: #ffffff;
            margin-bottom: 15px;
            font-size: 16px;
            font-weight: 600;
        }

        .form-field {
            margin-bottom: 15px;
        }

        .form-field label {
            display: block;
            margin-bottom: 8px;
            color: #d1d5db;
            font-weight: 500;
            font-size: 14px;
        }

        .form-field input[type="number"],
        .form-field input[type="text"] {
            width: 100%;
            padding: 10px 12px;
            background: rgba(55, 65, 81, 0.8);
            border: 1px solid rgba(255, 255, 255, 0.2);
            border-radius: 8px;
            color: #ffffff;
            font-size: 14px;
            transition: all 0.3s ease;
        }

        .form-field input[type="number"]:focus,
        .form-field input[type="text"]:focus {
            outline: none;
            border-color: #8b5cf6;
            box-shadow: 0 0 0 3px rgba(139, 92, 246, 0.2);
        }

        .checkbox-field {
            display: flex;
            align-items: center;
            margin-bottom: 12px;
        }

        .checkbox-field input[type="checkbox"] {
            margin-right: 10px;
            transform: scale(1.2);
            accent-color: #8b5cf6;
        }

        .checkbox-field label {
            margin-bottom: 0;
            cursor: pointer;
        }

        .form-section {
            background: rgba(30, 30, 46, 0.8);
            padding: 25px;
            border-radius: 15px;
            margin-bottom: 30px;
            border: 1px solid rgba(255, 255, 255, 0.1);
        }

        .url-input {
            width: 100%;
            padding: 15px;
            font-size: 16px;
            border: 2px solid rgba(255, 255, 255, 0.2);
            border-radius: 10px;
            margin-bottom: 20px;
            transition: all 0.3s ease;
            background: rgba(15, 15, 35, 0.9);
            color: #ffffff;
        }

        .url-input:focus {
            outline: none;
            border-color: #8b5cf6;
            box-shadow: 0 0 0 3px rgba(139, 92, 246, 0.2);
        }

        .url-input::placeholder {
            color: #9ca3af;
        }

        .button-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
        }

        .scrape-btn {
            padding: 15px 25px;
            border: none;
            border-radius: 12px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            color: white;
            position: relative;
            overflow: hidden;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.2);
        }

        .scrape-btn:before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.2), transparent);
            transition: left 0.5s;
        }

        .scrape-btn:hover:before {
            left: 100%;
        }

        .btn-whole-site { background: linear-gradient(45deg, #8b5cf6, #a855f7); }
        .btn-images { background: linear-gradient(45deg, #ec4899, #f43f5e); }
        .btn-videos { background: linear-gradient(45deg, #06b6d4, #0ea5e9); }
        .btn-links { background: linear-gradient(45deg, #10b981, #059669); }
        .btn-text { background: linear-gradient(45deg, #f59e0b, #d97706); }

        .scrape-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 25px rgba(0, 0, 0, 0.3);
        }

        .scrape-btn:active {
            transform: translateY(0);
        }

        .save-config-btn {
            background: linear-gradient(45deg, #10b981, #059669);
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 10px;
            cursor: pointer;
            font-weight: 600;
            transition: all 0.3s ease;
            font-size: 14px;
            box-shadow: 0 4px 15px rgba(16, 185, 129, 0.3);
        }

        .save-config-btn:hover {
            transform: translateY(-1px);
            box-shadow: 0 6px 20px rgba(16, 185, 129, 0.4);
        }

        .results-section {
            background: rgba(30, 30, 46, 0.8);
            border-radius: 15px;
            padding: 25px;
            margin-top: 20px;
            border: 1px solid rgba(255, 255, 255, 0.1);
        }

        .status {
            padding: 15px;
            border-radius: 10px;
            margin-bottom: 20px;
            font-weight: 600;
        }

        .status.success {
            background: rgba(16, 185, 129, 0.2);
            color: #6ee7b7;
            border: 1px solid rgba(16, 185, 129, 0.3);
        }

        .status.error {
            background: rgba(239, 68, 68, 0.2);
            color: #fca5a5;
            border: 1px solid rgba(239, 68, 68, 0.3);
        }

        .status.cached {
            background: rgba(245, 158, 11, 0.2);
            color: #fbbf24;
            border: 1px solid rgba(245, 158, 11, 0.3);
        }

        .results-grid {
            display: grid;
            gap: 15px;
        }

        .result-item {
            background: rgba(15, 15, 35, 0.9);
            padding: 20px;
            border-radius: 12px;
            border: 1px solid rgba(255, 255, 255, 0.1);
            display: flex;
            justify-content: space-between;
            align-items: center;
            transition: all 0.3s ease;
        }

        .result-item.image-item {
            align-items: flex-start;
        }

        .result-item:hover {
            box-shadow: 0 8px 25px rgba(139, 92, 246, 0.2);
            transform: translateY(-2px);
            border-color: rgba(139, 92, 246, 0.3);
        }

        .result-info {
            flex: 1;
            margin-right: 15px;
        }

        .result-info-with-image {
            display: flex;
            align-items: flex-start;
            gap: 15px;
            flex: 1;
            margin-right: 15px;
        }

        .image-preview {
            width: 80px;
            height: 80px;
            object-fit: cover;
            border-radius: 10px;
            border: 2px solid rgba(255, 255, 255, 0.2);
            flex-shrink: 0;
            transition: all 0.3s ease;
        }

        .image-preview:hover {
            transform: scale(1.1);
            border-color: #8b5cf6;
            box-shadow: 0 5px 20px rgba(139, 92, 246, 0.4);
        }

        .image-preview-error {
            width: 80px;
            height: 80px;
            background: rgba(55, 65, 81, 0.5);
            border: 2px dashed rgba(156, 163, 175, 0.5);
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #9ca3af;
            font-size: 24px;
            flex-shrink: 0;
        }

        .image-details {
            flex: 1;
        }

        .result-title {
            font-weight: 600;
            color: #ffffff;
            margin-bottom: 5px;
            word-break: break-all;
        }

        .result-meta {
            font-size: 14px;
            color: #9ca3af;
        }

        .download-btn {
            background: linear-gradient(45deg, #10b981, #059669);
            color: white;
            border: none;
            padding: 12px 20px;
            border-radius: 10px;
            cursor: pointer;
            font-weight: 600;
            transition: all 0.3s ease;
            text-decoration: none;
            display: inline-block;
            box-shadow: 0 4px 15px rgba(16, 185, 129, 0.3);
        }

        .download-btn:hover {
            transform: translateY(-1px);
            box-shadow: 0 6px 20px rgba(16, 185, 129, 0.4);
            background: linear-gradient(45deg, #059669, #047857);
        }

        .info-section {
            background: rgba(6, 182, 212, 0.1);
            border: 1px solid rgba(6, 182, 212, 0.3);
            color: #67e8f9;
            padding: 20px;
            border-radius: 15px;
            margin-bottom: 20px;
        }

        .info-section h3 {
            margin-bottom: 10px;
            color: #67e8f9;
        }

        .info-section ul {
            list-style-type: none;
            padding-left: 0;
        }

        .info-section li {
            padding: 5px 0;
            position: relative;
            padding-left: 25px;
        }

        .info-section li:before {
            content: '✓';
            position: absolute;
            left: 0;
            color: #10b981;
            font-weight: bold;
        }

        .warning-section {
            margin-top: 15px;
            padding: 15px;
            background: rgba(245, 158, 11, 0.1);
            border: 1px solid rgba(245, 158, 11, 0.3);
            border-radius: 8px;
            color: #fbbf24;
        }

        .debug-section {
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid rgba(239, 68, 68, 0.3);
            color: #fca5a5;
            padding: 20px;
            border-radius: 15px;
            margin-bottom: 20px;
            display: none;
        }

        .debug-section.show {
            display: block;
            animation: fadeIn 0.5s ease;
        }

        .debug-section pre {
            background: rgba(15, 15, 35, 0.8);
            padding: 15px;
            border-radius: 8px;
            overflow-x: auto;
            border: 1px solid rgba(255, 255, 255, 0.1);
            color: #e4e4e7;
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 12px;
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }

        .stat-card {
            background: rgba(15, 15, 35, 0.9);
            padding: 15px;
            border-radius: 10px;
            border: 1px solid rgba(255, 255, 255, 0.1);
            text-align: center;
        }

        .stat-card .stat-value {
            font-size: 24px;
            font-weight: 700;
            color: #8b5cf6;
            margin-bottom: 5px;
        }

        .stat-card .stat-label {
            font-size: 12px;
            color: #9ca3af;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .progress-bar {
            width: 100%;
            height: 8px;
            background: rgba(55, 65, 81, 0.5);
            border-radius: 4px;
            overflow: hidden;
            margin: 10px 0;
        }

        .progress-fill {
            height: 100%;
            background: linear-gradient(45deg, #8b5cf6, #06b6d4);
            transition: width 0.3s ease;
            border-radius: 4px;
        }

        @media (max-width: 768px) {
            .container {
                padding: 20px;
                margin: 10px;
            }

            .header-controls {
                flex-direction: column;
                align-items: stretch;
            }

            .control-buttons {
                justify-content: center;
            }

            .config-grid {
                grid-template-columns: 1fr;
            }

            .button-grid {
                grid-template-columns: 1fr;
            }

            .stats-grid {
                grid-template-columns: repeat(2, 1fr);
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header-controls">
            <div class="php-badge">PHP Web Scraper</div>
            <div class="control-buttons">
                <button class="control-btn" onclick="toggleDebug()" id="debugToggle">
                    🐛 Debug: <?php echo ScraperConfig::get('debug_mode') ? 'ON' : 'OFF'; ?>
                </button>
                <form method="post" style="display: inline;">
                    <button type="submit" name="clear_cache" class="control-btn">
                        🗑️ Clear Cache
                    </button>
                </form>
            </div>
        </div>
        
        <h1>Web Scraper Tool</h1>

        <!-- Tabs -->
        <div class="tabs">
            <button class="tab active" onclick="switchTab('scraper')">🔍 Scraper</button>
            <button class="tab" onclick="switchTab('config')">⚙️ Configuration</button>
            <button class="tab" onclick="switchTab('stats')">📊 Statistics</button>
            <button class="tab" onclick="switchTab('about')">ℹ️ About</button>
        </div>

        <!-- Configuration Tab -->
        <div id="config-tab" class="tab-content">
            <div class="config-section">
                <form method="post">
                    <div class="config-grid">
                        <div class="config-group">
                            <h3>🚀 Performance Settings</h3>
                            <div class="form-field">
                                <label for="max_file_size">Max File Size (MB)</label>
                                <input type="number" id="max_file_size" name="max_file_size" 
                                       value="<?php echo ScraperConfig::get('max_file_size') / 1024 / 1024; ?>" 
                                       min="1" max="500" step="1">
                            </div>
                            <div class="form-field">
                                <label for="timeout">Request Timeout (seconds)</label>
                                <input type="number" id="timeout" name="timeout" 
                                       value="<?php echo ScraperConfig::get('timeout'); ?>" 
                                       min="5" max="120" step="1">
                            </div>
                            <div class="form-field">
                                <label for="cache_duration">Cache Duration (seconds)</label>
                                <input type="number" id="cache_duration" name="cache_duration" 
                                       value="<?php echo ScraperConfig::get('cache_duration'); ?>" 
                                       min="0" max="3600" step="60">
                            </div>
                        </div>

                        <div class="config-group">
                            <h3>🔒 Security Settings</h3>
                            <div class="form-field">
                                <label for="rate_limit">Rate Limit (requests/minute)</label>
                                <input type="number" id="rate_limit" name="rate_limit" 
                                       value="<?php echo ScraperConfig::get('rate_limit'); ?>" 
                                       min="1" max="100" step="1">
                            </div>
                            <div class="checkbox-field">
                                <input type="checkbox" id="block_local_ips" name="block_local_ips" 
                                       <?php echo ScraperConfig::get('block_local_ips') ? 'checked' : ''; ?>>
                                <label for="block_local_ips">Block Local Network Access</label>
                            </div>
                            <div class="checkbox-field">
                                <input type="checkbox" id="log_errors" name="log_errors" 
                                       <?php echo ScraperConfig::get('log_errors') ? 'checked' : ''; ?>>
                                <label for="log_errors">Enable Error Logging</label>
                            </div>
                        </div>

                        <div class="config-group">
                            <h3>🛠️ Feature Settings</h3>
                            <div class="checkbox-field">
                                <input type="checkbox" id="enable_cache" name="enable_cache" 
                                       <?php echo ScraperConfig::get('enable_cache') ? 'checked' : ''; ?>>
                                <label for="enable_cache">Enable Response Caching</label>
                            </div>
                            <div class="checkbox-field">
                                <input type="checkbox" id="debug_mode" name="debug_mode" 
                                       <?php echo ScraperConfig::get('debug_mode') ? 'checked' : ''; ?>>
                                <label for="debug_mode">Enable Debug Mode</label>
                            </div>
                        </div>
                    </div>
                    <div style="text-align: center; margin-top: 20px;">
                        <button type="submit" name="update_config" class="save-config-btn">
                            💾 Save Configuration
                        </button>
                    </div>
                </form>
            </div>
        </div>

        <!-- Statistics Tab -->
        <div id="stats-tab" class="tab-content">
            <div class="config-section">
                <h3>📊 System Statistics</h3>
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-value"><?php echo count(glob('cache/*.json')); ?></div>
                        <div class="stat-label">Cached Items</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value"><?php echo file_exists('logs/scraper_errors.log') ? count(file('logs/scraper_errors.log')) : 0; ?></div>
                        <div class="stat-label">Error Logs</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value"><?php echo round(ScraperConfig::get('max_file_size') / 1024 / 1024); ?>MB</div>
                        <div class="stat-label">Max File Size</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value"><?php echo ScraperConfig::get('rate_limit'); ?>/min</div>
                        <div class="stat-label">Rate Limit</div>
                    </div>
                </div>

                <?php if (file_exists('cache/progress.json')): ?>
                    <?php $progress = json_decode(file_get_contents('cache/progress.json'), true); ?>
                    <div style="margin-top: 20px;">
                        <h4>Current Progress</h4>
                        <div class="progress-bar">
                            <div class="progress-fill" style="width: <?php echo $progress['progress']; ?>%"></div>
                        </div>
                        <p>Processing <?php echo $progress['action']; ?>: <?php echo $progress['current']; ?>/<?php echo $progress['total']; ?> (<?php echo $progress['progress']; ?>%)</p>
                    </div>
                <?php endif; ?>
            </div>
        </div>

        <!-- About Tab -->
        <div id="about-tab" class="tab-content">
            <div class="info-section">
                <h3>🚀 Enhanced Features</h3>
                <ul>
                    <li>Advanced security with rate limiting and IP blocking</li>
                    <li>Intelligent caching system for faster responses</li>
                    <li>Enhanced bot detection and browser mimicking</li>
                    <li>Real-time progress tracking for large operations</li>
                    <li>Comprehensive error logging and debugging</li>
                    <li>Configurable performance and security settings</li>
                    <li>Improved content detection and metadata extraction</li>
                    <li>Mobile-responsive design with modern UI</li>
                </ul>
                
                <div class="warning-section">
                    <strong>⚠️ Usage Guidelines:</strong><br>
                    • Respect robots.txt and website terms of service<br>
                    • Use reasonable delays between requests<br>
                    • Some sites may block automated requests<br>
                    • Always check local laws regarding web scraping
                </div>
            </div>
        </div>

        <!-- Scraper Tab -->
        <div id="scraper-tab" class="tab-content active">
            <?php if ($cache_used): ?>
                <div style="margin-bottom: 15px; padding: 15px; background: rgba(245, 158, 11, 0.1); border: 1px solid rgba(245, 158, 11, 0.3); border-radius: 8px; color: #fbbf24;">
                    <strong>⚡ Cache Hit:</strong> Results loaded from cache (<?php echo ScraperConfig::get('cache_duration'); ?>s TTL)
                </div>
            <?php endif; ?>

            <form method="post" class="form-section" id="scraperForm">
                <input type="text" 
                       name="url" 
                       class="url-input" 
                       placeholder="Enter website URL (e.g., https://example.com)" 
                       value="<?php echo htmlspecialchars($url); ?>" 
                       required>
                
                <input type="hidden" name="action" id="actionField" value="">
                
                <div class="button-grid">
                    <button type="button" onclick="submitForm('whole_site')" class="scrape-btn btn-whole-site">
                        📄 Download Whole Site
                    </button>
                    <button type="button" onclick="submitForm('images')" class="scrape-btn btn-images">
                        🖼️ Extract Images
                    </button>
                    <button type="button" onclick="submitForm('videos')" class="scrape-btn btn-videos">
                        🎥 Extract Videos
                    </button>
                    <button type="button" onclick="submitForm('links')" class="scrape-btn btn-links">
                        🔗 Extract Links
                    </button>
                    <button type="button" onclick="submitForm('text')" class="scrape-btn btn-text">
                        📝 Extract Text Content
                    </button>
                </div>
            </form>

            <?php if (!empty($debug_info) && ScraperConfig::get('debug_mode')): ?>
                <div class="debug-section show">
                    <strong>🐛 Debug Information:</strong><br>
                    <pre><?php echo htmlspecialchars($debug_info); ?></pre>
                </div>
            <?php endif; ?>

            <?php if ($error): ?>
                <div class="results-section">
                    <div class="status error">
                        ❌ <?php echo htmlspecialchars($error); ?>
                    </div>
                </div>
            <?php endif; ?>

            <?php if ($status && !$error): ?>
                <div class="results-section">
                    <div class="status <?php echo $cache_used ? 'cached' : 'success'; ?>">
                        <?php echo $cache_used ? '⚡' : '✅'; ?> <?php echo htmlspecialchars($status); ?>
                    </div>
                    
                    <?php if (!empty($results)): ?>
                        <div class="results-grid">
                            <?php foreach ($results as $index => $item): ?>
                                <div class="result-item <?php echo ($item['type'] ?? '') === 'image' ? 'image-item' : ''; ?>">
                                    
                                    <?php if (($item['type'] ?? '') === 'image'): ?>
                                        <div class="result-info-with-image">
                                            <img src="<?php echo htmlspecialchars($item['url']); ?>" 
                                                 alt="<?php echo htmlspecialchars($item['alt'] ?? 'Image preview'); ?>" 
                                                 class="image-preview"
                                                 onerror="this.style.display='none'; this.nextElementSibling.style.display='flex';"
                                                 loading="lazy">
                                            <div class="image-preview-error" style="display: none;">🖼️</div>
                                            
                                            <div class="image-details">
                                                <div class="result-title">
                                                    <?php echo htmlspecialchars($item['filename'] ?? 'Unknown'); ?>
                                                </div>
                                                <div class="result-meta">
                                                    <?php if (!empty($item['alt'])): ?>
                                                        <strong>Alt:</strong> <?php echo htmlspecialchars($item['alt']); ?><br>
                                                    <?php endif; ?>
                                                    <?php if (!empty($item['width']) && !empty($item['height'])): ?>
                                                        <strong>Dimensions:</strong> <?php echo $item['width']; ?>×<?php echo $item['height']; ?><br>
                                                    <?php endif; ?>
                                                    <strong>URL:</strong> <?php echo htmlspecialchars(strlen($item['url']) > 60 ? substr($item['url'], 0, 60) . '...' : $item['url']); ?>
                                                </div>
                                            </div>
                                        </div>
                                    <?php else: ?>
                                        <div class="result-info">
                                            <div class="result-title">
                                                <?php 
                                                if (isset($item['filename'])) {
                                                    echo htmlspecialchars($item['filename']);
                                                } elseif (isset($item['text'])) {
                                                    echo htmlspecialchars(substr($item['text'], 0, 100) . (strlen($item['text']) > 100 ? '...' : ''));
                                                } else {
                                                    echo 'Item ' . ($index + 1);
                                                }
                                                ?>
                                            </div>
                                            <div class="result-meta">
                                                <?php
                                                if (isset($item['word_count'])) {
                                                    echo 'Words: ' . number_format($item['word_count']) . ' | ';
                                                }
                                                if (isset($item['size'])) {
                                                    echo 'Size: ' . number_format($item['size']) . ' characters';
                                                } elseif (isset($item['platform'])) {
                                                    echo 'Platform: ' . htmlspecialchars($item['platform']);
                                                } elseif (isset($item['url'])) {
                                                    echo htmlspecialchars($item['url']);
                                                }
                                                ?>
                                            </div>
                                        </div>
                                    <?php endif; ?>
                                    
                                    <?php if (isset($item['content'])): ?>
                                        <form method="post" style="display: inline;">
                                            <input type="hidden" name="content" value="<?php echo htmlspecialchars($item['content']); ?>">
                                            <input type="hidden" name="filename" value="<?php echo htmlspecialchars($item['filename']); ?>">
                                            <button type="submit" name="download_content" class="download-btn">
                                                💾 Download
                                            </button>
                                        </form>
                                    <?php elseif (isset($item['url'])): ?>
                                        <a href="<?php echo htmlspecialchars($item['url']); ?>" 
                                           target="_blank" 
                                           class="download-btn">
                                            🔗 Open
                                        </a>
                                    <?php endif; ?>
                                </div>
                            <?php endforeach; ?>
                        </div>
                    <?php endif; ?>
                </div>
            <?php endif; ?>
        </div>
    </div>

    <script>
        let debugMode = <?php echo ScraperConfig::get('debug_mode') ? 'true' : 'false'; ?>;

        function switchTab(tabName) {
            // Hide all tab contents
            document.querySelectorAll('.tab-content').forEach(content => {
                content.classList.remove('active');
            });
            
            // Remove active class from all tabs
            document.querySelectorAll('.tab').forEach(tab => {
                tab.classList.remove('active');
            });
            
            // Show selected tab content
            document.getElementById(tabName + '-tab').classList.add('active');
            
            // Add active class to clicked tab
            event.target.classList.add('active');
        }

        function toggleDebug() {
            debugMode = !debugMode;
            const toggle = document.getElementById('debugToggle');
            const debugSection = document.querySelector('.debug-section');
            
            if (debugMode) {
                toggle.textContent = '🐛 Debug: ON';
                toggle.classList.add('active');
                if (debugSection) {
                    debugSection.classList.add('show');
                }
            } else {
                toggle.textContent = '🐛 Debug: OFF';
                toggle.classList.remove('active');
                if (debugSection) {
                    debugSection.classList.remove('show');
                }
            }
        }

        function submitForm(action) {
            // Set the action value
            document.getElementById('actionField').value = action;
            
            // Get the form and the button that was clicked
            const form = document.getElementById('scraperForm');
            const buttons = document.querySelectorAll('.scrape-btn');
            
            // Find the clicked button by matching the action
            let clickedButton = null;
            buttons.forEach(btn => {
                if (btn.onclick && btn.onclick.toString().includes(action)) {
                    clickedButton = btn;
                }
            });
            
            // Show loading state
            if (clickedButton) {
                clickedButton.disabled = true;
                const originalText = clickedButton.innerHTML;
                clickedButton.innerHTML = '<div style="display: inline-block; width: 20px; height: 20px; border: 2px solid #ffffff; border-top: 2px solid transparent; border-radius: 50%; animation: spin 1s linear infinite; margin-right: 5px;"></div> Processing...';
                
                // Add CSS for spinner animation if not already present
                if (!document.getElementById('spinnerStyle')) {
                    const style = document.createElement('style');
                    style.id = 'spinnerStyle';
                    style.textContent = '@keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }';
                    document.head.appendChild(style);
                }
                
                // Re-enable button and restore text if form submission fails
                setTimeout(() => {
                    clickedButton.disabled = false;
                    clickedButton.innerHTML = originalText;
                }, 30000); // 30 second timeout
            }
            
            // Debug: Log form data if debug mode is on
            if (debugMode) {
                console.log('🐛 Debug Mode: Submitting form with action:', action);
                const formData = new FormData(form);
                console.log('🐛 Form data:');
                for (let [key, value] of formData.entries()) {
                    console.log(`🐛 ${key}: ${value}`);
                }
            }
            
            // Submit the form
            form.submit();
        }

        // Auto-refresh progress if available
        function updateProgress() {
            fetch('cache/progress.json')
                .then(response => response.json())
                .then(data => {
                    const progressBar = document.querySelector('.progress-fill');
                    if (progressBar && data.progress !== undefined) {
                        progressBar.style.width = data.progress + '%';
                    }
                })
                .catch(error => {
                    // Ignore errors - progress file might not exist
                });
        }

        // Initialize
        document.addEventListener('DOMContentLoaded', function() {
            // Set debug mode based on server setting
            <?php if (ScraperConfig::get('debug_mode')): ?>
                debugMode = true;
                const toggle = document.getElementById('debugToggle');
                toggle.classList.add('active');
                const debugSection = document.querySelector('.debug-section');
                if (debugSection) {
                    debugSection.classList.add('show');
                }
            <?php endif; ?>

            // Update progress every 2 seconds if in processing
            setInterval(updateProgress, 2000);

            // Add click handlers for tabs
            document.querySelectorAll('.tab').forEach(tab => {
                tab.addEventListener('click', function(e) {
                    const tabName = this.textContent.includes('Scraper') ? 'scraper' :
                                   this.textContent.includes('Configuration') ? 'config' :
                                   this.textContent.includes('Statistics') ? 'stats' : 'about';
                    switchTab(tabName);
                });
            });

            // Form validation
            const urlInput = document.querySelector('.url-input');
            if (urlInput) {
                urlInput.addEventListener('blur', function() {
                    const url = this.value.trim();
                    if (url && !url.match(/^https?:\/\//)) {
                        this.style.borderColor = '#ef4444';
                        if (!document.getElementById('url-error')) {
                            const error = document.createElement('div');
                            error.id = 'url-error';
                            error.style.color = '#ef4444';
                            error.style.fontSize = '14px';
                            error.style.marginTop = '5px';
                            error.textContent = 'URL must start with http:// or https://';
                            this.parentNode.appendChild(error);
                        }
                    } else {
                        this.style.borderColor = '';
                        const error = document.getElementById('url-error');
                        if (error) error.remove();
                    }
                });
            }

            // Configuration form auto-save warning
            const configInputs = document.querySelectorAll('#config-tab input');
            configInputs.forEach(input => {
                input.addEventListener('change', function() {
                    const saveBtn = document.querySelector('.save-config-btn');
                    if (saveBtn && !saveBtn.classList.contains('unsaved')) {
                        saveBtn.classList.add('unsaved');
                        saveBtn.style.background = 'linear-gradient(45deg, #f59e0b, #d97706)';
                        saveBtn.textContent = '⚠️ Save Changes';
                    }
                });
            });

            // Keyboard shortcuts
            document.addEventListener('keydown', function(e) {
                // Ctrl/Cmd + Enter to submit form
                if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
                    const activeTab = document.querySelector('.tab-content.active');
                    if (activeTab && activeTab.id === 'scraper-tab') {
                        const firstBtn = document.querySelector('.scrape-btn');
                        if (firstBtn) firstBtn.click();
                    }
                }

                // Ctrl/Cmd + D for debug toggle
                if ((e.ctrlKey || e.metaKey) && e.key === 'd') {
                    e.preventDefault();
                    toggleDebug();
                }
            });

            // Tooltip functionality
            const tooltips = {
                'max_file_size': 'Maximum size of content to download. Larger files will be rejected.',
                'timeout': 'How long to wait for a response before giving up.',
                'rate_limit': 'Maximum requests per minute from the same IP address.',
                'cache_duration': 'How long to store results in cache (0 = disabled).',
                'block_local_ips': 'Prevent access to local network addresses for security.',
                'enable_cache': 'Store results temporarily to speed up repeated requests.',
                'log_errors': 'Save error details to log files for debugging.',
                'debug_mode': 'Show detailed information about requests and responses.'
            };

            Object.keys(tooltips).forEach(id => {
                const element = document.getElementById(id);
                if (element) {
                    element.title = tooltips[id];
                    element.addEventListener('mouseenter', function() {
                        // Could add fancy tooltips here
                    });
                }
            });
        });

        // Utility functions
        function formatBytes(bytes) {
            if (bytes === 0) return '0 Bytes';
            const k = 1024;
            const sizes = ['Bytes', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }

        function timeAgo(timestamp) {
            const now = Date.now() / 1000;
            const diff = now - timestamp;
            
            if (diff < 60) return 'Just now';
            if (diff < 3600) return Math.floor(diff / 60) + ' minutes ago';
            if (diff < 86400) return Math.floor(diff / 3600) + ' hours ago';
            return Math.floor(diff / 86400) + ' days ago';
        }

        // Export functions for potential use
        window.scraperUtils = {
            formatBytes,
            timeAgo,
            updateProgress,
            toggleDebug,
            submitForm,
            switchTab
        };
    </script>

</body>
</html>