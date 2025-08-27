<?php
/*
Plugin Name: Advanced Security IP Blocker
Description: Комплексная система безопасности: блокировка IP, защита wp-login.php, блокировка опасных файлов и ботов с поддержкой ASN
Plugin URI: https://github.com/RobertoBennett/IP-Blocker-Manager
Version: 2.3
Author: Robert Bennett
Text Domain: IP Blocker Manager
*/

defined('ABSPATH') || exit;

class Advanced_Security_Blocker {
    private $htaccess_path;
    private $marker_ip = "# IP_BLOCKER_SAFE_MARKER";
    private $marker_login = "# LOGIN_PROTECTION_MARKER";
    private $marker_files = "# DANGEROUS_FILES_MARKER";
    private $marker_bots = "# BOT_PROTECTION_MARKER";
    private $backup_dir;
    private $cache_dir;
    private $log = [];

    public function __construct() {
        $this->htaccess_path = ABSPATH . '.htaccess';
        $this->backup_dir = WP_CONTENT_DIR . '/security-blocker-backups/';
        $this->cache_dir = WP_CONTENT_DIR . '/security-blocker-cache/';
        
        add_action('admin_menu', [$this, 'admin_menu']);
        register_deactivation_hook(__FILE__, [$this, 'deactivate']);
        add_action('admin_init', [$this, 'create_backup_dir']);
        add_action('admin_enqueue_scripts', [$this, 'enqueue_scripts']);
        add_action('admin_init', [$this, 'init_default_settings']);
        add_action('admin_init', [$this, 'handle_backup_request']);
        add_action('admin_init', [$this, 'handle_cache_clear']);
    }

    public function init_default_settings() {
        // Настройки по умолчанию для опасных файлов
        if (!get_option('asb_dangerous_files')) {
            $default_files = ".htaccess\n.htpasswd\nwp-config.php\nreadme.html\nlicense.txt\nwp-config-sample.php\n.DS_Store\nThumbs.db\n*.sql\n*.log\n*.bak\n*.tmp\n*.swp\n*.old\n*.orig\n*.save\nerror_log\ndebug.log";
            update_option('asb_dangerous_files', $default_files);
        }
        
        // Настройки по умолчанию для ботов
        if (!get_option('asb_blocked_bots')) {
            $default_bots = "360Spider|404checker|80legs|Abonti|Aboundex|AhrefsBot|Alexibot|Applebot|Arachni|ASPSeek|Asterias|BackDoorBot|BackStreet|BackWeb|Badass|Bandit|Baiduspider|BatchFTP|Bigfoot|BotALot|Buddy|BuiltBotTough|Bullseye|BunnySlippers|CheeseBot|CherryPicker|ChinaClaw|Collector|Copier|CopyRightCheck|cosmos|Crescent|Custo|CyberSpyder|DISCo|DIIbot|DittoSpyder|Download|Downloader|Dumbot|EasouSpider|eCatch|EirGrabber|EmailCollector|EmailSiphon|EmailWolf|Express|Extractor|EyeNetIE|FlashGet|GetRight|GetWeb|Grafula|HMView|HTTrack|InterGET|JetCar|larbin|LeechFTP|Mister|Navroad|NearSite|NetAnts|NetSpider|NetZIP|Nutch|Octopus|PageGrabber|pavuk|pcBrowser|PeoplePal|planetwork|psbot|purebot|pycurl|RealDownload|ReGet|Rippers|SiteSnagger|SmartDownload|SuperBot|SuperHTTP|Surfbot|tAkeOut|VoidEYE|WebAuto|WebBandit|WebCopier|WebFetch|WebLeacher|WebReaper|WebSauger|WebStripper|WebWhacker|WebZIP|Wget|Widow|WWWOFFLE|Xenu|Zeus";
            update_option('asb_blocked_bots', $default_bots);
        }
    }

    public function handle_backup_request() {
        if (isset($_GET['page']) && $_GET['page'] === 'advanced-security-blocker' && isset($_GET['backup'])) {
            if (current_user_can('manage_options')) {
                $this->create_backup();
                wp_redirect(admin_url('options-general.php?page=advanced-security-blocker&backup_created=1'));
                exit;
            }
        }
    }

    public function handle_cache_clear() {
        if (isset($_GET['page']) && $_GET['page'] === 'advanced-security-blocker' && isset($_GET['clear_cache'])) {
            if (current_user_can('manage_options')) {
                $this->clear_asn_cache();
                wp_redirect(admin_url('options-general.php?page=advanced-security-blocker&cache_cleared=1'));
                exit;
            }
        }
    }

    public function enqueue_scripts($hook) {
        if ($hook !== 'settings_page_advanced-security-blocker') return;
        
        // Добавляем jQuery если еще не подключен
        wp_enqueue_script('jquery');
    }

    // ASN кэширование и API методы
    private function get_asn_cache_file($asn) {
        return $this->cache_dir . 'asn_' . $asn . '.json';
    }

    private function get_cached_asn_ranges($asn) {
        $cache_file = $this->get_asn_cache_file($asn);
        
        if (file_exists($cache_file)) {
            $cache_data = json_decode(file_get_contents($cache_file), true);
            
            // Проверяем, не устарел ли кэш (24 часа)
            if (isset($cache_data['timestamp']) && 
                (time() - $cache_data['timestamp']) < 86400) {
                
                $this->log[] = "ASN AS{$asn}: использованы кэшированные данные";
                return $cache_data['ranges'];
            }
        }
        
        return false;
    }

    private function cache_asn_ranges($asn, $ranges) {
        $cache_file = $this->get_asn_cache_file($asn);
        $cache_data = [
            'timestamp' => time(),
            'asn' => $asn,
            'ranges' => $ranges
        ];
        
        file_put_contents($cache_file, json_encode($cache_data));
        $this->log[] = "ASN AS{$asn}: данные кэшированы";
    }

    private function clear_asn_cache() {
        $cache_files = glob($this->cache_dir . 'asn_*.json');
        $cleared = 0;
        
        foreach ($cache_files as $file) {
            if (unlink($file)) {
                $cleared++;
            }
        }
        
        $this->log[] = "Очищено кэш файлов ASN: {$cleared}";
        return $cleared;
    }

    // Получение IP диапазонов по ASN
    private function get_asn_ip_ranges($asn) {
        // Сначала проверяем кэш
        $cached_ranges = $this->get_cached_asn_ranges($asn);
        if ($cached_ranges !== false) {
            return $cached_ranges;
        }

        $ip_ranges = [];
        
        // Убираем префикс AS если есть
        $asn = str_replace(['AS', 'as'], '', $asn);
        
        if (!is_numeric($asn)) {
            return false;
        }
        
        // Используем несколько источников для получения диапазонов
        $sources = [
            "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{$asn}",
            "https://api.hackertarget.com/aslookup/?q=AS{$asn}"
        ];
        
        foreach ($sources as $url) {
            $response = $this->fetch_url($url);
            if ($response) {
                if (strpos($url, 'ripe.net') !== false) {
                    $data = json_decode($response, true);
                    if (isset($data['data']['prefixes'])) {
                        foreach ($data['data']['prefixes'] as $prefix) {
                            if (isset($prefix['prefix'])) {
                                $ip_ranges[] = $prefix['prefix'];
                            }
                        }
                    }
                } else if (strpos($url, 'hackertarget.com') !== false) {
                    $lines = explode("\n", $response);
                    foreach ($lines as $line) {
                        if (preg_match('/(\d+\.\d+\.\d+\.\d+\/\d+)/', $line, $matches)) {
                            $ip_ranges[] = $matches[1];
                        }
                    }
                }
                
                if (!empty($ip_ranges)) {
                    break; // Если получили данные, не пробуем другие источники
                }
            }
        }
        
        $unique_ranges = array_unique($ip_ranges);
        
        // Кэшируем результат
        if (!empty($unique_ranges)) {
            $this->cache_asn_ranges($asn, $unique_ranges);
        }
        
        return $unique_ranges;
    }

    // Простой HTTP клиент
    private function fetch_url($url, $timeout = 10) {
        // Используем cURL если доступен
        if (function_exists('curl_init')) {
            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, $url);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_TIMEOUT, $timeout);
            curl_setopt($ch, CURLOPT_USERAGENT, 'WordPress Security Plugin');
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
            curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
            
            $response = curl_exec($ch);
            $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);
            
            if ($http_code === 200) {
                return $response;
            }
        }
        
        // Fallback на file_get_contents
        if (ini_get('allow_url_fopen')) {
            $context = stream_context_create([
                'http' => [
                    'timeout' => $timeout,
                    'user_agent' => 'WordPress Security Plugin'
                ]
            ]);
            
            return @file_get_contents($url, false, $context);
        }
        
        return false;
    }

    private function output_admin_styles() {
        ?>
        <style>
        .security-tabs {
            margin: 20px 0;
        }
        .security-tab-nav {
            border-bottom: 1px solid #ccc;
            margin-bottom: 20px;
            background: #f9f9f9;
            padding: 0;
        }
        .security-tab-nav button {
            display: inline-block;
            padding: 12px 20px;
            border: none;
            background: #f1f1f1;
            color: #333;
            cursor: pointer;
            margin-right: 2px;
            font-size: 14px;
            border-top: 3px solid transparent;
        }
        .security-tab-nav button:hover {
            background: #e8e8e8;
        }
        .security-tab-nav button.active {
            background: #fff;
            border-top: 3px solid #0073aa;
            color: #0073aa;
            font-weight: 600;
        }
        .security-tab-content {
            display: none;
            padding: 20px 0;
        }
        .security-tab-content.active {
            display: block;
        }
        .ip-blocker-textarea-wrapper {
            position: relative;
            width: 100%;
            max-width: 800px;
            display: block;
            clear: both;
        }
        .ip-blocker-line-numbers {
            position: absolute;
            left: 0;
            top: 1px;
            bottom: 1px;
            width: 45px;
            overflow: hidden;
            background-color: #f5f5f5;
            border-right: 1px solid #ddd;
            text-align: right;
            padding: 11px 8px 11px 5px;
            font-family: Consolas, Monaco, monospace;
            font-size: 13px;
            line-height: 1.4;
            color: #666;
            user-select: none;
            pointer-events: none;
            z-index: 1;
            box-sizing: border-box;
        }
        .ip-blocker-textarea-wrapper textarea {
            padding: 10px 10px 10px 55px !important;
            box-sizing: border-box;
            font-family: Consolas, Monaco, monospace;
            font-size: 13px;
            line-height: 1.4;
            width: 100%;
            resize: vertical;
            border: 1px solid #ddd;
            border-radius: 3px;
            background-color: #fff;
        }
        .simple-textarea {
            width: 100%;
            max-width: 800px;
            font-family: Consolas, Monaco, monospace;
            font-size: 13px;
            line-height: 1.4;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 3px;
        }
        .ip-blocker-description {
            margin-top: 10px !important;
            margin-bottom: 0 !important;
            clear: both;
            display: block;
            width: 100%;
        }
        .operation-log {
            background: #f8f8f8;
            border-left: 4px solid #0073aa;
            padding: 10px 15px;
            margin: 15px 0;
        }
        .operation-log ul {
            margin: 5px 0;
            padding-left: 20px;
        }
        .log-entry {
            margin: 3px 0;
        }
        .security-warning {
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            border-left: 4px solid #f39c12;
            padding: 10px 15px;
            margin: 15px 0;
        }
        .security-info {
            background: #d1ecf1;
            border: 1px solid #bee5eb;
            border-left: 4px solid #17a2b8;
            padding: 10px 15px;
            margin: 15px 0;
        }
        .card {
            background: #fff;
            border: 1px solid #ccd0d4;
            border-radius: 4px;
            padding: 15px;
            margin: 15px 0;
        }
        .card h3 {
            margin-top: 0;
        }
        .card ul {
            margin: 10px 0;
        }
        .card li {
            margin: 5px 0;
        }
        .asn-info {
            background: #e8f4fd;
            border: 1px solid #b8daff;
            border-left: 4px solid #007cba;
            padding: 10px 15px;
            margin: 15px 0;
        }
        </style>
        <?php
    }

    public function create_backup_dir() {
        if (!is_dir($this->backup_dir)) {
            wp_mkdir_p($this->backup_dir);
            // Создаем .htaccess для защиты папки с бекапами
            $htaccess_content = "Order deny,allow\nDeny from all\n";
            file_put_contents($this->backup_dir . '.htaccess', $htaccess_content);
        }
        
        if (!is_dir($this->cache_dir)) {
            wp_mkdir_p($this->cache_dir);
            // Создаем .htaccess для защиты папки с кэшем
            $htaccess_content = "Order deny,allow\nDeny from all\n";
            file_put_contents($this->cache_dir . '.htaccess', $htaccess_content);
        }
    }

    public function admin_menu() {
        add_options_page(
            'Расширенная Безопасность',
            'Безопасность',
            'manage_options',
            'advanced-security-blocker',
            [$this, 'settings_page']
        );
    }

    public function settings_page() {
        if (!current_user_can('manage_options')) {
            return;
        }

        $error = $success = '';
        $operation_log = '';

        // Показываем сообщения
        if (isset($_GET['backup_created'])) {
            $success = 'Резервная копия .htaccess успешно создана!';
        }
        
        if (isset($_GET['cache_cleared'])) {
            $success = 'Кэш ASN успешно очищен!';
        }

        // Обработка форм
        if (isset($_POST['submit_ip_blocker'])) {
            check_admin_referer('security_blocker_update');
            $ips = isset($_POST['ip_addresses']) ? sanitize_textarea_field($_POST['ip_addresses']) : '';
            $result = $this->update_ip_rules($ips);
            if ($result === true) {
                $success = 'IP правила успешно обновлены!';
            } else {
                $error = 'Ошибка IP правил: ' . $result;
            }
        }

        if (isset($_POST['submit_login_protection'])) {
            check_admin_referer('security_blocker_update');
            $whitelist_ips = isset($_POST['login_whitelist_ips']) ? sanitize_textarea_field($_POST['login_whitelist_ips']) : '';
            $result = $this->update_login_protection($whitelist_ips);
            if ($result === true) {
                $success = 'Защита wp-login.php успешно обновлена!';
            } else {
                $error = 'Ошибка защиты входа: ' . $result;
            }
        }

        if (isset($_POST['submit_file_protection'])) {
            check_admin_referer('security_blocker_update');
            $dangerous_files = isset($_POST['dangerous_files']) ? sanitize_textarea_field($_POST['dangerous_files']) : '';
            update_option('asb_dangerous_files', $dangerous_files);
            $result = $this->update_file_protection($dangerous_files);
            if ($result === true) {
                $success = 'Защита от опасных файлов успешно обновлена!';
            } else {
                $error = 'Ошибка защиты файлов: ' . $result;
            }
        }

        if (isset($_POST['submit_bot_protection'])) {
            check_admin_referer('security_blocker_update');
            $blocked_bots = isset($_POST['blocked_bots']) ? sanitize_textarea_field($_POST['blocked_bots']) : '';
            update_option('asb_blocked_bots', $blocked_bots);
            $result = $this->update_bot_protection($blocked_bots);
            if ($result === true) {
                $success = 'Защита от ботов успешно обновлена!';
            } else {
                $error = 'Ошибка защиты от ботов: ' . $result;
            }
        }

        // Формируем лог операций
        if (!empty($this->log)) {
            $operation_log = '<div class="operation-log"><strong>Журнал операций:</strong><ul>';
            foreach ($this->log as $entry) {
                $operation_log .= '<li class="log-entry">' . esc_html($entry) . '</li>';
            }
            $operation_log .= '</ul></div>';
        }

        // Получаем текущие данные
        $current_ips = $this->get_current_ips();
        $current_whitelist = $this->get_current_login_whitelist();
        $current_files = get_option('asb_dangerous_files', '');
        $current_bots = get_option('asb_blocked_bots', '');
        $current_user_ip = $this->get_user_ip();
        ?>
        <div class="wrap">
            <h1>Расширенная Система Безопасности</h1>
            
            <?php if ($error) : ?>
                <div class="notice notice-error"><p><?php echo esc_html($error); ?></p></div>
            <?php endif; ?>
            
            <?php if ($success) : ?>
                <div class="notice notice-success"><p><?php echo esc_html($success); ?></p></div>
                <?php echo $operation_log; ?>
            <?php endif; ?>

            <?php $this->output_admin_styles(); ?>

            <div class="security-tabs">
                <div class="security-tab-nav">
                    <button type="button" data-tab="tab-ip-blocking" class="active">Блокировка IP</button>
                    <button type="button" data-tab="tab-login-protection">Защита wp-login.php</button>
                    <button type="button" data-tab="tab-file-protection">Блокировка файлов</button>
                    <button type="button" data-tab="tab-bot-protection">Защита от ботов</button>
                    <button type="button" data-tab="tab-status">Статус системы</button>
                </div>

                <!-- Вкладка блокировки IP -->
                <div id="tab-ip-blocking" class="security-tab-content active" style="display: block;">
                    <h2>Блокировка IP-адресов</h2>
                    <div class="asn-info">
                        <strong>Новая функция!</strong> Теперь поддерживается блокировка по ASN (Autonomous System Number).
                        Просто добавьте номер ASN в формате <code>AS15169</code> или <code>15169</code>
                    </div>
                    <form method="post">
                        <?php wp_nonce_field('security_blocker_update'); ?>
                        <table class="form-table">
                            <tr>
                                <th><label for="ip_addresses">Заблокированные IP:</label></th>
                                <td>
                                    <div class="ip-blocker-textarea-wrapper">
                                        <div class="ip-blocker-line-numbers"></div>
                                        <textarea name="ip_addresses" id="ip_addresses" rows="15" cols="50" 
                                            class="large-text code" placeholder="192.168.0.1&#10;192.168.1.0/24&#10;AS15169"><?php 
                                            echo esc_textarea($current_ips); 
                                        ?></textarea>
                                    </div>
                                    <p class="description ip-blocker-description">
                                        По одной записи на строку. Поддерживаемые форматы:<br>
                                        • Одиночный IP: <code>192.168.1.100</code><br>
                                        • CIDR диапазон: <code>192.168.1.0/24</code><br>
                                        • ASN (автономная система): <code>AS15169</code> или <code>15169</code><br>
                                        <em>ASN автоматически преобразуется в список IP диапазонов</em>
                                    </p>
                                </td>
                            </tr>
                        </table>
                        <p>
                            <button type="submit" name="submit_ip_blocker" class="button button-primary">
                                Сохранить блокировку IP
                            </button>
                        </p>
                    </form>
                </div>

                <!-- Вкладка защиты wp-login.php -->
                <div id="tab-login-protection" class="security-tab-content">
                    <h2>Ограничение доступа к wp-login.php</h2>
                    <div class="security-warning">
                        <strong>Внимание!</strong> Убедитесь, что ваш IP-адрес добавлен в белый список, иначе вы не сможете войти в админ-панель!
                        <br>Ваш текущий IP: <strong><?php echo esc_html($current_user_ip); ?></strong>
                    </div>
                    <div class="asn-info">
                        <strong>Поддержка ASN!</strong> Можно разрешить доступ целым автономным системам, например <code>AS15169</code> для Google.
                    </div>
                    <form method="post">
                        <?php wp_nonce_field('security_blocker_update'); ?>
                        <table class="form-table">
                            <tr>
                                <th><label for="login_whitelist_ips">Разрешенные IP для wp-login.php:</label></th>
                                <td>
                                    <div class="ip-blocker-textarea-wrapper">
                                        <div class="ip-blocker-line-numbers"></div>
                                        <textarea name="login_whitelist_ips" id="login_whitelist_ips" rows="10" cols="50" 
                                            class="large-text code" placeholder="<?php echo esc_attr($current_user_ip); ?>&#10;192.168.1.0/24&#10;AS15169"><?php 
                                            echo esc_textarea($current_whitelist); 
                                        ?></textarea>
                                    </div>
                                    <p class="description ip-blocker-description">
                                        По одной записи на строку. Поддерживаемые форматы:<br>
                                        • Одиночный IP: <code>192.168.1.100</code><br>
                                        • CIDR диапазон: <code>192.168.1.0/24</code><br>
                                        • ASN (автономная система): <code>AS15169</code> или <code>15169</code><br>
                                        • Маска подсети: <code>192.168.1.0 255.255.255.0</code><br>
                                        • Частичный IP: <code>192.168.1</code><br>
                                        <em>ASN автоматически преобразуется в список разрешенных диапазонов</em>
                                    </p>
                                </td>
                            </tr>
                        </table>
                        <p>
                            <button type="submit" name="submit_login_protection" class="button button-primary">
                                Сохранить защиту входа
                            </button>
                            <button type="button" class="button" onclick="addCurrentIP();">
                                Добавить мой IP
                            </button>
                        </p>
                    </form>
                </div>

                <!-- Вкладка блокировки файлов -->
                <div id="tab-file-protection" class="security-tab-content">
                    <h2>Блокировка опасных файлов</h2>
                    <div class="security-info">
                        Эта функция блокирует доступ к потенциально опасным файлам. Можно использовать маски файлов (например, *.log для всех .log файлов).
                    </div>
                    <form method="post">
                        <?php wp_nonce_field('security_blocker_update'); ?>
                        <table class="form-table">
                            <tr>
                                <th><label for="dangerous_files">Заблокированные файлы:</label></th>
                                <td>
                                    <textarea name="dangerous_files" id="dangerous_files" rows="15" cols="80" 
                                        class="simple-textarea" placeholder=".htaccess"><?php 
                                        echo esc_textarea($current_files); 
                                    ?></textarea>
                                    <p class="description">По одному файлу/маске на строку. Поддерживаются маски с * (например, *.log, *.bak)</p>
                                </td>
                            </tr>
                        </table>
                        <p>
                            <button type="submit" name="submit_file_protection" class="button button-primary">
                                Сохранить защиту файлов
                            </button>
                        </p>
                    </form>
                </div>

                <!-- Вкладка защиты от ботов -->
                <div id="tab-bot-protection" class="security-tab-content">
                    <h2>Блокировка ботов и вредоносных User-Agent</h2>
                    <div class="security-info">
                        Список User-Agent строк, разделенных символом "|". Запросы с этими User-Agent будут заблокированы.
                    </div>
                    <form method="post">
                        <?php wp_nonce_field('security_blocker_update'); ?>
                        <table class="form-table">
                            <tr>
                                <th><label for="blocked_bots">Заблокированные User-Agent:</label></th>
                                <td>
                                    <textarea name="blocked_bots" id="blocked_bots" rows="10" cols="80" 
                                        class="simple-textarea" placeholder="BadBot|SpamBot|Crawler"><?php 
                                        echo esc_textarea($current_bots); 
                                    ?></textarea>
                                    <p class="description">User-Agent строки, разделенные символом "|". Поддерживается частичное совпадение.</p>
                                </td>
                            </tr>
                        </table>
                        <p>
                            <button type="submit" name="submit_bot_protection" class="button button-primary">
                                Сохранить защиту от ботов
                            </button>
                        </p>
                    </form>
                </div>

                <!-- Вкладка статуса -->
                <div id="tab-status" class="security-tab-content">
                    <h2>Статус системы безопасности</h2>
                    <div class="card">
                        <h3>Системная информация</h3>
                        <ul>
                            <li>Файл .htaccess: <?php echo is_writable($this->htaccess_path) ? 
                                '<span style="color:green">✓ Доступен для записи</span>' : 
                                '<span style="color:red">✗ Недоступен для записи</span>'; ?></li>
                            <li>Резервные копии: <?php echo is_writable($this->backup_dir) ? 
                                '<span style="color:green">✓ Доступны</span>' : 
                                '<span style="color:red">✗ Недоступны</span>'; ?></li>
                            <li>Кэш ASN: <?php echo is_writable($this->cache_dir) ? 
                                '<span style="color:green">✓ Доступен</span>' : 
                                '<span style="color:red">✗ Недоступен</span>'; ?></li>
                            <li>Последняя резервная копия: <?php 
                                $backups = glob($this->backup_dir . 'htaccess-*.bak');
                                if (!empty($backups)) {
                                    rsort($backups);
                                    echo '<span style="color:green">' . date('d.m.Y H:i:s', filemtime($backups[0])) . '</span>';
                                } else {
                                    echo '<span style="color:orange">не создана</span>';
                                }
                            ?></li>
                            <li>Кэшированных ASN: <?php 
                                $cache_files = glob($this->cache_dir . 'asn_*.json');
                                echo '<span style="color:blue">' . count($cache_files) . '</span>';
                            ?></li>
                            <li>Ваш текущий IP: <strong><?php echo esc_html($current_user_ip); ?></strong></li>
                        </ul>
                    </div>
                    
                    <div class="card">
                        <h3>Активные защиты</h3>
                        <ul>
                            <li>Блокировка IP: <?php echo !empty($current_ips) ? 
                                '<span style="color:green">✓ Активна (' . count(array_filter(explode("\n", trim($current_ips)))) . ' записей)</span>' : 
                                '<span style="color:gray">○ Неактивна</span>'; ?></li>
                            <li>Защита wp-login.php: <?php echo !empty($current_whitelist) ? 
                                '<span style="color:green">✓ Активна (' . count(array_filter(explode("\n", trim($current_whitelist)))) . ' разрешенных записей)</span>' : 
                                '<span style="color:gray">○ Неактивна</span>'; ?></li>
                            <li>Блокировка файлов: <?php echo !empty($current_files) ? 
                                '<span style="color:green">✓ Активна (' . count(array_filter(explode("\n", trim($current_files)))) . ' правил)</span>' : 
                                '<span style="color:gray">○ Неактивна</span>'; ?></li>
                            <li>Защита от ботов: <?php echo !empty($current_bots) ? 
                                '<span style="color:green">✓ Активна</span>' : 
                                '<span style="color:gray">○ Неактивна</span>'; ?></li>
                        </ul>
                    </div>

                    <p>
                        <a href="<?php echo esc_url(admin_url('options-general.php?page=advanced-security-blocker&backup=1')); ?>" 
                           class="button">
                            Создать резервную копию .htaccess
                        </a>
                        <a href="<?php echo esc_url(admin_url('options-general.php?page=advanced-security-blocker&clear_cache=1')); ?>" 
                           class="button">
                            Очистить кэш ASN
                        </a>
                    </p>
                </div>
            </div>
        </div>

        <script>
        function addCurrentIP() {
            var textarea = document.getElementById('login_whitelist_ips');
            var currentIP = '<?php echo esc_js($current_user_ip); ?>';
            if (textarea && textarea.value.indexOf(currentIP) === -1) {
                textarea.value += (textarea.value ? '\n' : '') + currentIP;
            }
        }

        // Инициализация после загрузки DOM
        document.addEventListener('DOMContentLoaded', function() {
            // Функция переключения вкладок
            function showTab(tabId) {
                var contents = document.querySelectorAll('.security-tab-content');
                var buttons = document.querySelectorAll('.security-tab-nav button');
                
                contents.forEach(function(content) {
                    content.classList.remove('active');
                    content.style.display = 'none';
                });
                
                buttons.forEach(function(button) {
                    button.classList.remove('active');
                });
                
                var targetTab = document.getElementById(tabId);
                var targetButton = document.querySelector('.security-tab-nav button[data-tab="' + tabId + '"]');
                
                if (targetTab) {
                    targetTab.classList.add('active');
                    targetTab.style.display = 'block';
                }
                
                if (targetButton) {
                    targetButton.classList.add('active');
                }
            }
            
            // Обработчик клика по кнопкам вкладок
            var tabButtons = document.querySelectorAll('.security-tab-nav button');
            tabButtons.forEach(function(button) {
                button.addEventListener('click', function(e) {
                    e.preventDefault();
                    var tabId = this.getAttribute('data-tab');
                    showTab(tabId);
                });
            });
            
            // Показываем первую вкладку по умолчанию
            showTab("tab-ip-blocking");
            
            // Нумерация строк для textarea
            function setupLineNumbers(wrapper) {
                var textarea = wrapper.querySelector('textarea');
                var lineNumbersDiv = wrapper.querySelector('.ip-blocker-line-numbers');
                
                if (!textarea || !lineNumbersDiv) return;
                
                function updateLineNumbers() {
                    var text = textarea.value;
                    var lines = text ? text.split('\n').length : 1;
                    var lineNumbers = '';
                    
                    for (var i = 1; i <= lines; i++) {
                        lineNumbers += i + (i < lines ? '\n' : '');
                    }
                    
                    lineNumbersDiv.textContent = lineNumbers;
                }
                
                textarea.addEventListener('input', updateLineNumbers);
                textarea.addEventListener('keyup', updateLineNumbers);
                textarea.addEventListener('paste', updateLineNumbers);
                textarea.addEventListener('scroll', function() {
                    lineNumbersDiv.scrollTop = textarea.scrollTop;
                });
                
                updateLineNumbers();
            }
            
            // Инициализация нумерации строк
            var wrappers = document.querySelectorAll('.ip-blocker-textarea-wrapper');
            wrappers.forEach(setupLineNumbers);
        });
        </script>
        <?php
    }

    private function get_user_ip() {
        // Получаем реальный IP пользователя с учетом прокси
        $ip_keys = ['HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'HTTP_CLIENT_IP', 'REMOTE_ADDR'];
        
        foreach ($ip_keys as $key) {
            if (!empty($_SERVER[$key])) {
                $ips = explode(',', $_SERVER[$key]);
                $ip = trim($ips[0]);
                if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                    return $ip;
                }
            }
        }
        
        return isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '';
    }

    // Обновленная функция блокировки IP с поддержкой ASN
    private function update_ip_rules($ips) {
        $this->log = [];
        
        try {
            $this->create_backup();
            $this->log[] = 'Создана резервная копия .htaccess';
            
            $ip_list = explode("\n", $ips);
            $ip_list = array_map('trim', $ip_list);
            $ip_list = array_filter($ip_list);
            
            $original_count = count($ip_list);
            $ip_list = array_unique($ip_list);
            $duplicates_count = $original_count - count($ip_list);
            
            if ($duplicates_count > 0) {
                $this->log[] = "Удалено дубликатов: $duplicates_count";
            }
            
            $rules = [];
            $valid_ips = [];
            $invalid_ips = [];
            $asn_ranges = [];
            
            foreach ($ip_list as $entry) {
                // Проверяем, является ли это ASN
                if (preg_match('/^AS?(\d+)$/i', $entry, $matches)) {
                    $asn = $matches[1];
                    $this->log[] = "Обработка ASN: AS{$asn}";
                    
                    $ranges = $this->get_asn_ip_ranges($asn);
                    if ($ranges && !empty($ranges)) {
                        foreach ($ranges as $range) {
                            $rules[] = "deny from {$range}";
                            $asn_ranges[] = $range;
                        }
                        $this->log[] = "ASN AS{$asn}: добавлено " . count($ranges) . " диапазонов";
                    } else {
                        $this->log[] = "ASN AS{$asn}: не удалось получить диапазоны";
                        $invalid_ips[] = $entry;
                    }
                }
                // Проверяем CIDR диапазон
                else if (strpos($entry, '/') !== false) {
                    list($ip, $mask) = explode('/', $entry, 2);
                    if (filter_var($ip, FILTER_VALIDATE_IP) && 
                        is_numeric($mask) && $mask >= 0 && $mask <= 32) {
                        $rules[] = "deny from {$entry}";
                        $valid_ips[] = $entry;
                    } else {
                        $invalid_ips[] = $entry;
                    }
                }
                // Обычный IP
                else if (filter_var($entry, FILTER_VALIDATE_IP)) {
                    $rules[] = "deny from {$entry}";
                    $valid_ips[] = $entry;
                } else {
                    $invalid_ips[] = $entry;
                }
            }
            
            if (!empty($invalid_ips)) {
                $this->log[] = "Недопустимые записи (игнорированы): " . implode(', ', $invalid_ips);
            }
            
            $htaccess = file_exists($this->htaccess_path) ? 
                file_get_contents($this->htaccess_path) : '';
            
            $pattern = '/\n?' . preg_quote($this->marker_ip, '/') . '.*?' . preg_quote($this->marker_ip, '/') . '/s';
            $htaccess = preg_replace($pattern, '', $htaccess);
            
            if (!empty($rules)) {
                $block = "\n" . $this->marker_ip . "\n" . implode("\n", $rules) . "\n" . $this->marker_ip . "\n";
                $htaccess = $block . $htaccess;
                $this->log[] = "Добавлено IP: " . count($valid_ips) . ", ASN диапазонов: " . count($asn_ranges);
            } else {
                $this->log[] = "Все правила блокировки IP удалены";
            }
            
            if (!file_put_contents($this->htaccess_path, $htaccess)) {
                throw new Exception('Не удалось записать в .htaccess');
            }
            
            $this->log[] = "Изменения успешно применены";
            return true;
            
        } catch (Exception $e) {
            $this->restore_backup();
            $this->log[] = "Ошибка: восстановлена резервная копия";
            return $e->getMessage();
        }
    }

    // Обновленная функция защиты wp-login.php с поддержкой ASN
    private function update_login_protection($whitelist_ips) {
        $this->log = [];
        
        try {
            $this->create_backup();
            $this->log[] = 'Создана резервная копия .htaccess';
            
            $htaccess = file_exists($this->htaccess_path) ? 
                file_get_contents($this->htaccess_path) : '';
            
            $pattern = '/\n?' . preg_quote($this->marker_login, '/') . '.*?' . preg_quote($this->marker_login, '/') . '/s';
            $htaccess = preg_replace($pattern, '', $htaccess);
            
            if (!empty(trim($whitelist_ips))) {
                $ip_list = explode("\n", $whitelist_ips);
                $ip_list = array_map('trim', $ip_list);
                $ip_list = array_filter($ip_list);
                $ip_list = array_unique($ip_list);
                
                $rules = [
                    '<Files "wp-login.php">',
                    'Order Deny,Allow',
                    'Deny from all'
                ];
                
                $valid_ips = [];
                $invalid_ips = [];
                $asn_ranges = [];
                
                foreach ($ip_list as $entry) {
                    $is_valid = false;
                    
                    // Проверяем ASN
                    if (preg_match('/^AS?(\d+)$/i', $entry, $matches)) {
                        $asn = $matches[1];
                        $this->log[] = "Обработка ASN для whitelist: AS{$asn}";
                        
                        $ranges = $this->get_asn_ip_ranges($asn);
                        if ($ranges && !empty($ranges)) {
                            foreach ($ranges as $range) {
                                $rules[] = "Allow from {$range}";
                                $asn_ranges[] = $range;
                            }
                            $this->log[] = "ASN AS{$asn}: добавлено в whitelist " . count($ranges) . " диапазонов";
                            $is_valid = true;
                        }
                    }
                    // CIDR диапазон
                    else if (strpos($entry, '/') !== false) {
                        list($ip, $mask) = explode('/', $entry, 2);
                        if (filter_var($ip, FILTER_VALIDATE_IP) && 
                            is_numeric($mask) && $mask >= 0 && $mask <= 32) {
                            $rules[] = "Allow from {$entry}";
                            $valid_ips[] = $entry;
                            $is_valid = true;
                            $this->log[] = "Добавлен CIDR диапазон: {$entry}";
                        }
                    }
                    // Обычный IP
                    else if (filter_var($entry, FILTER_VALIDATE_IP)) {
                        $rules[] = "Allow from {$entry}";
                        $valid_ips[] = $entry;
                        $is_valid = true;
                    }
                    // Диапазон с маской подсети
                    else if (preg_match('/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/', $entry, $matches)) {
                        $ip = $matches[1];
                        $netmask = $matches[2];
                        
                        if (filter_var($ip, FILTER_VALIDATE_IP) && filter_var($netmask, FILTER_VALIDATE_IP)) {
                            $rules[] = "Allow from {$ip} {$netmask}";
                            $valid_ips[] = $entry;
                            $is_valid = true;
                            $this->log[] = "Добавлен диапазон с маской: {$entry}";
                        }
                    }
                    // Частичные IP
                    else if (preg_match('/^(\d{1,3}\.){1,3}\d{1,3}$/', $entry) && 
                             !filter_var($entry, FILTER_VALIDATE_IP)) {
                        $parts = explode('.', $entry);
                        $valid_partial = true;
                        
                        foreach ($parts as $part) {
                            if (!is_numeric($part) || $part < 0 || $part > 255) {
                                $valid_partial = false;
                                break;
                            }
                        }
                        
                        if ($valid_partial && count($parts) >= 1 && count($parts) <= 3) {
                            $rules[] = "Allow from {$entry}";
                            $valid_ips[] = $entry;
                            $is_valid = true;
                            $this->log[] = "Добавлен частичный IP: {$entry}";
                        }
                    }
                    
                    if (!$is_valid) {
                        $invalid_ips[] = $entry;
                    }
                }
                
                if (!empty($invalid_ips)) {
                    $this->log[] = "Недопустимые записи (игнорированы): " . implode(', ', $invalid_ips);
                }
                
                $rules[] = '</Files>';
                
                $block = "\n" . $this->marker_login . "\n" . implode("\n", $rules) . "\n" . $this->marker_login . "\n";
                $htaccess = $block . $htaccess;
                
                $this->log[] = "Защита wp-login.php: IP/диапазоны: " . count($valid_ips) . ", ASN диапазоны: " . count($asn_ranges);
            } else {
                $this->log[] = "Защита wp-login.php отключена";
            }
            
            if (!file_put_contents($this->htaccess_path, $htaccess)) {
                throw new Exception('Не удалось записать в .htaccess');
            }
            
            $this->log[] = "Изменения успешно применены";
            return true;
            
        } catch (Exception $e) {
            $this->restore_backup();
            $this->log[] = "Ошибка: восстановлена резервная копия";
            return $e->getMessage();
        }
    }

    // Обновление защиты от опасных файлов
    private function update_file_protection($dangerous_files) {
        $this->log = [];
        
        try {
            $this->create_backup();
            $this->log[] = 'Создана резервная копия .htaccess';
            
            $htaccess = file_exists($this->htaccess_path) ? 
                file_get_contents($this->htaccess_path) : '';
            
            // Удаляем старые правила
            $pattern = '/\n?' . preg_quote($this->marker_files, '/') . '.*?' . preg_quote($this->marker_files, '/') . '/s';
            $htaccess = preg_replace($pattern, '', $htaccess);
            
            if (!empty(trim($dangerous_files))) {
                $file_list = explode("\n", $dangerous_files);
                $file_list = array_map('trim', $file_list);
                $file_list = array_filter($file_list);
                $file_list = array_unique($file_list);
                
                $escaped_files = array_map(function($file) {
                    return str_replace(['*', '.'], ['.*', '\.'], preg_quote($file, '/'));
                }, $file_list);
                
                $rules = ['<FilesMatch "(' . implode('|', $escaped_files) . ')$">'];
                $rules[] = 'Order Allow,Deny';
                $rules[] = 'Deny from all';
                $rules[] = '</FilesMatch>';
                
                $block = "\n" . $this->marker_files . "\n" . implode("\n", $rules) . "\n" . $this->marker_files . "\n";
                $htaccess = $block . $htaccess;
                
                $this->log[] = "Защита файлов активирована для " . count($file_list) . " правил";
            } else {
                $this->log[] = "Защита файлов отключена";
            }
            
            if (!file_put_contents($this->htaccess_path, $htaccess)) {
                throw new Exception('Не удалось записать в .htaccess');
            }
            
            $this->log[] = "Изменения успешно применены";
            return true;
            
        } catch (Exception $e) {
            $this->restore_backup();
            $this->log[] = "Ошибка: восстановлена резервная копия";
            return $e->getMessage();
        }
    }

    // Обновление защиты от ботов (с SetEnvIfNoCase)
    private function update_bot_protection($blocked_bots) {
        $this->log = [];
        
        try {
            $this->create_backup();
            $this->log[] = 'Создана резервная копия .htaccess';
            
            $htaccess = file_exists($this->htaccess_path) ? 
                file_get_contents($this->htaccess_path) : '';
            
            // Удаляем старые правила
            $pattern = '/\n?' . preg_quote($this->marker_bots, '/') . '.*?' . preg_quote($this->marker_bots, '/') . '/s';
            $htaccess = preg_replace($pattern, '', $htaccess);
            
            if (!empty(trim($blocked_bots))) {
                $bot_list = explode('|', $blocked_bots);
                $bot_list = array_map('trim', $bot_list);
                $bot_list = array_filter($bot_list);
                $bot_list = array_unique($bot_list);
                
                // Очищаем от потенциально опасных символов
                $cleaned_bots = [];
                $skipped_bots = [];
                
                foreach ($bot_list as $bot) {
                    if (strlen($bot) < 2) {
                        $skipped_bots[] = $bot;
                        continue;
                    }
                    
                    // Для SetEnvIfNoCase можем оставить больше символов
                    $cleaned_bot = preg_replace('/["\'\\\]/', '', $bot);
                    
                    if (!empty($cleaned_bot) && strlen($cleaned_bot) > 1) {
                        $cleaned_bots[] = $cleaned_bot;
                    } else {
                        $skipped_bots[] = $bot;
                    }
                }
                
                if (!empty($skipped_bots)) {
                    $this->log[] = "Пропущено проблемных User-Agent: " . count($skipped_bots);
                }
                
                if (!empty($cleaned_bots)) {
                    // Разбиваем на группы для избежания слишком длинных строк
                    $bot_groups = array_chunk($cleaned_bots, 100);
                    $rules = [];
                    
                    foreach ($bot_groups as $group_index => $group) {
                        $bot_string = implode('|', $group);
                        $rules[] = 'SetEnvIfNoCase User-Agent "' . $bot_string . '" block_bot' . ($group_index > 0 ? '_' . $group_index : '');
                    }
                    
                    // Добавляем правила блокировки
                    $rules[] = '';
                    $rules[] = '<Limit GET POST HEAD>';
                    $rules[] = '    Order Allow,Deny';
                    $rules[] = '    Allow from all';
                    
                    // Добавляем все переменные блокировки
                    for ($i = 0; $i < count($bot_groups); $i++) {
                        $rules[] = '    Deny from env=block_bot' . ($i > 0 ? '_' . $i : '');
                    }
                    
                    $rules[] = '</Limit>';
                    
                    $block = "\n" . $this->marker_bots . "\n" . implode("\n", $rules) . "\n" . $this->marker_bots . "\n";
                    $htaccess = $block . $htaccess;
                    
                    $this->log[] = "Защита от ботов активирована для " . count($cleaned_bots) . " User-Agent в " . count($bot_groups) . " группах";
                } else {
                    $this->log[] = "Все User-Agent содержали недопустимые символы и были отфильтрованы";
                }
            } else {
                $this->log[] = "Защита от ботов отключена";
            }
            
            if (!file_put_contents($this->htaccess_path, $htaccess)) {
                throw new Exception('Не удалось записать в .htaccess');
            }
            
            $this->log[] = "Изменения успешно применены";
            return true;
            
        } catch (Exception $e) {
            $this->restore_backup();
            $this->log[] = "Ошибка: восстановлена резервная копия - " . $e->getMessage();
            return $e->getMessage();
        }
    }

    // Получение текущих заблокированных IP
    private function get_current_ips() {
        if (!file_exists($this->htaccess_path)) return '';
        
        $htaccess = file_get_contents($this->htaccess_path);
        preg_match('/' . preg_quote($this->marker_ip, '/') . '(.*?)' . preg_quote($this->marker_ip, '/') . '/s', $htaccess, $matches);
        
        if (empty($matches[1])) return '';
        
        preg_match_all('/deny from ([^\r\n]+)/', $matches[1], $ips);
        return implode("\n", array_unique($ips[1]));
    }

    // Получение текущего белого списка для wp-login.php
    private function get_current_login_whitelist() {
        if (!file_exists($this->htaccess_path)) return '';
        
        $htaccess = file_get_contents($this->htaccess_path);
        preg_match('/' . preg_quote($this->marker_login, '/') . '(.*?)' . preg_quote($this->marker_login, '/') . '/s', $htaccess, $matches);
        
        if (empty($matches[1])) return '';
        
        preg_match_all('/Allow from ([^\r\n]+)/', $matches[1], $allows);
        
        if (!empty($allows[1])) {
            return implode("\n", array_unique($allows[1]));
        }
        
        return '';
    }

    // Создание резервной копии
    private function create_backup() {
        if (file_exists($this->htaccess_path)) {
            $backup_file = $this->backup_dir . 'htaccess-' . date('Ymd-His') . '.bak';
            if (copy($this->htaccess_path, $backup_file)) {
                $this->log[] = "Резервная копия создана: " . basename($backup_file);
                
                // Удаляем старые бекапы (оставляем только последние 10)
                $backups = glob($this->backup_dir . 'htaccess-*.bak');
                if (count($backups) > 10) {
                    rsort($backups);
                    $old_backups = array_slice($backups, 10);
                    foreach ($old_backups as $old_backup) {
                        unlink($old_backup);
                    }
                }
            } else {
                $this->log[] = "Ошибка создания резервной копии";
            }
        }
    }

    // Восстановление из резервной копии
    private function restore_backup() {
        $backups = glob($this->backup_dir . 'htaccess-*.bak');
        if (!empty($backups)) {
            rsort($backups);
            if (copy($backups[0], $this->htaccess_path)) {
                $this->log[] = "Восстановлена резервная копия: " . basename($backups[0]);
            } else {
                $this->log[] = "Ошибка восстановления из резервной копии";
            }
        }
    }

    // Деактивация плагина - очистка всех правил
    public function deactivate() {
        $this->update_ip_rules('');
        $this->update_login_protection('');
        $this->update_file_protection('');
        $this->update_bot_protection('');
    }
}

new Advanced_Security_Blocker();
