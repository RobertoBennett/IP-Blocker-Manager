<?php
/*
Plugin Name: IP Blocker Manager
Description: Управление блокировкой IP-адресов через .htaccess
Plugin URI: https://github.com/RobertoBennett/IP-Blocker-Manager
Version: 1.2
Author: Robert Bennett
Updated by: Assistant
Text Domain: IP Blocker Manager
*/

defined('ABSPATH') || exit;

class Safe_IP_Blocker {
    private $htaccess_path;
    private $marker = "# IP_BLOCKER_SAFE_MARKER";
    private $backup_dir;
    private $log = [];

    public function __construct() {
        $this->htaccess_path = ABSPATH . '.htaccess';
        $this->backup_dir = WP_CONTENT_DIR . '/ip-blocker-backups/';
        
        add_action('admin_menu', [$this, 'admin_menu']);
        register_deactivation_hook(__FILE__, [$this, 'deactivate']);
        add_action('admin_init', [$this, 'create_backup_dir']);
        add_action('admin_enqueue_scripts', [$this, 'enqueue_scripts']);
    }

    public function enqueue_scripts($hook) {
        if ($hook !== 'settings_page_safe-ip-blocker') return;
        
        // Исправленные стили для нумерации строк
        echo '<style>
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
        </style>';
        
        // Исправленный скрипт для обновления нумерации
        echo '<script>
        jQuery(document).ready(function($) {
            const textarea = $("#ip_addresses");
            const lineNumbersDiv = $(".ip-blocker-line-numbers");
            
            function updateLineNumbers() {
                const text = textarea.val();
                const lines = text ? text.split("\n").length : 1;
                let lineNumbers = "";
                
                for (let i = 1; i <= lines; i++) {
                    lineNumbers += i + (i < lines ? "\n" : "");
                }
                
                lineNumbersDiv.text(lineNumbers);
            }
            
            // Обновляем нумерацию при изменении текста
            textarea.on("input keyup paste", updateLineNumbers);
            
            // Синхронизируем прокрутку
            textarea.on("scroll", function() {
                lineNumbersDiv.scrollTop(textarea.scrollTop());
            });
            
            // Инициализация
            updateLineNumbers();
        });
        </script>';
    }

    public function create_backup_dir() {
        if (!is_dir($this->backup_dir)) {
            wp_mkdir_p($this->backup_dir);
        }
    }

    public function admin_menu() {
        add_options_page(
            'Блокировка IP',
            'IP Блокер',
            'manage_options',
            'safe-ip-blocker',
            [$this, 'settings_page']
        );
    }

    public function settings_page() {
        if (!current_user_can('manage_options')) {
            return;
        }

        $error = $success = '';
        $current_ips = $this->get_current_ips();
        $operation_log = '';

        if (isset($_POST['submit_ip_blocker'])) {
            check_admin_referer('safe_ip_blocker_update');
            
            $ips = isset($_POST['ip_addresses']) 
                ? sanitize_textarea_field($_POST['ip_addresses']) 
                : '';
            
            $result = $this->update_rules($ips);
            
            if ($result === true) {
                $success = 'Правила успешно обновлены!';
                $current_ips = $this->get_current_ips();
                
                // Формируем лог операций
                if (!empty($this->log)) {
                    $operation_log = '<div class="operation-log"><strong>Журнал операций:</strong><ul>';
                    foreach ($this->log as $entry) {
                        $operation_log .= '<li class="log-entry">' . esc_html($entry) . '</li>';
                    }
                    $operation_log .= '</ul></div>';
                }
            } else {
                $error = 'Ошибка: ' . $result;
            }
        }
        ?>
        <div class="wrap">
            <h1>Безопасный IP Блокер</h1>
            
            <?php if ($error) : ?>
                <div class="notice notice-error"><p><?php echo esc_html($error); ?></p></div>
            <?php endif; ?>
            
            <?php if ($success) : ?>
                <div class="notice notice-success"><p><?php echo esc_html($success); ?></p></div>
                <?php echo $operation_log; ?>
            <?php endif; ?>
            
            <form method="post">
                <?php wp_nonce_field('safe_ip_blocker_update'); ?>
                <table class="form-table">
                    <tr>
                        <th><label for="ip_addresses">IP-адреса:</label></th>
                        <td>
                            <div class="ip-blocker-textarea-wrapper">
                                <div class="ip-blocker-line-numbers"></div>
                                <textarea name="ip_addresses" id="ip_addresses" rows="20" cols="50" 
                                    class="large-text code" placeholder="192.168.0.1"><?php 
                                    echo esc_textarea($current_ips); 
                                ?></textarea>
                            </div>
                            <p class="description ip-blocker-description">По одному IP на строку (дубликаты будут автоматически удалены)</p>
                        </td>
                    </tr>
                </table>
                <p>
                    <button type="submit" name="submit_ip_blocker" class="button button-primary">
                        Сохранить изменения
                    </button>
                    <a href="<?php echo esc_url(admin_url('options-general.php?page=safe-ip-blocker&backup=1')); ?>" 
                       class="button">
                        Создать резервную копию
                    </a>
                </p>
            </form>
            
            <div class="card">
                <h2 class="title">Статус системы</h2>
                <ul>
                    <li>Файл .htaccess: <?php echo is_writable($this->htaccess_path) ? 
                        '<span style="color:green">Доступен для записи</span>' : 
                        '<span style="color:red">Недоступен для записи</span>'; ?></li>
                    <li>Резервные копии: <?php echo is_writable($this->backup_dir) ? 
                        '<span style="color:green">Доступны</span>' : 
                        '<span style="color:red">Недоступны</span>'; ?></li>
                    <li>Последняя резервная копия: <?php 
                        $backups = glob($this->backup_dir . 'htaccess-*.bak');
                        if (!empty($backups)) {
                            rsort($backups);
                            echo date('d.m.Y H:i:s', filemtime($backups[0]));
                        } else {
                            echo 'не создана';
                        }
                    ?></li>
                </ul>
            </div>
        </div>
        <?php
    }

    private function update_rules($ips) {
        $this->log = [];
        
        try {
            // Создаем резервную копию
            $this->create_backup();
            $this->log[] = 'Создана резервная копия .htaccess';
            
            // Обрабатываем введенные IP
            $ip_list = explode("\n", $ips);
            $ip_list = array_map('trim', $ip_list);
            $ip_list = array_filter($ip_list);
            
            // Собираем статистику
            $original_count = count($ip_list);
            $ip_list = array_unique($ip_list);
            $duplicates_count = $original_count - count($ip_list);
            
            if ($duplicates_count > 0) {
                $this->log[] = "Удалено дубликатов: $duplicates_count";
            }
            
            // Подготовка правил
            $rules = [];
            $valid_ips = [];
            $invalid_ips = [];
            
            foreach ($ip_list as $ip) {
                if (filter_var($ip, FILTER_VALIDATE_IP)) {
                    $rules[] = "deny from {$ip}";
                    $valid_ips[] = $ip;
                } else {
                    $invalid_ips[] = $ip;
                }
            }
            
            // Логируем невалидные IP
            if (!empty($invalid_ips)) {
                $this->log[] = "Недопустимые IP (игнорированы): " . implode(', ', $invalid_ips);
            }
            
            // Получаем текущий .htaccess
            $htaccess = file_exists($this->htaccess_path) ? 
                file_get_contents($this->htaccess_path) : '';
            
            // Удаляем старые правила
            $pattern = '/\n?' . preg_quote($this->marker) . '.*?' . preg_quote($this->marker) . '/s';
            $htaccess = preg_replace($pattern, '', $htaccess);
            
            // Добавляем новые правила
            if (!empty($rules)) {
                $block = "\n" . $this->marker . "\n" . implode("\n", $rules) . "\n" . $this->marker . "\n";
                $htaccess = $block . $htaccess;
                $this->log[] = "Добавлено IP: " . count($valid_ips);
            } else {
                $this->log[] = "Все правила блокировки удалены";
            }
            
            // Сохраняем изменения
            if (!file_put_contents($this->htaccess_path, $htaccess)) {
                throw new Exception('Не удалось записать в .htaccess');
            }
            
            $this->log[] = "Изменения успешно применены";
            return true;
            
        } catch (Exception $e) {
            // Восстанавливаем из резервной копии при ошибке
            $this->restore_backup();
            $this->log[] = "Ошибка: восстановлена резервная копия";
            return $e->getMessage();
        }
    }

    private function create_backup() {
        if (file_exists($this->htaccess_path)) {
            $backup_file = $this->backup_dir . 'htaccess-' . date('Ymd-His') . '.bak';
            if (copy($this->htaccess_path, $backup_file)) {
                $this->log[] = "Резервная копия создана: " . basename($backup_file);
            } else {
                $this->log[] = "Ошибка создания резервной копии";
            }
        }
    }

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

    private function get_current_ips() {
        if (!file_exists($this->htaccess_path)) return '';
        
        $htaccess = file_get_contents($this->htaccess_path);
        preg_match('/' . preg_quote($this->marker) . '(.*?)' . preg_quote($this->marker) . '/s', $htaccess, $matches);
        
        if (empty($matches)) return '';
        
        preg_match_all('/deny from ([\d\.:a-fA-F]+)/', $matches[1], $ips);
        return implode("\n", array_unique($ips[1]));
    }

    public function deactivate() {
        $this->update_rules('');
    }
}


new Safe_IP_Blocker();
