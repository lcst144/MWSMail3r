<?php

class SMTP
{
    const VERSION = '5.2.9';
    const CRLF = "\r\n";
    const DEFAULT_SMTP_PORT = 25;
    const MAX_LINE_LENGTH = 998;
    const DEBUG_OFF = 0;
    const DEBUG_CLIENT = 1;
    const DEBUG_SERVER = 2;
    const DEBUG_CONNECTION = 3;
    const DEBUG_LOWLEVEL = 4;
    public $Version = '5.2.9';
    public $SMTP_PORT = 25;
    public $CRLF = "\r\n";
    public $do_debug = self::DEBUG_OFF;
    public $Debugoutput = 'echo';
    public $do_verp = false;
    public $Timeout = 300;
    public $Timelimit = 300;
    protected $smtp_conn;
    protected $error = array();
    protected $helo_rply = null;
    protected $server_caps = null;
    protected $last_reply = '';

    public function connect($host, $port = null, $timeout = 30, $options = array())
    {
        static $streamok;
        if (is_null($streamok)) {
            $streamok = function_exists('stream_socket_client');
        }
        $this->error = array();
        if ($this->connected()) {
            $this->error = array('error' => 'Already connected to a server');
            return false;
        }
        if (empty($port)) {
            $port = self::DEFAULT_SMTP_PORT;
        }
        $this->edebug("Connection: opening to $host:$port, t=$timeout, opt=" . var_export($options, true), self::DEBUG_CONNECTION);
        $errno = 0;
        $errstr = '';
        if ($streamok) {
            $socket_context = stream_context_create($options);
            $this->smtp_conn = @stream_socket_client($host . ":" . $port, $errno, $errstr, $timeout, STREAM_CLIENT_CONNECT, $socket_context);
        } else {
            $this->edebug("Connection: stream_socket_client not available, falling back to fsockopen", self::DEBUG_CONNECTION);
            $this->smtp_conn = fsockopen($host, $port, $errno, $errstr, $timeout);
        }
        if (!is_resource($this->smtp_conn)) {
            $this->error = array('error' => 'Failed to connect to server', 'errno' => $errno, 'errstr' => $errstr);
            $this->edebug('SMTP ERROR: ' . $this->error['error'] . ": $errstr ($errno)", self::DEBUG_CLIENT);
            return false;
        }
        $this->edebug('Connection: opened', self::DEBUG_CONNECTION);
        if (substr(PHP_OS, 0, 3) != 'WIN') {
            $max = ini_get('max_execution_time');
            if ($max != 0 && $timeout > $max) {
                @set_time_limit($timeout);
            }
            stream_set_timeout($this->smtp_conn, $timeout, 0);
        }
        $announce = $this->get_lines();
        $this->edebug('SERVER -> CLIENT: ' . $announce, self::DEBUG_SERVER);
        return true;
    }

    public function connected()
    {
        if (is_resource($this->smtp_conn)) {
            $sock_status = stream_get_meta_data($this->smtp_conn);
            if ($sock_status['eof']) {
                $this->edebug('SMTP NOTICE: EOF caught while checking if connected', self::DEBUG_CLIENT);
                $this->close();
                return false;
            }
            return true;
        }
        return false;
    }

    protected function edebug($str, $level = 0)
    {
        if ($level > $this->do_debug) {
            return;
        }
        if (!in_array($this->Debugoutput, array('error_log', 'html', 'echo')) and is_callable($this->Debugoutput)) {
            call_user_func($this->Debugoutput, $str, $this->do_debug);
            return;
        }
        switch ($this->Debugoutput) {
            case  'error_log':
                error_log($str);
                break;
            case  'html':
                echo htmlentities(preg_replace('/[\r\n]+/', '', $str), ENT_QUOTES, 'UTF-8') . "<br>\n";
                break;
            case  'echo':
            default:
                $str = preg_replace('/(\r\n|\r|\n)/ms', "\n", $str);
                echo gmdate('Y-m-d H:i:s') . "\t" . str_replace("\n", "\n                   \t                  ", trim($str)) . "\n";
        }
    }

    public function close()
    {
        $this->error = array();
        $this->server_caps = null;
        $this->helo_rply = null;
        if (is_resource($this->smtp_conn)) {
            fclose($this->smtp_conn);
            $this->smtp_conn = null;
            $this->edebug('Connection: closed', self::DEBUG_CONNECTION);
        }
    }

    protected function get_lines()
    {
        if (!is_resource($this->smtp_conn)) {
            return '';
        }
        $data = '';
        $endtime = 0;
        stream_set_timeout($this->smtp_conn, $this->Timeout);
        if ($this->Timelimit > 0) {
            $endtime = time() + $this->Timelimit;
        }
        while (is_resource($this->smtp_conn) && !feof($this->smtp_conn)) {
            $str = @fgets($this->smtp_conn, 515);
            $this->edebug("SMTP -> get_lines(): \$data was \"$data\"", self::DEBUG_LOWLEVEL);
            $this->edebug("SMTP -> get_lines(): \$str is \"$str\"", self::DEBUG_LOWLEVEL);
            $data .= $str;
            $this->edebug("SMTP -> get_lines(): \$data is \"$data\"", self::DEBUG_LOWLEVEL);
            if ((isset($str[3]) and $str[3] == ' ')) {
                break;
            }
            $info = stream_get_meta_data($this->smtp_conn);
            if ($info['timed_out']) {
                $this->edebug('SMTP -> get_lines(): timed-out (' . $this->Timeout . ' sec)', self::DEBUG_LOWLEVEL);
                break;
            }
            if ($endtime and time() > $endtime) {
                $this->edebug('SMTP -> get_lines(): timelimit reached (' . $this->Timelimit . ' sec)', self::DEBUG_LOWLEVEL);
                break;
            }
        }
        return $data;
    }

    public function startTLS()
    {
        if (!$this->sendCommand('STARTTLS', 'STARTTLS', 220)) {
            return false;
        }
        if (!stream_socket_enable_crypto($this->smtp_conn, true, STREAM_CRYPTO_METHOD_TLS_CLIENT)) {
            return false;
        }
        return true;
    }

    protected function sendCommand($command, $commandstring, $expect)
    {
        if (!$this->connected()) {
            $this->error = array('error' => "Called $command without being connected");
            return false;
        }
        $this->client_send($commandstring . self::CRLF);
        $this->last_reply = $this->get_lines();
        $matches = array();
        if (preg_match("/^([0-9]{3})[ -](?:([0-9]\\.[0-9]\\.[0-9]) )?/", $this->last_reply, $matches)) {
            $code = $matches[1];
            $code_ex = (count($matches) > 2 ? $matches[2] : null);
            $detail = preg_replace("/{$code}[ -]" . ($code_ex ? str_replace('.', '\\.', $code_ex) . ' ' : '') . "/m", '', $this->last_reply);
        } else {
            $code = substr($this->last_reply, 0, 3);
            $code_ex = null;
            $detail = substr($this->last_reply, 4);
        }
        $this->edebug('SERVER -> CLIENT: ' . $this->last_reply, self::DEBUG_SERVER);
        if (!in_array($code, (array)$expect)) {
            $this->error = array('error' => "$command command failed", 'smtp_code' => $code, 'smtp_code_ex' => $code_ex, 'detail' => $detail);
            $this->edebug('SMTP ERROR: ' . $this->error['error'] . ': ' . $this->last_reply, self::DEBUG_CLIENT);
            return false;
        }
        $this->error = array();
        return true;
    }

    public function client_send($data)
    {
        $this->edebug("CLIENT -> SERVER: $data", self::DEBUG_CLIENT);
        return fwrite($this->smtp_conn, $data);
    }

    public function authenticate($username, $password, $authtype = null, $realm = '', $workstation = '')
    {
        if (!$this->server_caps) {
            $this->error = array('error' => 'Authentication is not allowed before HELO/EHLO');
            return false;
        }
        if (array_key_exists('EHLO', $this->server_caps)) {
            if (!array_key_exists('AUTH', $this->server_caps)) {
                $this->error = array('error' => 'Authentication is not allowed at this stage');
                return false;
            }
            self::edebug('Auth method requested: ' . ($authtype ? $authtype : 'UNKNOWN'), self::DEBUG_LOWLEVEL);
            self::edebug('Auth methods available on the server: ' . implode(',', $this->server_caps['AUTH']), self::DEBUG_LOWLEVEL);
            if (empty($authtype)) {
                foreach (array('LOGIN', 'CRAM-MD5', 'NTLM', 'PLAIN') as $method) {
                    if (in_array($method, $this->server_caps['AUTH'])) {
                        $authtype = $method;
                        break;
                    }
                }
                if (empty($authtype)) {
                    $this->error = array('error' => 'No supported authentication methods found');
                    return false;
                }
                self::edebug('Auth method selected: ' . $authtype, self::DEBUG_LOWLEVEL);
            }
            if (!in_array($authtype, $this->server_caps['AUTH'])) {
                $this->error = array('error' => 'The requested authentication method "' . $authtype . '" is not supported by the server');
                return false;
            }
        } elseif (empty($authtype)) {
            $authtype = 'LOGIN';
        }
        switch ($authtype) {
            case  'PLAIN':
                if (!$this->sendCommand('AUTH', 'AUTH PLAIN', 334)) {
                    return false;
                }
                if (!$this->sendCommand('User & Password', base64_encode("\0" . $username . "\0" . $password), 235)) {
                    return false;
                }
                break;
            case  'LOGIN':
                if (!$this->sendCommand('AUTH', 'AUTH LOGIN', 334)) {
                    return false;
                }
                if (!$this->sendCommand("Username", base64_encode($username), 334)) {
                    return false;
                }
                if (!$this->sendCommand("Password", base64_encode($password), 235)) {
                    return false;
                }
                break;
            case  'NTLM':
                require_once 'extras/ntlm_sasl_client.php';
                $temp = new stdClass();
                $ntlm_client = new ntlm_sasl_client_class;
                if (!$ntlm_client->Initialize($temp)) {
                    $this->error = array('error' => $temp->error);
                    $this->edebug('You need to enable some modules in your php.ini file: ' . $this->error['error'], self::DEBUG_CLIENT);
                    return false;
                }
                $msg1 = $ntlm_client->TypeMsg1($realm, $workstation);
                if (!$this->sendCommand('AUTH NTLM', 'AUTH NTLM ' . base64_encode($msg1), 334)) {
                    return false;
                }
                $challenge = substr($this->last_reply, 3);
                $challenge = base64_decode($challenge);
                $ntlm_res = $ntlm_client->NTLMResponse(substr($challenge, 24, 8), $password);
                $msg3 = $ntlm_client->TypeMsg3($ntlm_res, $username, $realm, $workstation);
                return $this->sendCommand('Username', base64_encode($msg3), 235);
            case  'CRAM-MD5':
                if (!$this->sendCommand('AUTH CRAM-MD5', 'AUTH CRAM-MD5', 334)) {
                    return false;
                }
                $challenge = base64_decode(substr($this->last_reply, 4));
                $response = $username . ' ' . $this->hmac($challenge, $password);
                return $this->sendCommand('Username', base64_encode($response), 235);
            default:
                $this->error = array('error' => 'Authentication method "' . $authtype . '" is not supported');
                return false;
        }
        return true;
    }

    protected function hmac($data, $key)
    {
        if (function_exists('hash_hmac')) {
            return hash_hmac('md5', $data, $key);
        }
        $bytelen = 64;
        if (strlen($key) > $bytelen) {
            $key = pack('H*', md5($key));
        }
        $key = str_pad($key, $bytelen, chr(0x00));
        $ipad = str_pad('', $bytelen, chr(0x36));
        $opad = str_pad('', $bytelen, chr(0x5c));
        $k_ipad = $key ^ $ipad;
        $k_opad = $key ^ $opad;
        return md5($k_opad . pack('H*', md5($k_ipad . $data)));
    }

    public function data($msg_data)
    {
        if (!$this->sendCommand('DATA', 'DATA', 354)) {
            return false;
        }
        $lines = explode("\n", str_replace(array("\r\n", "\r"), "\n", $msg_data));
        $field = substr($lines[0], 0, strpos($lines[0], ':'));
        $in_headers = false;
        if (!empty($field) && strpos($field, ' ') === false) {
            $in_headers = true;
        }
        foreach ($lines as $line) {
            $lines_out = array();
            if ($in_headers and $line == '') {
                $in_headers = false;
            }
            while (isset($line[self::MAX_LINE_LENGTH])) {
                $pos = strrpos(substr($line, 0, self::MAX_LINE_LENGTH), ' ');
                if (!$pos) {
                    $pos = self::MAX_LINE_LENGTH - 1;
                    $lines_out[] = substr($line, 0, $pos);
                    $line = substr($line, $pos);
                } else {
                    $lines_out[] = substr($line, 0, $pos);
                    $line = substr($line, $pos + 1);
                }
                if ($in_headers) {
                    $line = "\t" . $line;
                }
            }
            $lines_out[] = $line;
            foreach ($lines_out as $line_out) {
                if (!empty($line_out) and $line_out[0] == '.') {
                    $line_out = '.' . $line_out;
                }
                $this->client_send($line_out . self::CRLF);
            }
        }
        $savetimelimit = $this->Timelimit;
        $this->Timelimit = $this->Timelimit * 2;
        $result = $this->sendCommand('DATA END', '.', 250);
        $this->Timelimit = $savetimelimit;
        return $result;
    }

    public function hello($host = '')
    {
        return (boolean)($this->sendHello('EHLO', $host) or $this->sendHello('HELO', $host));
    }

    protected function sendHello($hello, $host)
    {
        $noerror = $this->sendCommand($hello, $hello . ' ' . $host, 250);
        $this->helo_rply = $this->last_reply;
        if ($noerror) {
            $this->parseHelloFields($hello);
        } else {
            $this->server_caps = null;
        }
        return $noerror;
    }

    protected function parseHelloFields($type)
    {
        $this->server_caps = array();
        $lines = explode("\n", $this->last_reply);
        foreach ($lines as $n => $s) {
            $s = trim(substr($s, 4));
            if (!$s) {
                continue;
            }
            $fields = explode(' ', $s);
            if ($fields) {
                if (!$n) {
                    $name = $type;
                    $fields = $fields[0];
                } else {
                    $name = array_shift($fields);
                    if ($name == 'SIZE') {
                        $fields = ($fields) ? $fields[0] : 0;
                    }
                }
                $this->server_caps[$name] = ($fields ? $fields : true);
            }
        }
    }

    public function mail($from)
    {
        $useVerp = ($this->do_verp ? ' XVERP' : '');
        return $this->sendCommand('MAIL FROM', 'MAIL FROM:<' . $from . '>' . $useVerp, 250);
    }

    public function quit($close_on_error = true)
    {
        $noerror = $this->sendCommand('QUIT', 'QUIT', 221);
        $err = $this->error;
        if ($noerror or $close_on_error) {
            $this->close();
            $this->error = $err;
        }
        return $noerror;
    }

    public function recipient($toaddr)
    {
        return $this->sendCommand('RCPT TO', 'RCPT TO:<' . $toaddr . '>', array(250, 251));
    }

    public function reset()
    {
        return $this->sendCommand('RSET', 'RSET', 250);
    }

    public function sendAndMail($from)
    {
        return $this->sendCommand('SAML', "SAML FROM:$from", 250);
    }

    public function verify($name)
    {
        return $this->sendCommand('VRFY', "VRFY $name", array(250, 251));
    }

    public function noop()
    {
        return $this->sendCommand('NOOP', 'NOOP', 250);
    }

    public function turn()
    {
        $this->error = array('error' => 'The SMTP TURN command is not implemented');
        $this->edebug('SMTP NOTICE: ' . $this->error['error'], self::DEBUG_CLIENT);
        return false;
    }

    public function getError()
    {
        return $this->error;
    }

    public function getServerExtList()
    {
        return $this->server_caps;
    }

    public function getServerExt($name)
    {
        if (!$this->server_caps) {
            $this->error = array('No HELO/EHLO was sent');
            return null;
        }
        if (!array_key_exists($name, $this->server_caps)) {
            if ($name == 'HELO') {
                return $this->server_caps['EHLO'];
            }
            if ($name == 'EHLO' || array_key_exists('EHLO', $this->server_caps)) {
                return false;
            }
            $this->error = array('HELO handshake was used. Client knows nothing about server extensions');
            return null;
        }
        return $this->server_caps[$name];
    }

    public function getLastReply()
    {
        return $this->last_reply;
    }

    public function setVerp($enabled = false)
    {
        $this->do_verp = $enabled;
    }

    public function getVerp()
    {
        return $this->do_verp;
    }

    public function getDebugOutput()
    {
        return $this->Debugoutput;
    }

    public function setDebugOutput($method = 'echo')
    {
        $this->Debugoutput = $method;
    }

    public function setDebugLevel($level = 0)
    {
        $this->do_debug = $level;
    }

    public function getDebugLevel()
    {
        return $this->do_debug;
    }

    public function getTimeout()
    {
        return $this->Timeout;
    }

    public function setTimeout($timeout = 0)
    {
        $this->Timeout = $timeout;
    }
}

class Mailer
{
    const STOP_MESSAGE = 0;
    const STOP_CONTINUE = 1;
    const STOP_CRITICAL = 2;
    const CRLF = "\r\n";
    public $Version = '3.1.1';
    public $Priority = 3;
    public $CharSet = 'iso-8859-1';
    public $ContentType = 'text/plain';
    public $Encoding = '8bit';
    public $ErrorInfo = '';
    public $From = 'root@localhost';
    public $FromName = 'Root User';
    public $Sender = '';
    public $ReturnPath = '';
    public $Subject = '';
    public $Body = '';
    public $AltBody = '';
    public $Ical = '';
    public $WordWrap = 0;
    public $Mailer = 'mail';
    public $Sendmail = '/usr/sbin/sendmail';
    public $UseSendmailOptions = true;
    public $PluginDir = '';
    public $ConfirmReadingTo = '';
    public $Hostname = '';
    public $MessageID = '';
    public $MessageDate = '';
    public $Host = 'localhost';
    public $Port = 25;
    public $Helo = '';
    public $SMTPSecure = '';
    public $SMTPAuth = false;
    public $Username = '';
    public $Password = '';
    public $AuthType = '';
    public $Realm = '';
    public $Workstation = '';
    public $Timeout = 10;
    public $SMTPDebug = 0;
    public $Debugoutput = 'echo';
    public $SMTPKeepAlive = false;
    public $SingleTo = false;
    public $SingleToArray = array();
    public $do_verp = false;
    public $AllowEmpty = false;
    public $LE = "\n";
    public $DKIM_selector = '';
    public $DKIM_identity = '';
    public $DKIM_passphrase = '';
    public $DKIM_domain = '';
    public $DKIM_private = '';
    public $action_function = '';
    public $XMailer = '';
    protected $MIMEBody = '';
    protected $MIMEHeader = '';
    protected $mailHeader = '';
    protected $smtp = null;
    protected $to = array();
    protected $cc = array();
    protected $bcc = array();
    protected $ReplyTo = array();
    protected $all_recipients = array();
    protected $attachment = array();
    protected $CustomHeader = array();
    protected $lastMessageID = '';
    protected $message_type = '';
    protected $boundary = array();
    protected $language = array();
    protected $error_count = 0;
    protected $sign_cert_file = '';
    protected $sign_key_file = '';
    protected $sign_key_pass = '';
    protected $exceptions = false;

    public function __construct($exceptions = false)
    {
        $this->exceptions = ($exceptions == true);
        if (version_compare(PHP_VERSION, '5.1.2', '>=')) {
            $autoload = spl_autoload_functions();
            if ($autoload === false or !in_array('PHPMailerAutoload', $autoload)) {
            }
        }
    }

    public function __destruct()
    {
        if ($this->Mailer == 'smtp') {
            $this->smtpClose();
        }
    }

    public function smtpClose()
    {
        if ($this->smtp !== null) {
            if ($this->smtp->connected()) {
                $this->smtp->quit();
                $this->smtp->close();
            }
        }
    }

    public function isSMTP()
    {
        $this->Mailer = 'smtp';
    }

    public function isMail()
    {
        $this->Mailer = 'mail';
    }

    public function isSendmail()
    {
        $ini_sendmail_path = ini_get('sendmail_path');
        if (!stristr($ini_sendmail_path, 'sendmail')) {
            $this->Sendmail = '/usr/sbin/sendmail';
        } else {
            $this->Sendmail = $ini_sendmail_path;
        }
        $this->Mailer = 'sendmail';
    }

    public function isQmail()
    {
        $ini_sendmail_path = ini_get('sendmail_path');
        if (!stristr($ini_sendmail_path, 'qmail')) {
            $this->Sendmail = '/var/qmail/bin/qmail-inject';
        } else {
            $this->Sendmail = $ini_sendmail_path;
        }
        $this->Mailer = 'qmail';
    }

    public function addAddress($address, $name = '')
    {
        return $this->addAnAddress('to', $address, $name);
    }

    protected function addAnAddress($kind, $address, $name = '')
    {
        if (!preg_match('/^(to|cc|bcc|Reply-To)$/', $kind)) {
            $this->setError($this->lang('Invalid recipient array') . ': ' . $kind);
            $this->edebug($this->lang('Invalid recipient array') . ': ' . $kind);
            if ($this->exceptions) {
                throw new invalidAdressException('Invalid recipient array: ' . $kind);
            }
            return false;
        }
        $address = trim($address);
        $name = trim(preg_replace('/[\r\n]+/', '', $name));
        if (!$this->validateAddress($address)) {
            $this->setError($this->lang('invalid_address') . ': ' . $address);
            $this->edebug($this->lang('invalid_address') . ': ' . $address);
            if ($this->exceptions) {
                throw new invalidAdressException($this->lang('invalid_address') . ': ' . $address);
            }
            return false;
        }
        if ($kind != 'Reply-To') {
            if (!isset($this->all_recipients[strtolower($address)])) {
                array_push($this->$kind, array($address, $name));
                $this->all_recipients[strtolower($address)] = true;
                return true;
            }
        } else {
            if (!array_key_exists(strtolower($address), $this->ReplyTo)) {
                $this->ReplyTo[strtolower($address)] = array($address, $name);
                return true;
            }
        }
        return false;
    }

    protected function setError($msg)
    {
        $this->error_count++;
        if ($this->Mailer == 'smtp' and !is_null($this->smtp)) {
            $lasterror = $this->smtp->getError();
            if (!empty($lasterror) and array_key_exists('smtp_msg', $lasterror)) {
                $msg .= '<p>' . $this->lang('smtp_error') . $lasterror['smtp_msg'] . "</p>\n";
            }
        }
        $this->ErrorInfo = $msg;
    }

    protected function lang($key)
    {
        if (count($this->language) < 1) {
            $this->setLanguage('en');
        }
        if (isset($this->language[$key])) {
            return $this->language[$key];
        } else {
            return 'Language string failed to load: ' . $key;
        }
    }

    public function setLanguage($langcode = 'en', $lang_path = '')
    {
        $PHPMAILER_LANG = array('authenticate' => 'SMTP Error: Could not authenticate.', 'connect_host' => 'SMTP Error: Could not connect to SMTP host.', 'data_not_accepted' => 'SMTP Error: data not accepted.', 'empty_message' => 'Message body empty', 'encoding' => 'Unknown encoding: ', 'execute' => 'Could not execute: ', 'file_access' => 'Could not access file: ', 'file_open' => 'File Error: Could not open file: ', 'from_failed' => 'The following From address failed: ', 'instantiate' => 'Could not instantiate mail function.', 'invalid_address' => 'Invalid address', 'mailer_not_supported' => ' mailer is not supported.', 'provide_address' => 'You must provide at least one recipient email address.', 'recipients_failed' => 'SMTP Error: The following recipients failed: ', 'signing' => 'Signing Error: ', 'smtp_connect_failed' => 'SMTP connect() failed.', 'smtp_error' => 'SMTP server error: ', 'variable_set' => 'Cannot set or reset variable: ');
        if (empty($lang_path)) {
            $lang_path = dirname(__FILE__) . DIRECTORY_SEPARATOR . 'language' . DIRECTORY_SEPARATOR;
        }
        $foundlang = true;
        $lang_file = $lang_path . 'phpmailer.lang-' . $langcode . '.php';
        if ($langcode != 'en') {
            if (!is_readable($lang_file)) {
                $foundlang = false;
            } else {
                $foundlang = include $lang_file;
            }
        }
        $this->language = $PHPMAILER_LANG;
        return ($foundlang == true);
    }

    protected function edebug($str)
    {
        if (!$this->SMTPDebug) {
            return;
        }
        switch ($this->Debugoutput) {
            case  'error_log':
                error_log($str);
                break;
            case  'html':
                echo htmlentities(preg_replace('/[\r\n]+/', '', $str), ENT_QUOTES, $this->CharSet) . "<br>\n";
                break;
            case  'echo':
            default:
                echo $str . "\n";
        }
    }

    public static function validateAddress($address, $patternselect = 'auto')
    {
        if (!$patternselect or $patternselect == 'auto') {
            if (defined('PCRE_VERSION')) {
                if (version_compare(PCRE_VERSION, '8.0') >= 0) {
                    $patternselect = 'pcre8';
                } else {
                    $patternselect = 'pcre';
                }
            } else {
                if (version_compare(PHP_VERSION, '5.2.0') >= 0) {
                    $patternselect = 'php';
                } else {
                    $patternselect = 'noregex';
                }
            }
        }
        switch ($patternselect) {
            case  'pcre8':
                return (boolean)preg_match('/^(?!(?>(?1)"?(?>\\\[ -~]|[^"])"?(?1)){255,})(?!(?>(?1)"?(?>\\\[ -~]|[^"])"?(?1)){65,}@)' . '((?>(?>(?>((?>(?>(?>\x0D\x0A)?[\t ])+|(?>[\t ]*\x0D\x0A)?[\t ]+)?)(\((?>(?2)' . '(?>[\x01-\x08\x0B\x0C\x0E-\'*-\[\]-\x7F]|\\\[\x00-\x7F]|(?3)))*(?2)\)))+(?2))|(?2))?)' . '([!#-\'*+\/-9=?^-~-]+|"(?>(?2)(?>[\x01-\x08\x0B\x0C\x0E-!#-\[\]-\x7F]|\\\[\x00-\x7F]))*' . '(?2)")(?>(?1)\.(?1)(?4))*(?1)@(?!(?1)[a-z0-9-]{64,})(?1)(?>([a-z0-9](?>[a-z0-9-]*[a-z0-9])?)' . '(?>(?1)\.(?!(?1)[a-z0-9-]{64,})(?1)(?5)){0,126}|\[(?:(?>IPv6:(?>([a-f0-9]{1,4})(?>:(?6)){7}' . '|(?!(?:.*[a-f0-9][:\]]){8,})((?6)(?>:(?6)){0,6})?::(?7)?))|(?>(?>IPv6:(?>(?6)(?>:(?6)){5}:' . '|(?!(?:.*[a-f0-9]:){6,})(?8)?::(?>((?6)(?>:(?6)){0,4}):)?))?(25[0-5]|2[0-4][0-9]|1[0-9]{2}' . '|[1-9]?[0-9])(?>\.(?9)){3}))\])(?1)$/isD', $address);
            case  'pcre':
                return (boolean)preg_match('/^(?!(?>"?(?>\\\[ -~]|[^"])"?){255,})(?!(?>"?(?>\\\[ -~]|[^"])"?){65,}@)(?>' . '[!#-\'*+\/-9=?^-~-]+|"(?>(?>[\x01-\x08\x0B\x0C\x0E-!#-\[\]-\x7F]|\\\[\x00-\xFF]))*")' . '(?>\.(?>[!#-\'*+\/-9=?^-~-]+|"(?>(?>[\x01-\x08\x0B\x0C\x0E-!#-\[\]-\x7F]|\\\[\x00-\xFF]))*"))*' . '@(?>(?![a-z0-9-]{64,})(?>[a-z0-9](?>[a-z0-9-]*[a-z0-9])?)(?>\.(?![a-z0-9-]{64,})' . '(?>[a-z0-9](?>[a-z0-9-]*[a-z0-9])?)){0,126}|\[(?:(?>IPv6:(?>(?>[a-f0-9]{1,4})(?>:' . '[a-f0-9]{1,4}){7}|(?!(?:.*[a-f0-9][:\]]){8,})(?>[a-f0-9]{1,4}(?>:[a-f0-9]{1,4}){0,6})?' . '::(?>[a-f0-9]{1,4}(?>:[a-f0-9]{1,4}){0,6})?))|(?>(?>IPv6:(?>[a-f0-9]{1,4}(?>:' . '[a-f0-9]{1,4}){5}:|(?!(?:.*[a-f0-9]:){6,})(?>[a-f0-9]{1,4}(?>:[a-f0-9]{1,4}){0,4})?' . '::(?>(?:[a-f0-9]{1,4}(?>:[a-f0-9]{1,4}){0,4}):)?))?(?>25[0-5]|2[0-4][0-9]|1[0-9]{2}' . '|[1-9]?[0-9])(?>\.(?>25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}))\])$/isD', $address);
            case  'html5':
                return (boolean)preg_match('/^[a-zA-Z0-9.!#$%&\'*+\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}' . '[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/sD', $address);
            case  'noregex':
                return (strlen($address) >= 3 and strpos($address, '@') >= 1 and strpos($address, '@') != strlen($address) - 1);
            case  'php':
            default:
                return (boolean)filter_var($address, FILTER_VALIDATE_EMAIL);
        }
    }

    public function addCC($address, $name = '')
    {
        return $this->addAnAddress('cc', $address, $name);
    }

    public function addBCC($address, $name = '')
    {
        return $this->addAnAddress('bcc', $address, $name);
    }

    public function addReplyTo($address, $name = '')
    {
        return $this->addAnAddress('Reply-To', $address, $name);
    }

    public function setFrom($address, $name = '', $auto = true)
    {
        $address = trim($address);
        $name = trim(preg_replace('/[\r\n]+/', '', $name));
        if (!$this->validateAddress($address)) {
            $this->setError($this->lang('invalid_address') . ': ' . $address);
            $this->edebug($this->lang('invalid_address') . ': ' . $address);
            if ($this->exceptions) {
                throw new invalidAdressException($this->lang('invalid_address') . ': ' . $address);
            }
            return false;
        }
        $this->From = $address;
        $this->FromName = $name;
        if ($auto) {
            if (empty($this->Sender)) {
                $this->Sender = $address;
            }
        }
        return true;
    }

    public function getLastMessageID()
    {
        return $this->lastMessageID;
    }

    public function send()
    {
        try {
            if (!$this->preSend()) {
                return false;
            }
            return $this->postSend();
        } catch (invalidAdressException $exc) {
            $this->mailHeader = '';
            $this->setError($exc->getMessage());
            if ($this->exceptions) {
                throw $exc;
            }
            return false;
        }
    }

    public function preSend()
    {
        try {
            $this->mailHeader = '';
            if ((count($this->to) + count($this->cc) + count($this->bcc)) < 1) {
                throw new invalidAdressException($this->lang('provide_address'), self::STOP_CRITICAL);
            }
            if (!empty($this->AltBody)) {
                $this->ContentType = 'multipart/alternative';
            }
            $this->error_count = 0;
            $this->setMessageType();
            if (!$this->AllowEmpty and empty($this->Body)) {
                throw new invalidAdressException($this->lang('empty_message'), self::STOP_CRITICAL);
            }
            $this->MIMEHeader = $this->createHeader();
            $this->MIMEBody = $this->createBody();
            if ($this->Mailer == 'mail') {
                if (count($this->to) > 0) {
                    $this->mailHeader .= $this->addrAppend('To', $this->to);
                } else {
                    $this->mailHeader .= $this->headerLine('To', 'undisclosed-recipients:;
');
                }
                $this->mailHeader .= $this->headerLine('Subject', $this->encodeHeader($this->secureHeader(trim($this->Subject))));
            }
            if (!empty($this->DKIM_domain) && !empty($this->DKIM_private) && !empty($this->DKIM_selector) && !empty($this->DKIM_domain) && file_exists($this->DKIM_private)) {
                $header_dkim = $this->DKIM_Add($this->MIMEHeader . $this->mailHeader, $this->encodeHeader($this->secureHeader($this->Subject)), $this->MIMEBody);
                $this->MIMEHeader = rtrim($this->MIMEHeader, "\r\n ") . self::CRLF . str_replace("\r\n", "\n", $header_dkim) . self::CRLF;
            }
            return true;
        } catch (invalidAdressException $exc) {
            $this->setError($exc->getMessage());
            if ($this->exceptions) {
                throw $exc;
            }
            return false;
        }
    }

    protected function setMessageType()
    {
        $this->message_type = array();
        if ($this->alternativeExists()) {
            $this->message_type[] = 'alt';
        }
        if ($this->inlineImageExists()) {
            $this->message_type[] = 'inline';
        }
        if ($this->attachmentExists()) {
            $this->message_type[] = 'attach';
        }
        $this->message_type = implode('_', $this->message_type);
        if ($this->message_type == '') {
            $this->message_type = 'plain';
        }
    }

    public function alternativeExists()
    {
        return !empty($this->AltBody);
    }

    public function inlineImageExists()
    {
        foreach ($this->attachment as $attachment) {
            if ($attachment[6] == 'inline') {
                return true;
            }
        }
        return false;
    }

    public function attachmentExists()
    {
        foreach ($this->attachment as $attachment) {
            if ($attachment[6] == 'attachment') {
                return true;
            }
        }
        return false;
    }

    public function createHeader()
    {
        $result = '';
        $uniq_id = uniqid("priv8uts") . md5(time());
        $this->boundary[1] = 'b1_' . $uniq_id;
        $this->boundary[2] = 'b2_' . $uniq_id;
        $this->boundary[3] = 'b3_' . $uniq_id;
        if ($this->MessageDate == '') {
            $this->MessageDate = self::rfcDate();
        }
        $result .= $this->headerLine('Date', $this->MessageDate);
        if ($this->SingleTo === true) {
            if ($this->Mailer != 'mail') {
                foreach ($this->to as $toaddr) {
                    $this->SingleToArray[] = $this->addrFormat($toaddr);
                }
            }
        } else {
            if (count($this->to) > 0) {
                if ($this->Mailer != 'mail') {
                    $result .= $this->addrAppend('To', $this->to);
                }
            } elseif (count($this->cc) == 0) {
                $result .= $this->headerLine('To', 'undisclosed-recipients:;
');
            }
        }
        $result .= $this->addrAppend('From', array(array(trim($this->From), $this->FromName)));
        if (count($this->cc) > 0) {
            $result .= $this->addrAppend('Cc', $this->cc);
        }
        if (($this->Mailer == 'sendmail' or $this->Mailer == 'qmail' or $this->Mailer == 'mail') and count($this->bcc) > 0) {
            $result .= $this->addrAppend('Bcc', $this->bcc);
        }
        if (count($this->ReplyTo) > 0) {
            $result .= $this->addrAppend('Reply-To', $this->ReplyTo);
        }
        if ($this->Mailer != 'mail') {
            $result .= $this->headerLine('Subject', $this->encodeHeader($this->secureHeader($this->Subject)));
        }
        if ($this->MessageID != '') {
            $this->lastMessageID = $this->MessageID;
        } else {
            $this->lastMessageID = sprintf('<%s@%s>', $uniq_id, $this->ServerHostname());
        }
        $result .= $this->HeaderLine('Message-ID', $this->lastMessageID);
        $result .= $this->headerLine('X-Priority', $this->Priority);
        if ($this->XMailer == '') {
            $result .= $this->headerLine('X-Mailer', 'TJMailer' . $this->Version);
        } else {
            $myXmailer = trim($this->XMailer);
            if ($myXmailer) {
                $result .= $this->headerLine('X-Mailer', $myXmailer);
            }
        }
        if ($this->ConfirmReadingTo != '') {
            $result .= $this->headerLine('Disposition-Notification-To', '<' . trim($this->ConfirmReadingTo) . '>');
        }
        for ($index = 0;
             $index < count($this->CustomHeader);
             $index++) {
            $result .= $this->headerLine(trim($this->CustomHeader[$index][0]), $this->encodeHeader(trim($this->CustomHeader[$index][1])));
        }
        if (!$this->sign_key_file) {
            $result .= $this->headerLine('MIME-Version', '1.0');
            $result .= $this->getMailMIME();
        }
        return $result;
    }

    public static function rfcDate()
    {
        date_default_timezone_set(@date_default_timezone_get());
        return date('D, j M Y H:i:s O');
    }

    public function headerLine($name, $value)
    {
        return $name . ': ' . $value . $this->LE;
    }

    public function addrFormat($addr)
    {
        if (empty($addr[1])) {
            return $this->secureHeader($addr[0]);
        } else {
            return $this->encodeHeader($this->secureHeader($addr[1]), 'phrase') . ' <' . $this->secureHeader($addr[0]) . '>';
        }
    }

    public function secureHeader($str)
    {
        return trim(str_replace(array("\r", "\n"), '', $str));
    }

    public function encodeHeader($str, $position = 'text')
    {
        $matchcount = 0;
        switch (strtolower($position)) {
            case  'phrase':
                if (!preg_match('/[\200-\377]/', $str)) {
                    $encoded = addcslashes($str, "\0..\37\177\\\"");
                    if (($str == $encoded) && !preg_match('/[^A-Za-z0-9!#$%&\'*+\/=?^_`{|}~ -]/', $str)) {
                        return ($encoded);
                    } else {
                        return ("\"$encoded\"");
                    }
                }
                $matchcount = preg_match_all('/[^\040\041\043-\133\135-\176]/', $str, $matches);
                break;
            case  'comment':
                $matchcount = preg_match_all('/[()"]/', $str, $matches);
            case  'text':
            default:
                $matchcount += preg_match_all('/[\000-\010\013\014\016-\037\177-\377]/', $str, $matches);
                break;
        }
        if ($matchcount == 0) {
            return ($str);
        }
        $maxlen = 75 - 7 - strlen($this->CharSet);
        if ($matchcount > strlen($str) / 3) {
            $encoding = 'B';
            if (function_exists('mb_strlen') && $this->hasMultiBytes($str)) {
                $encoded = $this->base64EncodeWrapMB($str, "\n");
            } else {
                $encoded = base64_encode($str);
                $maxlen -= $maxlen % 4;
                $encoded = trim(chunk_split($encoded, $maxlen, "\n"));
            }
        } else {
            $encoding = 'Q';
            $encoded = $this->encodeQ($str, $position);
            $encoded = $this->wrapText($encoded, $maxlen, true);
            $encoded = str_replace('=' . self::CRLF, "\n", trim($encoded));
        }
        $encoded = preg_replace('/^(.*)$/m', ' =?' . $this->CharSet . "?$encoding?\\1?=", $encoded);
        $encoded = trim(str_replace("\n", $this->LE, $encoded));
        return $encoded;
    }

    public function hasMultiBytes($str)
    {
        if (function_exists('mb_strlen')) {
            return (strlen($str) > mb_strlen($str, $this->CharSet));
        } else {
            return false;
        }
    }

    public function base64EncodeWrapMB($str, $linebreak = null)
    {
        $start = '=?' . $this->CharSet . '?B?';
        $end = '?=';
        $encoded = '';
        if ($linebreak === null) {
            $linebreak = $this->LE;
        }
        $mb_length = mb_strlen($str, $this->CharSet);
        $length = 75 - strlen($start) - strlen($end);
        $ratio = $mb_length / strlen($str);
        $avgLength = floor($length * $ratio * .75);
        for ($i = 0;
             $i < $mb_length;
             $i += $offset) {
            $lookBack = 0;
            do {
                $offset = $avgLength - $lookBack;
                $chunk = mb_substr($str, $i, $offset, $this->CharSet);
                $chunk = base64_encode($chunk);
                $lookBack++;
            } while (strlen($chunk) > $length);
            $encoded .= $chunk . $linebreak;
        }
        $encoded = substr($encoded, 0, -strlen($linebreak));
        return $encoded;
    }

    public function encodeQ($str, $position = 'text')
    {
        $pattern = '';
        $encoded = str_replace(array("\r", "\n"), '', $str);
        switch (strtolower($position)) {
            case  'phrase':
                $pattern = '^A-Za-z0-9!*+\/ -';
                break;
            case  'comment':
                $pattern = '\(\)"';
            case  'text':
            default:
                $pattern = '\000-\011\013\014\016-\037\075\077\137\177-\377' . $pattern;
                break;
        }
        $matches = array();
        if (preg_match_all("/[{$pattern}]/", $encoded, $matches)) {
            $eqkey = array_search('=', $matches[0]);
            if ($eqkey !== false) {
                unset($matches[0][$eqkey]);
                array_unshift($matches[0], '=');
            }
            foreach (array_unique($matches[0]) as $char) {
                $encoded = str_replace($char, '=' . sprintf('%02X', ord($char)), $encoded);
            }
        }
        return str_replace(' ', '_', $encoded);
    }

    public function wrapText($message, $length, $qp_mode = false)
    {
        $soft_break = ($qp_mode) ? sprintf(' =%s', $this->LE) : $this->LE;
        $is_utf8 = (strtolower($this->CharSet) == 'utf-8');
        $lelen = strlen($this->LE);
        $crlflen = strlen(self::CRLF);
        $message = $this->fixEOL($message);
        if (substr($message, -$lelen) == $this->LE) {
            $message = substr($message, 0, -$lelen);
        }
        $line = explode($this->LE, $message);
        $message = '';
        for ($i = 0;
             $i < count($line);
             $i++) {
            $line_part = explode(' ', $line[$i]);
            $buf = '';
            for ($e = 0;
                 $e < count($line_part);
                 $e++) {
                $word = $line_part[$e];
                if ($qp_mode and (strlen($word) > $length)) {
                    $space_left = $length - strlen($buf) - $crlflen;
                    if ($e != 0) {
                        if ($space_left > 20) {
                            $len = $space_left;
                            if ($is_utf8) {
                                $len = $this->utf8CharBoundary($word, $len);
                            } elseif (substr($word, $len - 1, 1) == '=') {
                                $len--;
                            } elseif (substr($word, $len - 2, 1) == '=') {
                                $len -= 2;
                            }
                            $part = substr($word, 0, $len);
                            $word = substr($word, $len);
                            $buf .= ' ' . $part;
                            $message .= $buf . sprintf('=%s', self::CRLF);
                        } else {
                            $message .= $buf . $soft_break;
                        }
                        $buf = '';
                    }
                    while (strlen($word) > 0) {
                        if ($length <= 0) {
                            break;
                        }
                        $len = $length;
                        if ($is_utf8) {
                            $len = $this->utf8CharBoundary($word, $len);
                        } elseif (substr($word, $len - 1, 1) == '=') {
                            $len--;
                        } elseif (substr($word, $len - 2, 1) == '=') {
                            $len -= 2;
                        }
                        $part = substr($word, 0, $len);
                        $word = substr($word, $len);
                        if (strlen($word) > 0) {
                            $message .= $part . sprintf('=%s', self::CRLF);
                        } else {
                            $buf = $part;
                        }
                    }
                } else {
                    $buf_o = $buf;
                    $buf .= ($e == 0) ? $word : (' ' . $word);
                    if (strlen($buf) > $length and $buf_o != '') {
                        $message .= $buf_o . $soft_break;
                        $buf = $word;
                    }
                }
            }
            $message .= $buf . self::CRLF;
        }
        return $message;
    }

    public function fixEOL($str)
    {
        $nstr = str_replace(array("\r\n", "\r"), "\n", $str);
        if ($this->LE !== "\n") {
            $nstr = str_replace("\n", $this->LE, $nstr);
        }
        return $nstr;
    }

    public function utf8CharBoundary($encodedText, $maxLength)
    {
        $foundSplitPos = false;
        $lookBack = 3;
        while (!$foundSplitPos) {
            $lastChunk = substr($encodedText, $maxLength - $lookBack, $lookBack);
            $encodedCharPos = strpos($lastChunk, '=');
            if ($encodedCharPos !== false) {
                $hex = substr($encodedText, $maxLength - $lookBack + $encodedCharPos + 1, 2);
                $dec = hexdec($hex);
                if ($dec < 128) {
                    $maxLength = ($encodedCharPos == 0) ? $maxLength : $maxLength - ($lookBack - $encodedCharPos);
                    $foundSplitPos = true;
                } elseif ($dec >= 192) {
                    $maxLength = $maxLength - ($lookBack - $encodedCharPos);
                    $foundSplitPos = true;
                } elseif ($dec < 192) {
                    $lookBack += 3;
                }
            } else {
                $foundSplitPos = true;
            }
        }
        return $maxLength;
    }

    public function addrAppend($type, $addr)
    {
        $addresses = array();
        foreach ($addr as $address) {
            $addresses[] = $this->addrFormat($address);
        }
        return $type . ': ' . implode(', ', $addresses) . $this->LE;
    }

    protected function serverHostname()
    {
        $result = 'localhost.localdomain';
        if (!empty($this->Hostname)) {
            $result = $this->Hostname;
        } elseif (isset($_SERVER) and array_key_exists('SERVER_NAME', $_SERVER) and !empty($_SERVER['SERVER_NAME'])) {
            $result = $_SERVER['SERVER_NAME'];
        } elseif (function_exists('gethostname') && gethostname() !== false) {
            $result = gethostname();
        } elseif (php_uname('n') !== false) {
            $result = php_uname('n');
        }
        return $result;
    }

    public function getMailMIME()
    {
        $result = '';
        $ismultipart = true;
        switch ($this->message_type) {
            case  'inline':
                $result .= $this->headerLine('Content-Type', 'multipart/related;');
                $result .= $this->textLine("\tboundary=\"" . $this->boundary[1] . '"');
                break;
            case  'attach':
            case  'inline_attach':
            case  'alt_attach':
            case  'alt_inline_attach':
                $result .= $this->headerLine('Content-Type', 'multipart/mixed;');
                $result .= $this->textLine("\tboundary=\"" . $this->boundary[1] . '"');
                break;
            case  'alt':
            case  'alt_inline':
                $result .= $this->headerLine('Content-Type', 'multipart/alternative;');
                $result .= $this->textLine("\tboundary=\"" . $this->boundary[1] . '"');
                break;
            default:
                $result .= $this->textLine('Content-Type: ' . $this->ContentType . ';charset=' . $this->CharSet);
                $ismultipart = false;
                break;
        }
        if ($this->Encoding != '7bit') {
            if ($ismultipart) {
                if ($this->Encoding == '8bit') {
                    $result .= $this->headerLine('Content-Transfer-Encoding', '8bit');
                }
            } else {
                $result .= $this->headerLine('Content-Transfer-Encoding', $this->Encoding);
            }
        }
        if ($this->Mailer != 'mail') {
            $result .= $this->LE;
        }
        return $result;
    }

    public function textLine($value)
    {
        return $value . $this->LE;
    }

    public function createBody()
    {
        $body = '';
        if ($this->sign_key_file) {
            $body .= $this->getMailMIME() . $this->LE;
        }
        $this->setWordWrap();
        $bodyEncoding = $this->Encoding;
        $bodyCharSet = $this->CharSet;
        if ($bodyEncoding == '8bit' and !$this->has8bitChars($this->Body)) {
            $bodyEncoding = '7bit';
            $bodyCharSet = 'us-ascii';
        }
        $altBodyEncoding = $this->Encoding;
        $altBodyCharSet = $this->CharSet;
        if ($altBodyEncoding == '8bit' and !$this->has8bitChars($this->AltBody)) {
            $altBodyEncoding = '7bit';
            $altBodyCharSet = 'us-ascii';
        }
        switch ($this->message_type) {
            case  'inline':
                $body .= $this->getBoundary($this->boundary[1], $bodyCharSet, '', $bodyEncoding);
                $body .= $this->encodeString($this->Body, $bodyEncoding);
                $body .= $this->LE . $this->LE;
                $body .= $this->attachAll('inline', $this->boundary[1]);
                break;
            case  'attach':
                $body .= $this->getBoundary($this->boundary[1], $bodyCharSet, '', $bodyEncoding);
                $body .= $this->encodeString($this->Body, $bodyEncoding);
                $body .= $this->LE . $this->LE;
                $body .= $this->attachAll('attachment', $this->boundary[1]);
                break;
            case  'inline_attach':
                $body .= $this->textLine('--' . $this->boundary[1]);
                $body .= $this->headerLine('Content-Type', 'multipart/related;');
                $body .= $this->textLine("\tboundary=\"" . $this->boundary[2] . '"');
                $body .= $this->LE;
                $body .= $this->getBoundary($this->boundary[2], $bodyCharSet, '', $bodyEncoding);
                $body .= $this->encodeString($this->Body, $bodyEncoding);
                $body .= $this->LE . $this->LE;
                $body .= $this->attachAll('inline', $this->boundary[2]);
                $body .= $this->LE;
                $body .= $this->attachAll('attachment', $this->boundary[1]);
                break;
            case  'alt':
                $body .= $this->getBoundary($this->boundary[1], $altBodyCharSet, 'text/plain', $altBodyEncoding);
                $body .= $this->encodeString($this->AltBody, $altBodyEncoding);
                $body .= $this->LE . $this->LE;
                $body .= $this->getBoundary($this->boundary[1], $bodyCharSet, 'text/html', $bodyEncoding);
                $body .= $this->encodeString($this->Body, $bodyEncoding);
                $body .= $this->LE . $this->LE;
                if (!empty($this->Ical)) {
                    $body .= $this->getBoundary($this->boundary[1], '', 'text/calendar; method=REQUEST', '');
                    $body .= $this->encodeString($this->Ical, $this->Encoding);
                    $body .= $this->LE . $this->LE;
                }
                $body .= $this->endBoundary($this->boundary[1]);
                break;
            case  'alt_inline':
                $body .= $this->getBoundary($this->boundary[1], $altBodyCharSet, 'text/plain', $altBodyEncoding);
                $body .= $this->encodeString($this->AltBody, $altBodyEncoding);
                $body .= $this->LE . $this->LE;
                $body .= $this->textLine('--' . $this->boundary[1]);
                $body .= $this->headerLine('Content-Type', 'multipart/related;');
                $body .= $this->textLine("\tboundary=\"" . $this->boundary[2] . '"');
                $body .= $this->LE;
                $body .= $this->getBoundary($this->boundary[2], $bodyCharSet, 'text/html', $bodyEncoding);
                $body .= $this->encodeString($this->Body, $bodyEncoding);
                $body .= $this->LE . $this->LE;
                $body .= $this->attachAll('inline', $this->boundary[2]);
                $body .= $this->LE;
                $body .= $this->endBoundary($this->boundary[1]);
                break;
            case  'alt_attach':
                $body .= $this->textLine('--' . $this->boundary[1]);
                $body .= $this->headerLine('Content-Type', 'multipart/alternative;');
                $body .= $this->textLine("\tboundary=\"" . $this->boundary[2] . '"');
                $body .= $this->LE;
                $body .= $this->getBoundary($this->boundary[2], $altBodyCharSet, 'text/plain', $altBodyEncoding);
                $body .= $this->encodeString($this->AltBody, $altBodyEncoding);
                $body .= $this->LE . $this->LE;
                $body .= $this->getBoundary($this->boundary[2], $bodyCharSet, 'text/html', $bodyEncoding);
                $body .= $this->encodeString($this->Body, $bodyEncoding);
                $body .= $this->LE . $this->LE;
                $body .= $this->endBoundary($this->boundary[2]);
                $body .= $this->LE;
                $body .= $this->attachAll('attachment', $this->boundary[1]);
                break;
            case  'alt_inline_attach':
                $body .= $this->textLine('--' . $this->boundary[1]);
                $body .= $this->headerLine('Content-Type', 'multipart/alternative;');
                $body .= $this->textLine("\tboundary=\"" . $this->boundary[2] . '"');
                $body .= $this->LE;
                $body .= $this->getBoundary($this->boundary[2], $altBodyCharSet, 'text/plain', $altBodyEncoding);
                $body .= $this->encodeString($this->AltBody, $altBodyEncoding);
                $body .= $this->LE . $this->LE;
                $body .= $this->textLine('--' . $this->boundary[2]);
                $body .= $this->headerLine('Content-Type', 'multipart/related;');
                $body .= $this->textLine("\tboundary=\"" . $this->boundary[3] . '"');
                $body .= $this->LE;
                $body .= $this->getBoundary($this->boundary[3], $bodyCharSet, 'text/html', $bodyEncoding);
                $body .= $this->encodeString($this->Body, $bodyEncoding);
                $body .= $this->LE . $this->LE;
                $body .= $this->attachAll('inline', $this->boundary[3]);
                $body .= $this->LE;
                $body .= $this->endBoundary($this->boundary[2]);
                $body .= $this->LE;
                $body .= $this->attachAll('attachment', $this->boundary[1]);
                break;
            default:
                $body .= $this->encodeString($this->Body, $bodyEncoding);
                break;
        }
        if ($this->isError()) {
            $body = '';
        } elseif ($this->sign_key_file) {
            try {
                if (!defined('PKCS7_TEXT')) {
                    throw new invalidAdressException($this->lang('signing') . ' OpenSSL extension missing.');
                }
                $file = tempnam(sys_get_temp_dir(), 'mail');
                file_put_contents($file, $body);
                $signed = tempnam(sys_get_temp_dir(), 'signed');
                if (@openssl_pkcs7_sign($file, $signed, 'file://' . realpath($this->sign_cert_file), array('file://' . realpath($this->sign_key_file), $this->sign_key_pass), null)) {
                    @unlink($file);
                    $body = file_get_contents($signed);
                    @unlink($signed);
                } else {
                    @unlink($file);
                    @unlink($signed);
                    throw new invalidAdressException($this->lang('signing') . openssl_error_string());
                }
            } catch (invalidAdressException $exc) {
                $body = '';
                if ($this->exceptions) {
                    throw $exc;
                }
            }
        }
        return $body;
    }

    public function setWordWrap()
    {
        if ($this->WordWrap < 1) {
            return;
        }
        switch ($this->message_type) {
            case  'alt':
            case  'alt_inline':
            case  'alt_attach':
            case  'alt_inline_attach':
                $this->AltBody = $this->wrapText($this->AltBody, $this->WordWrap);
                break;
            default:
                $this->Body = $this->wrapText($this->Body, $this->WordWrap);
                break;
        }
    }

    public function has8bitChars($text)
    {
        return (boolean)preg_match('/[\x80-\xFF]/', $text);
    }

    protected function getBoundary($boundary, $charSet, $contentType, $encoding)
    {
        $result = '';
        if ($charSet == '') {
            $charSet = $this->CharSet;
        }
        if ($contentType == '') {
            $contentType = $this->ContentType;
        }
        if ($encoding == '') {
            $encoding = $this->Encoding;
        }
        $result .= $this->textLine('--' . $boundary);
        $result .= sprintf('Content-Type: %s;charset=%s', $contentType, $charSet);
        $result .= $this->LE;
        if ($encoding != '7bit') {
            $result .= $this->headerLine('Content-Transfer-Encoding', $encoding);
        }
        $result .= $this->LE;
        return $result;
    }

    public function encodeString($str, $encoding = 'base64')
    {
        $encoded = '';
        switch (strtolower($encoding)) {
            case  'base64':
                $encoded = chunk_split(base64_encode($str), 76, $this->LE);
                break;
            case  '7bit':
            case  '8bit':
                $encoded = $this->fixEOL($str);
                if (substr($encoded, -(strlen($this->LE))) != $this->LE) {
                    $encoded .= $this->LE;
                }
                break;
            case  'binary':
                $encoded = $str;
                break;
            case  'quoted-printable':
                $encoded = $this->encodeQP($str);
                break;
            default:
                $this->setError($this->lang('encoding') . $encoding);
                break;
        }
        return $encoded;
    }

    public function encodeQP($string, $line_max = 76)
    {
        if (function_exists('quoted_printable_encode')) {
            return $this->fixEOL(quoted_printable_encode($string));
        }
        $string = str_replace(array('%20', '%0D%0A.', '%0D%0A', '%'), array(' ', "\r\n=2E", "\r\n", '='), rawurlencode($string));
        $string = preg_replace('/[^\r\n]{' . ($line_max - 3) . '}[^=\r\n]{2}/', "$0=\r\n", $string);
        return $this->fixEOL($string);
    }

    protected function attachAll($disposition_type, $boundary)
    {
        $mime = array();
        $cidUniq = array();
        $incl = array();
        foreach ($this->attachment as $attachment) {
            if ($attachment[6] == $disposition_type) {
                $string = '';
                $path = '';
                $bString = $attachment[5];
                if ($bString) {
                    $string = $attachment[0];
                } else {
                    $path = $attachment[0];
                }
                $inclhash = md5(serialize($attachment));
                if (in_array($inclhash, $incl)) {
                    continue;
                }
                $incl[] = $inclhash;
                $name = $attachment[2];
                $encoding = $attachment[3];
                $type = $attachment[4];
                $disposition = $attachment[6];
                $cid = $attachment[7];
                if ($disposition == 'inline' && isset($cidUniq[$cid])) {
                    continue;
                }
                $cidUniq[$cid] = true;
                $mime[] = sprintf('--%s%s', $boundary, $this->LE);
                $mime[] = sprintf('Content-Type: %s; name="%s"%s', $type, $this->encodeHeader($this->secureHeader($name)), $this->LE);
                if ($encoding != '7bit') {
                    $mime[] = sprintf('Content-Transfer-Encoding: %s%s', $encoding, $this->LE);
                }
                if ($disposition == 'inline') {
                    $mime[] = sprintf('Content-ID: <%s>%s', $cid, $this->LE);
                }
                if (!(empty($disposition))) {
                    if (preg_match('/[ \(\)<>@,;:\\"\/\[\]\?=]/', $name)) {
                        $mime[] = sprintf('Content-Disposition: %s;filename="%s"%s', $disposition, $this->encodeHeader($this->secureHeader($name)), $this->LE . $this->LE);
                    } else {
                        $mime[] = sprintf('Content-Disposition: %s; filename=%s%s', $disposition, $this->encodeHeader($this->secureHeader($name)), $this->LE . $this->LE);
                    }
                } else {
                    $mime[] = $this->LE;
                }
                if ($bString) {
                    $mime[] = $this->encodeString($string, $encoding);
                    if ($this->isError()) {
                        return '';
                    }
                    $mime[] = $this->LE . $this->LE;
                } else {
                    $mime[] = $this->encodeFile($path, $encoding);
                    if ($this->isError()) {
                        return '';
                    }
                    $mime[] = $this->LE . $this->LE;
                }
            }
        }
        $mime[] = sprintf('--%s--%s', $boundary, $this->LE);
        return implode('', $mime);
    }

    public function isError()
    {
        return ($this->error_count > 0);
    }

    protected function encodeFile($path, $encoding = 'base64')
    {
        try {
            if (!is_readable($path)) {
                throw new invalidAdressException($this->lang('file_open') . $path, self::STOP_CONTINUE);
            }
            $magic_quotes = get_magic_quotes_runtime();
            if ($magic_quotes) {
                if (version_compare(PHP_VERSION, '5.3.0', '<')) {
                    set_magic_quotes_runtime(false);
                } else {
                    ini_set('magic_quotes_runtime', 0);
                }
            }
            $file_buffer = file_get_contents($path);
            $file_buffer = $this->encodeString($file_buffer, $encoding);
            if ($magic_quotes) {
                if (version_compare(PHP_VERSION, '5.3.0', '<')) {
                    set_magic_quotes_runtime($magic_quotes);
                } else {
                    ini_set('magic_quotes_runtime', ($magic_quotes ? '1' : '0'));
                }
            }
            return $file_buffer;
        } catch (Exception $exc) {
            $this->setError($exc->getMessage());
            return '';
        }
    }

    protected function endBoundary($boundary)
    {
        return $this->LE . '--' . $boundary . '--' . $this->LE;
    }

    public function DKIM_Add($headers_line, $subject, $body)
    {
        $DKIMsignatureType = 'rsa-sha1';
        $DKIMcanonicalization = 'relaxed/simple';
        $DKIMquery = 'dns/txt';
        $DKIMtime = time();
        $subject_header = "Subject: $subject";
        $headers = explode($this->LE, $headers_line);
        $from_header = '';
        $to_header = '';
        $current = '';
        foreach ($headers as $header) {
            if (strpos($header, 'From:') === 0) {
                $from_header = $header;
                $current = 'from_header';
            } elseif (strpos($header, 'To:') === 0) {
                $to_header = $header;
                $current = 'to_header';
            } else {
                if ($current && strpos($header, ' =?') === 0) {
                    $current .= $header;
                } else {
                    $current = '';
                }
            }
        }
        $from = str_replace('|', '=7C', $this->DKIM_QP($from_header));
        $to = str_replace('|', '=7C', $this->DKIM_QP($to_header));
        $subject = str_replace('|', '=7C', $this->DKIM_QP($subject_header));
        $body = $this->DKIM_BodyC($body);
        $DKIMlen = strlen($body);
        $DKIMb64 = base64_encode(pack('H*', sha1($body)));
        $ident = ($this->DKIM_identity == '') ? '' : ' i=' . $this->DKIM_identity . ';';
        $dkimhdrs = 'DKIM-Signature: v=1; a=' . $DKIMsignatureType . '; q=' . $DKIMquery . '; l=' . $DKIMlen . '; s=' . $this->DKIM_selector . ";\r\n" . "\tt=" . $DKIMtime . ';c=' . $DKIMcanonicalization . ";\r\n" . "\th=From:To:Subject;\r\n" . "\td=" . $this->DKIM_domain . ';' . $ident . "\r\n" . "\tz=$from\r\n" . "\t|$to\r\n" . "\t|$subject;\r\n" . "\tbh=" . $DKIMb64 . ";\r\n" . "\tb=";
        $toSign = $this->DKIM_HeaderC($from_header . "\r\n" . $to_header . "\r\n" . $subject_header . "\r\n" . $dkimhdrs);
        $signed = $this->DKIM_Sign($toSign);
        return $dkimhdrs . $signed . "\r\n";
    }

    public function DKIM_QP($txt)
    {
        $line = '';
        for ($i = 0;
             $i < strlen($txt);
             $i++) {
            $ord = ord($txt[$i]);
            if (((0x21 <= $ord) && ($ord <= 0x3A)) || $ord == 0x3C || ((0x3E <= $ord) && ($ord <= 0x7E))) {
                $line .= $txt[$i];
            } else {
                $line .= '=' . sprintf('%02X', $ord);
            }
        }
        return $line;
    }

    public function DKIM_BodyC($body)
    {
        if ($body == '') {
            return "\r\n";
        }
        $body = str_replace("\r\n", "\n", $body);
        $body = str_replace("\n", "\r\n", $body);
        while (substr($body, strlen($body) - 4, 4) == "\r\n\r\n") {
            $body = substr($body, 0, strlen($body) - 2);
        }
        return $body;
    }

    public function DKIM_HeaderC($signHeader)
    {
        $signHeader = preg_replace('/\r\n\s+/', ' ', $signHeader);
        $lines = explode("\r\n", $signHeader);
        foreach ($lines as $key => $line) {
            list($heading, $value) = explode(':', $line, 2);
            $heading = strtolower($heading);
            $value = preg_replace('/\s+/', ' ', $value);
            $lines[$key] = $heading . ':' . trim($value);
        }
        $signHeader = implode("\r\n", $lines);
        return $signHeader;
    }

    public function DKIM_Sign($signHeader)
    {
        if (!defined('PKCS7_TEXT')) {
            if ($this->exceptions) {
                throw new invalidAdressException($this->lang('signing') . ' OpenSSL extension missing.');
            }
            return '';
        }
        $privKeyStr = file_get_contents($this->DKIM_private);
        if ($this->DKIM_passphrase != '') {
            $privKey = openssl_pkey_get_private($privKeyStr, $this->DKIM_passphrase);
        } else {
            $privKey = $privKeyStr;
        }
        if (openssl_sign($signHeader, $signature, $privKey)) {
            return base64_encode($signature);
        }
        return '';
    }

    public function postSend()
    {
        try {
            switch ($this->Mailer) {
                case  'sendmail':
                case  'qmail':
                    return $this->sendmailSend($this->MIMEHeader, $this->MIMEBody);
                case  'smtp':
                    return $this->smtpSend($this->MIMEHeader, $this->MIMEBody);
                case  'mail':
                    return $this->mailSend($this->MIMEHeader, $this->MIMEBody);
                default:
                    $sendMethod = $this->Mailer . 'Send';
                    if (method_exists($this, $sendMethod)) {
                        return $this->$sendMethod($this->MIMEHeader, $this->MIMEBody);
                    }
                    return $this->mailSend($this->MIMEHeader, $this->MIMEBody);
            }
        } catch (invalidAdressException $exc) {
            $this->setError($exc->getMessage());
            $this->edebug($exc->getMessage());
            if ($this->exceptions) {
                throw $exc;
            }
        }
        return false;
    }

    protected function sendmailSend($header, $body)
    {
        if ($this->Sender != '') {
            if ($this->Mailer == 'qmail') {
                $sendmail = sprintf('%s -f%s', escapeshellcmd($this->Sendmail), escapeshellarg($this->Sender));
            } else {
                $sendmail = sprintf('%s -oi -f%s -t', escapeshellcmd($this->Sendmail), escapeshellarg($this->Sender));
            }
        } else {
            if ($this->Mailer == 'qmail') {
                $sendmail = sprintf('%s', escapeshellcmd($this->Sendmail));
            } else {
                $sendmail = sprintf('%s -oi -t', escapeshellcmd($this->Sendmail));
            }
        }
        if ($this->SingleTo === true) {
            foreach ($this->SingleToArray as $toAddr) {
                if (!@$mail = popen($sendmail, 'w')) {
                    throw new invalidAdressException($this->lang('execute') . $this->Sendmail, self::STOP_CRITICAL);
                }
                fputs($mail, 'To: ' . $toAddr . "\n");
                fputs($mail, $header);
                fputs($mail, $body);
                $result = pclose($mail);
                $this->doCallback(($result == 0), array($toAddr), $this->cc, $this->bcc, $this->Subject, $body, $this->From);
                if ($result != 0) {
                    throw new invalidAdressException($this->lang('execute') . $this->Sendmail, self::STOP_CRITICAL);
                }
            }
        } else {
            if (!@$mail = popen($sendmail, 'w')) {
                throw new invalidAdressException($this->lang('execute') . $this->Sendmail, self::STOP_CRITICAL);
            }
            fputs($mail, $header);
            fputs($mail, $body);
            $result = pclose($mail);
            $this->doCallback(($result == 0), $this->to, $this->cc, $this->bcc, $this->Subject, $body, $this->From);
            if ($result != 0) {
                throw new invalidAdressException($this->lang('execute') . $this->Sendmail, self::STOP_CRITICAL);
            }
        }
        return true;
    }

    protected function doCallback($isSent, $to, $cc, $bcc, $subject, $body, $from)
    {
        if (!empty($this->action_function) && is_callable($this->action_function)) {
            $params = array($isSent, $to, $cc, $bcc, $subject, $body, $from);
            call_user_func_array($this->action_function, $params);
        }
    }

    protected function smtpSend($header, $body)
    {
        $bad_rcpt = array();
        if (!$this->smtpConnect()) {
            throw new invalidAdressException($this->lang('smtp_connect_failed'), self::STOP_CRITICAL);
        }
        $smtp_from = ($this->Sender == '') ? $this->From : $this->Sender;
        if (!$this->smtp->mail($smtp_from)) {
            $this->setError($this->lang('from_failed') . $smtp_from . ' : ' . implode(',', $this->smtp->getError()));
            throw new invalidAdressException($this->ErrorInfo, self::STOP_CRITICAL);
        }
        foreach ($this->to as $to) {
            if (!$this->smtp->recipient($to[0])) {
                $bad_rcpt[] = $to[0];
                $isSent = false;
            } else {
                $isSent = true;
            }
            $this->doCallback($isSent, array($to[0]), array(), array(), $this->Subject, $body, $this->From);
        }
        foreach ($this->cc as $cc) {
            if (!$this->smtp->recipient($cc[0])) {
                $bad_rcpt[] = $cc[0];
                $isSent = false;
            } else {
                $isSent = true;
            }
            $this->doCallback($isSent, array(), array($cc[0]), array(), $this->Subject, $body, $this->From);
        }
        foreach ($this->bcc as $bcc) {
            if (!$this->smtp->recipient($bcc[0])) {
                $bad_rcpt[] = $bcc[0];
                $isSent = false;
            } else {
                $isSent = true;
            }
            $this->doCallback($isSent, array(), array(), array($bcc[0]), $this->Subject, $body, $this->From);
        }
        if ((count($this->all_recipients) > count($bad_rcpt)) and !$this->smtp->data($header . $body)) {
            throw new invalidAdressException($this->lang('data_not_accepted'), self::STOP_CRITICAL);
        }
        if ($this->SMTPKeepAlive == true) {
            $this->smtp->reset();
        } else {
            $this->smtp->quit();
            $this->smtp->close();
        }
        if (count($bad_rcpt) > 0) {
            throw new invalidAdressException($this->lang('recipients_failed') . implode(', ', $bad_rcpt), self::STOP_CONTINUE);
        }
        return true;
    }

    public function smtpConnect($options = array())
    {
        if (is_null($this->smtp)) {
            $this->smtp = $this->getSMTPInstance();
        }
        if ($this->smtp->connected()) {
            return true;
        }
        $this->smtp->setTimeout($this->Timeout);
        $this->smtp->setDebugLevel($this->SMTPDebug);
        $this->smtp->setDebugOutput($this->Debugoutput);
        $this->smtp->setVerp($this->do_verp);
        $hosts = explode(';
', $this->Host);
        $lastexception = null;
        foreach ($hosts as $hostentry) {
            $hostinfo = array();
            if (!preg_match('/^((ssl|tls):\/\/)*([a-zA-Z0-9\.-]*):?([0-9]*)$/', trim($hostentry), $hostinfo)) {
                continue;
            }
            $prefix = '';
            $tls = ($this->SMTPSecure == 'tls');
            if ($hostinfo[2] == 'ssl' or ($hostinfo[2] == '' and $this->SMTPSecure == 'ssl')) {
                $prefix = 'ssl://';
                $tls = false;
            } elseif ($hostinfo[2] == 'tls') {
                $tls = true;
            }
            $host = $hostinfo[3];
            $port = $this->Port;
            $tport = (integer)$hostinfo[4];
            if ($tport > 0 and $tport < 65536) {
                $port = $tport;
            }
            if ($this->smtp->connect($prefix . $host, $port, $this->Timeout, $options)) {
                try {
                    if ($this->Helo) {
                        $hello = $this->Helo;
                    } else {
                        $hello = $this->serverHostname();
                    }
                    $this->smtp->hello($hello);
                    if ($tls) {
                        if (!$this->smtp->startTLS()) {
                            throw new invalidAdressException($this->lang('connect_host'));
                        }
                        $this->smtp->hello($hello);
                    }
                    if ($this->SMTPAuth) {
                        if (!$this->smtp->authenticate($this->Username, $this->Password, $this->AuthType, $this->Realm, $this->Workstation)) {
                            throw new invalidAdressException($this->lang('authenticate'));
                        }
                    }
                    return true;
                } catch (invalidAdressException $exc) {
                    $lastexception = $exc;
                    $this->smtp->quit();
                }
            }
        }
        $this->smtp->close();
        if ($this->exceptions and !is_null($lastexception)) {
            throw $lastexception;
        }
        return false;
    }

    public function getSMTPInstance()
    {
        if (!is_object($this->smtp)) {
            $this->smtp = new SMTP;
        }
        return $this->smtp;
    }

    protected function mailSend($header, $body)
    {
        $toArr = array();
        foreach ($this->to as $toaddr) {
            $toArr[] = $this->addrFormat($toaddr);
        }
        $to = implode(', ', $toArr);
        if (empty($this->Sender)) {
            $params = ' ';
        } else {
            $params = sprintf('-f%s', $this->Sender);
        }
        if ($this->Sender != '' and !ini_get('safe_mode')) {
            $old_from = ini_get('sendmail_from');
            ini_set('sendmail_from', $this->Sender);
        }
        $result = false;
        if ($this->SingleTo === true && count($toArr) > 1) {
            foreach ($toArr as $toAddr) {
                $result = $this->mailPassthru($toAddr, $this->Subject, $body, $header, $params);
                $this->doCallback($result, array($toAddr), $this->cc, $this->bcc, $this->Subject, $body, $this->From);
            }
        } else {
            $result = $this->mailPassthru($to, $this->Subject, $body, $header, $params);
            $this->doCallback($result, $this->to, $this->cc, $this->bcc, $this->Subject, $body, $this->From);
        }
        if (isset($old_from)) {
            ini_set('sendmail_from', $old_from);
        }
        if (!$result) {
            throw new invalidAdressException($this->lang('instantiate'), self::STOP_CRITICAL);
        }
        return true;
    }

    private function mailPassthru($to, $subject, $body, $header, $params)
    {
        if (ini_get('mbstring.func_overload') & 1) {
            $subject = $this->secureHeader($subject);
        } else {
            $subject = $this->encodeHeader($this->secureHeader($subject));
        }
        if (ini_get('safe_mode') || !($this->UseSendmailOptions)) {
            $result = @mail($to, $subject, $body, $header);
        } else {
            $result = @mail($to, $subject, $body, $header, $params);
        }
        return $result;
    }

    public function getTranslations()
    {
        return $this->language;
    }

    public function getSentMIMEMessage()
    {
        return $this->MIMEHeader . $this->mailHeader . self::CRLF . $this->MIMEBody;
    }

    public function addAttachment($path, $name = '', $encoding = 'base64', $type = '', $disposition = 'attachment')
    {
        try {
            if (!@is_file($path)) {
                throw new invalidAdressException($this->lang('file_access') . $path, self::STOP_CONTINUE);
            }
            if ($type == '') {
                $type = self::filenameToType($path);
            }
            $filename = basename($path);
            if ($name == '') {
                $name = $filename;
            }
            $this->attachment[] = array(0 => $path, 1 => $filename, 2 => $name, 3 => $encoding, 4 => $type, 5 => false, 6 => $disposition, 7 => 0);
        } catch (invalidAdressException $exc) {
            $this->setError($exc->getMessage());
            $this->edebug($exc->getMessage());
            if ($this->exceptions) {
                throw $exc;
            }
            return false;
        }
        return true;
    }

    public static function filenameToType($filename)
    {
        $qpos = strpos($filename, '?');
        if ($qpos !== false) {
            $filename = substr($filename, 0, $qpos);
        }
        $pathinfo = self::mb_pathinfo($filename);
        return self::_mime_types($pathinfo['extension']);
    }

    public static function mb_pathinfo($path, $options = null)
    {
        $ret = array('dirname' => '', 'basename' => '', 'extension' => '', 'filename' => '');
        $pathinfo = array();
        if (preg_match('%^(.*?)[\\\\/]*(([^/\\\\]*?)(\.([^\.\\\\/]+?)|))[\\\\/\.]*$%im', $path, $pathinfo)) {
            if (array_key_exists(1, $pathinfo)) {
                $ret['dirname'] = $pathinfo[1];
            }
            if (array_key_exists(2, $pathinfo)) {
                $ret['basename'] = $pathinfo[2];
            }
            if (array_key_exists(5, $pathinfo)) {
                $ret['extension'] = $pathinfo[5];
            }
            if (array_key_exists(3, $pathinfo)) {
                $ret['filename'] = $pathinfo[3];
            }
        }
        switch ($options) {
            case  PATHINFO_DIRNAME:
            case  'dirname':
                return $ret['dirname'];
            case  PATHINFO_BASENAME:
            case  'basename':
                return $ret['basename'];
            case  PATHINFO_EXTENSION:
            case  'extension':
                return $ret['extension'];
            case  PATHINFO_FILENAME:
            case  'filename':
                return $ret['filename'];
            default:
                return $ret;
        }
    }

    public static function _mime_types($ext = '')
    {
        $mimes = array('xl' => 'application/excel', 'hqx' => 'application/mac-binhex40', 'cpt' => 'application/mac-compactpro', 'bin' => 'application/macbinary', 'doc' => 'application/msword', 'word' => 'application/msword', 'class' => 'application/octet-stream', 'dll' => 'application/octet-stream', 'dms' => 'application/octet-stream', 'exe' => 'application/octet-stream', 'lha' => 'application/octet-stream', 'lzh' => 'application/octet-stream', 'psd' => 'application/octet-stream', 'sea' => 'application/octet-stream', 'so' => 'application/octet-stream', 'oda' => 'application/oda', 'pdf' => 'application/pdf', 'ai' => 'application/postscript', 'eps' => 'application/postscript', 'ps' => 'application/postscript', 'smi' => 'application/smil', 'smil' => 'application/smil', 'mif' => 'application/vnd.mif', 'xls' => 'application/vnd.ms-excel', 'ppt' => 'application/vnd.ms-powerpoint', 'wbxml' => 'application/vnd.wap.wbxml', 'wmlc' => 'application/vnd.wap.wmlc', 'dcr' => 'application/x-director', 'dir' => 'application/x-director', 'dxr' => 'application/x-director', 'dvi' => 'application/x-dvi', 'gtar' => 'application/x-gtar', 'php3' => 'application/x-httpd-php', 'php4' => 'application/x-httpd-php', 'php' => 'application/x-httpd-php', 'phtml' => 'application/x-httpd-php', 'phps' => 'application/x-httpd-php-source', 'js' => 'application/x-javascript', 'swf' => 'application/x-shockwave-flash', 'sit' => 'application/x-stuffit', 'tar' => 'application/x-tar', 'tgz' => 'application/x-tar', 'xht' => 'application/xhtml+xml', 'xhtml' => 'application/xhtml+xml', 'zip' => 'application/zip', 'mid' => 'audio/midi', 'midi' => 'audio/midi', 'mp2' => 'audio/mpeg', 'mp3' => 'audio/mpeg', 'mpga' => 'audio/mpeg', 'aif' => 'audio/x-aiff', 'aifc' => 'audio/x-aiff', 'aiff' => 'audio/x-aiff', 'ram' => 'audio/x-pn-realaudio', 'rm' => 'audio/x-pn-realaudio', 'rpm' => 'audio/x-pn-realaudio-plugin', 'ra' => 'audio/x-realaudio', 'wav' => 'audio/x-wav', 'bmp' => 'image/bmp', 'gif' => 'image/gif', 'jpeg' => 'image/jpeg', 'jpe' => 'image/jpeg', 'jpg' => 'image/jpeg', 'png' => 'image/png', 'tiff' => 'image/tiff', 'tif' => 'image/tiff', 'eml' => 'message/rfc822', 'css' => 'text/css', 'html' => 'text/html', 'htm' => 'text/html', 'shtml' => 'text/html', 'log' => 'text/plain', 'text' => 'text/plain', 'txt' => 'text/plain', 'rtx' => 'text/richtext', 'rtf' => 'text/rtf', 'vcf' => 'text/vcard', 'vcard' => 'text/vcard', 'xml' => 'text/xml', 'xsl' => 'text/xml', 'mpeg' => 'video/mpeg', 'mpe' => 'video/mpeg', 'mpg' => 'video/mpeg', 'mov' => 'video/quicktime', 'qt' => 'video/quicktime', 'rv' => 'video/vnd.rn-realvideo', 'avi' => 'video/x-msvideo', 'movie' => 'video/x-sgi-movie');
        return (array_key_exists(strtolower($ext), $mimes) ? $mimes[strtolower($ext)] : 'application/octet-stream');
    }

    public function getAttachments()
    {
        return $this->attachment;
    }

    public function encodeQPphp($string, $line_max = 76, $space_conv = false)
    {
        return $this->encodeQP($string, $line_max);
    }

    public function addStringAttachment($string, $filename, $encoding = 'base64', $type = '', $disposition = 'attachment')
    {
        if ($type == '') {
            $type = self::filenameToType($filename);
        }
        $this->attachment[] = array(0 => $string, 1 => $filename, 2 => basename($filename), 3 => $encoding, 4 => $type, 5 => true, 6 => $disposition, 7 => 0);
    }

    public function addStringEmbeddedImage($string, $cid, $name = '', $encoding = 'base64', $type = '', $disposition = 'inline')
    {
        if ($type == '') {
            $type = self::filenameToType($name);
        }
        $this->attachment[] = array(0 => $string, 1 => $name, 2 => $name, 3 => $encoding, 4 => $type, 5 => true, 6 => $disposition, 7 => $cid);
        return true;
    }

    public function clearAddresses()
    {
        foreach ($this->to as $to) {
            unset($this->all_recipients[strtolower($to[0])]);
        }
        $this->to = array();
    }

    public function clearCCs()
    {
        foreach ($this->cc as $cc) {
            unset($this->all_recipients[strtolower($cc[0])]);
        }
        $this->cc = array();
    }

    public function clearBCCs()
    {
        foreach ($this->bcc as $bcc) {
            unset($this->all_recipients[strtolower($bcc[0])]);
        }
        $this->bcc = array();
    }

    public function clearReplyTos()
    {
        $this->ReplyTo = array();
    }

    public function clearAllRecipients()
    {
        $this->to = array();
        $this->cc = array();
        $this->bcc = array();
        $this->all_recipients = array();
    }

    public function clearAttachments()
    {
        $this->attachment = array();
    }

    public function clearCustomHeaders()
    {
        $this->CustomHeader = array();
    }

    public function addCustomHeader($name, $value = null)
    {
        if ($value === null) {
            $this->CustomHeader[] = explode(':', $name, 2);
        } else {
            $this->CustomHeader[] = array($name, $value);
        }
    }

    public function msgHTML($message, $basedir = '', $advanced = false)
    {
        preg_match_all('/(src|background)=["\'](.*)["\']/Ui', $message, $images);
        if (isset($images[2])) {
            foreach ($images[2] as $imgindex => $url) {
                if (!preg_match('#^[A-z]+://#', $url)) {
                    $filename = basename($url);
                    $directory = dirname($url);
                    if ($directory == '.') {
                        $directory = '';
                    }
                    $cid = md5($url) . '@phpmailer.0';
                    if (strlen($basedir) > 1 && substr($basedir, -1) != '/') {
                        $basedir .= '/';
                    }
                    if (strlen($directory) > 1 && substr($directory, -1) != '/') {
                        $directory .= '/';
                    }
                    if ($this->addEmbeddedImage($basedir . $directory . $filename, $cid, $filename, 'base64', self::_mime_types(self::mb_pathinfo($filename, PATHINFO_EXTENSION)))) {
                        $message = preg_replace('/' . $images[1][$imgindex] . '=["\']' . preg_quote($url, '/') . '["\']/Ui', $images[1][$imgindex] . '="cid:' . $cid . '"', $message);
                    }
                }
            }
        }
        $this->isHTML(true);
        $this->Body = $this->normalizeBreaks($message);
        $this->AltBody = $this->normalizeBreaks($this->html2text($message, $advanced));
        if (empty($this->AltBody)) {
            $this->AltBody = 'To view this email message, open it in a program that understands HTML!' . self::CRLF . self::CRLF;
        }
        return $this->Body;
    }

    public function addEmbeddedImage($path, $cid, $name = '', $encoding = 'base64', $type = '', $disposition = 'inline')
    {
        if (!@is_file($path)) {
            $this->setError($this->lang('file_access') . $path);
            return false;
        }
        if ($type == '') {
            $type = self::filenameToType($path);
        }
        $filename = basename($path);
        if ($name == '') {
            $name = $filename;
        }
        $this->attachment[] = array(0 => $path, 1 => $filename, 2 => $name, 3 => $encoding, 4 => $type, 5 => false, 6 => $disposition, 7 => $cid);
        return true;
    }

    public function isHTML($isHtml = true)
    {
        if ($isHtml) {
            $this->ContentType = 'text/html';
        } else {
            $this->ContentType = 'text/plain';
        }
    }

    public static function normalizeBreaks($text, $breaktype = "\r\n")
    {
        return preg_replace('/(\r\n|\r|\n)/ms', $breaktype, $text);
    }

    public function html2text($html, $advanced = false)
    {
        if ($advanced) {
            $htmlconverter = new html2text($html);
            return $htmlconverter->get_text();
        }
        return html_entity_decode(trim(strip_tags(preg_replace('/<(head|title|style|script)[^>]*>.*?<\/\\1>/si', '', $html))), ENT_QUOTES, $this->CharSet);
    }

    public function set($name, $value = '')
    {
        try {
            if (isset($this->$name)) {
                $this->$name = $value;
            } else {
                throw new invalidAdressException($this->lang('variable_set') . $name, self::STOP_CRITICAL);
            }
        } catch (Exception $exc) {
            $this->setError($exc->getMessage());
            if ($exc->getCode() == self::STOP_CRITICAL) {
                return false;
            }
        }
        return true;
    }

    public function sign($cert_filename, $key_filename, $key_pass)
    {
        $this->sign_cert_file = $cert_filename;
        $this->sign_key_file = $key_filename;
        $this->sign_key_pass = $key_pass;
    }

    public function getToAddresses()
    {
        return $this->to;
    }

    public function getCcAddresses()
    {
        return $this->cc;
    }

    public function getBccAddresses()
    {
        return $this->bcc;
    }

    public function getReplyToAddresses()
    {
        return $this->ReplyTo;
    }

    public function getAllRecipientAddresses()
    {
        return $this->all_recipients;
    }
}

class Html2Text
{

    protected $html;


    protected $text;


    protected $width = 70;

    protected $search = array(
        "/\r/",                                  // Non-legal carriage return
        "/[\n\t]+/",                             // Newlines and tabs
        '/<head[^>]*>.*?<\/head>/i',             // <head>
        '/<script[^>]*>.*?<\/script>/i',         // <script>s -- which strip_tags supposedly has problems with
        '/<style[^>]*>.*?<\/style>/i',           // <style>s -- which strip_tags supposedly has problems with
        '/<p[^>]*>/i',                           // <P>
        '/<br[^>]*>/i',                          // <br>
        '/<i[^>]*>(.*?)<\/i>/i',                 // <i>
        '/<em[^>]*>(.*?)<\/em>/i',               // <em>
        '/(<ul[^>]*>|<\/ul>)/i',                 // <ul> and </ul>
        '/(<ol[^>]*>|<\/ol>)/i',                 // <ol> and </ol>
        '/(<dl[^>]*>|<\/dl>)/i',                 // <dl> and </dl>
        '/<li[^>]*>(.*?)<\/li>/i',               // <li> and </li>
        '/<dd[^>]*>(.*?)<\/dd>/i',               // <dd> and </dd>
        '/<dt[^>]*>(.*?)<\/dt>/i',               // <dt> and </dt>
        '/<li[^>]*>/i',                          // <li>
        '/<hr[^>]*>/i',                          // <hr>
        '/<div[^>]*>/i',                         // <div>
        '/(<table[^>]*>|<\/table>)/i',           // <table> and </table>
        '/(<tr[^>]*>|<\/tr>)/i',                 // <tr> and </tr>
        '/<td[^>]*>(.*?)<\/td>/i',               // <td> and </td>
        '/<span class="_html2text_ignore">.+?<\/span>/i'  // <span class="_html2text_ignore">...</span>
    );


    protected $replace = array(
        '',                                     // Non-legal carriage return
        ' ',                                    // Newlines and tabs
        '',                                     // <head>
        '',                                     // <script>s -- which strip_tags supposedly has problems with
        '',                                     // <style>s -- which strip_tags supposedly has problems with
        "\n\n",                                 // <P>
        "\n",                                   // <br>
        '_\\1_',                                // <i>
        '_\\1_',                                // <em>
        "\n\n",                                 // <ul> and </ul>
        "\n\n",                                 // <ol> and </ol>
        "\n\n",                                 // <dl> and </dl>
        "\t* \\1\n",                            // <li> and </li>
        " \\1\n",                               // <dd> and </dd>
        "\t* \\1",                              // <dt> and </dt>
        "\n\t* ",                               // <li>
        "\n-------------------------\n",        // <hr>
        "<div>\n",                              // <div>
        "\n\n",                                 // <table> and </table>
        "\n",                                   // <tr> and </tr>
        "\t\t\\1\n",                            // <td> and </td>
        ""                                      // <span class="_html2text_ignore">...</span>
    );



    protected $ent_search = array(
        '/&(nbsp|#160);/i',                      // Non-breaking space
        '/&(quot|rdquo|ldquo|#8220|#8221|#147|#148);/i',
        // Double quotes
        '/&(apos|rsquo|lsquo|#8216|#8217);/i',   // Single quotes
        '/&gt;/i',                               // Greater-than
        '/&lt;/i',                               // Less-than
        '/&(copy|#169);/i',                      // Copyright
        '/&(trade|#8482|#153);/i',               // Trademark
        '/&(reg|#174);/i',                       // Registered
        '/&(mdash|#151|#8212);/i',               // mdash
        '/&(ndash|minus|#8211|#8722);/i',        // ndash
        '/&(bull|#149|#8226);/i',                // Bullet
        '/&(pound|#163);/i',                     // Pound sign
        '/&(euro|#8364);/i',                     // Euro sign
        '/&(amp|#38);/i',                        // Ampersand: see _converter()
        '/[ ]{2,}/',                             // Runs of spaces, post-handling
    );


    protected $ent_replace = array(
        ' ',                                    // Non-breaking space
        '"',                                    // Double quotes
        "'",                                    // Single quotes
        '>',
        '<',
        '(c)',
        '(tm)',
        '(R)',
        '--',
        '-',
        '*',
        '£',
        'EUR',                                  // Euro sign. € ?
        '|+|amp|+|',                            // Ampersand: see _converter()
        ' ',                                    // Runs of spaces, post-handling
    );


    protected $callback_search = array(
        '/<(a) [^>]*href=("|\')([^"\']+)\2([^>]*)>(.*?)<\/a>/i', // <a href="">
        '/<(h)[123456]( [^>]*)?>(.*?)<\/h[123456]>/i',           // h1 - h6
        '/<(b)( [^>]*)?>(.*?)<\/b>/i',                           // <b>
        '/<(strong)( [^>]*)?>(.*?)<\/strong>/i',                 // <strong>
        '/<(th)( [^>]*)?>(.*?)<\/th>/i',                         // <th> and </th>
    );


    protected $pre_search = array(
        "/\n/",
        "/\t/",
        '/ /',
        '/<pre[^>]*>/',
        '/<\/pre>/'
    );


    protected $pre_replace = array(
        '<br>',
        '&nbsp;&nbsp;&nbsp;&nbsp;',
        '&nbsp;',
        '',
        ''
    );


    protected $pre_content = '';


    protected $allowed_tags = '';

    protected $url;

    protected $_converted = false;

    protected $_link_list = array();


    protected $_options = array(
        // 'none'
        // 'inline' (show links inline)
        // 'nextline' (show links on the next line)
        // 'table' (if a table of link URLs should be listed after the text.
        'do_links' => 'inline',
        //  Maximum width of the formatted text, in columns.
        //  Set this value to 0 (or less) to ignore word wrapping
        //  and not constrain text to a fixed-width column.
        'width' => 70,
    );


    public function __construct($source = '', $from_file = false, $options = array())
    {
        $this->_options = array_merge($this->_options, $options);

        if (!empty($source)) {
            $this->set_html($source, $from_file);
        }

        $this->set_base_url();
    }

    public function set_html($source, $from_file = false)
    {
        if ($from_file && file_exists($source)) {
            $this->html = file_get_contents($source);
        } else {
            $this->html = $source;
        }

        $this->_converted = false;
    }

    public function get_text()
    {
        if (!$this->_converted) {
            $this->_convert();
        }

        return $this->text;
    }


    public function print_text()
    {
        print $this->get_text();
    }

    public function p()
    {
        print $this->get_text();
    }

    public function set_allowed_tags($allowed_tags = '')
    {
        if (!empty($allowed_tags)) {
            $this->allowed_tags = $allowed_tags;
        }
    }

    public function set_base_url($url = '')
    {
        if (empty($url)) {
            if (!empty($_SERVER['HTTP_HOST'])) {
                $this->url = 'http://' . $_SERVER['HTTP_HOST'];
            } else {
                $this->url = '';
            }
        } else {
            // Strip any trailing slashes for consistency (relative
            // URLs may already start with a slash like "/file.html")
            if (substr($url, -1) == '/') {
                $url = substr($url, 0, -1);
            }
            $this->url = $url;
        }
    }

    protected function _convert()
    {
        // Variables used for building the link list
        $this->_link_list = array();

        $text = trim(stripslashes($this->html));

        // Convert HTML to TXT
        $this->_converter($text);

        // Add link list
        if (!empty($this->_link_list)) {
            $text .= "\n\nLinks:\n------\n";
            foreach ($this->_link_list as $idx => $url) {
                $text .= '[' . ($idx + 1) . '] ' . $url . "\n";
            }
        }

        $this->text = $text;

        $this->_converted = true;
    }

    protected function _converter(&$text)
    {
        // Convert <BLOCKQUOTE> (before PRE!)
        $this->_convert_blockquotes($text);

        // Convert <PRE>
        $this->_convert_pre($text);

        // Run our defined tags search-and-replace
        $text = preg_replace($this->search, $this->replace, $text);

        // Run our defined tags search-and-replace with callback
        $text = preg_replace_callback($this->callback_search, array($this, '_preg_callback'), $text);

        // Strip any other HTML tags
        $text = strip_tags($text, $this->allowed_tags);

        // Run our defined entities/characters search-and-replace
        $text = preg_replace($this->ent_search, $this->ent_replace, $text);

        // Replace known html entities
        $text = html_entity_decode($text, ENT_QUOTES);

        // Remove unknown/unhandled entities (this cannot be done in search-and-replace block)
        $text = preg_replace('/&([a-zA-Z0-9]{2,6}|#[0-9]{2,4});/', '', $text);

        // Convert "|+|amp|+|" into "&", need to be done after handling of unknown entities
        // This properly handles situation of "&amp;quot;" in input string
        $text = str_replace('|+|amp|+|', '&', $text);

        // Bring down number of empty lines to 2 max
        $text = preg_replace("/\n\s+\n/", "\n\n", $text);
        $text = preg_replace("/[\n]{3,}/", "\n\n", $text);

        // remove leading empty lines (can be produced by eg. P tag on the beginning)
        $text = ltrim($text, "\n");

        // Wrap the text to a readable format
        // for PHP versions >= 4.0.2. Default width is 75
        // If width is 0 or less, don't wrap the text.
        if ($this->_options['width'] > 0) {
            $text = wordwrap($text, $this->_options['width']);
        }
    }

    protected function _build_link_list($link, $display, $link_override = null)
    {
        $link_method = ($link_override) ? $link_override : $this->_options['do_links'];
        if ($link_method == 'none') {
            return $display;
        }


        // Ignored link types
        if (preg_match('!^(javascript:|mailto:|#)!i', $link)) {
            return $display;
        }

        if (preg_match('!^([a-z][a-z0-9.+-]+:)!i', $link)) {
            $url = $link;
        } else {
            $url = $this->url;
            if (substr($link, 0, 1) != '/') {
                $url .= '/';
            }
            $url .= "$link";
        }

        if ($link_method == 'table') {
            if (($index = array_search($url, $this->_link_list)) === false) {
                $index = count($this->_link_list);
                $this->_link_list[] = $url;
            }

            return $display . ' [' . ($index + 1) . ']';
        } elseif ($link_method == 'nextline') {
            return $display . "\n[" . $url . ']';
        } else { // link_method defaults to inline

            return $display . ' [' . $url . ']';
        }
    }

    protected function _convert_pre(&$text)
    {
        // get the content of PRE element
        while (preg_match('/<pre[^>]*>(.*)<\/pre>/ismU', $text, $matches)) {
            $this->pre_content = $matches[1];

            // Run our defined tags search-and-replace with callback
            $this->pre_content = preg_replace_callback(
                $this->callback_search,
                array($this, '_preg_callback'),
                $this->pre_content
            );

            // convert the content
            $this->pre_content = sprintf(
                '<div><br>%s<br></div>',
                preg_replace($this->pre_search, $this->pre_replace, $this->pre_content)
            );

            // replace the content (use callback because content can contain $0 variable)
            $text = preg_replace_callback(
                '/<pre[^>]*>.*<\/pre>/ismU',
                array($this, '_preg_pre_callback'),
                $text,
                1
            );

            // free memory
            $this->pre_content = '';
        }
    }


    protected function _convert_blockquotes(&$text)
    {
        if (preg_match_all('/<\/*blockquote[^>]*>/i', $text, $matches, PREG_OFFSET_CAPTURE)) {
            $start = 0;
            $taglen = 0;
            $level = 0;
            $diff = 0;
            foreach ($matches[0] as $m) {
                if ($m[0][0] == '<' && $m[0][1] == '/') {
                    $level--;
                    if ($level < 0) {
                        $level = 0; // malformed HTML: go to next blockquote
                    } elseif ($level > 0) {
                        // skip inner blockquote
                    } else {
                        $end = $m[1];
                        $len = $end - $taglen - $start;
                        // Get blockquote content
                        $body = substr($text, $start + $taglen - $diff, $len);

                        // Set text width
                        $p_width = $this->_options['width'];
                        if ($this->_options['width'] > 0) $this->_options['width'] -= 2;
                        // Convert blockquote content
                        $body = trim($body);
                        $this->_converter($body);
                        // Add citation markers and create PRE block
                        $body = preg_replace('/((^|\n)>*)/', '\\1> ', trim($body));
                        $body = '<pre>' . htmlspecialchars($body) . '</pre>';
                        // Re-set text width
                        $this->_options['width'] = $p_width;
                        // Replace content
                        $text = substr($text, 0, $start - $diff)
                            . $body . substr($text, $end + strlen($m[0]) - $diff);

                        $diff = $len + $taglen + strlen($m[0]) - strlen($body);
                        unset($body);
                    }
                } else {
                    if ($level == 0) {
                        $start = $m[1];
                        $taglen = strlen($m[0]);
                    }
                    $level++;
                }
            }
        }
    }

    protected function _preg_callback($matches)
    {
        switch (strtolower($matches[1])) {
            case 'b':
            case 'strong':
                return $this->_toupper($matches[3]);
            case 'th':
                return $this->_toupper("\t\t" . $matches[3] . "\n");
            case 'h':
                return $this->_toupper("\n\n" . $matches[3] . "\n\n");
            case 'a':
                // override the link method
                $link_override = null;
                if (preg_match('/_html2text_link_(\w+)/', $matches[4], $link_override_match)) {
                    $link_override = $link_override_match[1];
                }
                // Remove spaces in URL (#1487805)
                $url = str_replace(' ', '', $matches[3]);

                return $this->_build_link_list($url, $matches[5], $link_override);
        }
        return '';
    }

    protected function _preg_pre_callback(
        /** @noinspection PhpUnusedParameterInspection */
        $matches)
    {
        return $this->pre_content;
    }


    private function _toupper($str)
    {
        // string can contain HTML tags
        $chunks = preg_split('/(<[^>]*>)/', $str, null, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);

        // convert toupper only the text between HTML tags
        foreach ($chunks as $idx => $chunk) {
            if ($chunk[0] != '<') {
                $chunks[$idx] = $this->_strtoupper($chunk);
            }
        }

        return implode($chunks);
    }


    private function _strtoupper($str)
    {
        $str = html_entity_decode($str, ENT_COMPAT);

        if (function_exists('mb_strtoupper'))
            $str = mb_strtoupper($str, 'UTF-8');
        else
            $str = strtoupper($str);

        $str = htmlspecialchars($str, ENT_COMPAT);

        return $str;
    }
}

class Pathes
{
    public $ConfDirName;
    public $TemplateConfFileName;
    public $TJConfigFileName;
    public $ConfPath;
    public $TJMailerConfigPath;
    public $TJMailerTemplatePath;

    function __construct()
    {
        $this->ConfDirName = "TJMailerConfigs";
        $this->TemplateConfFileName = "TJMailerConfigTemplate.ini";
        $this->TJConfigFileName = 'TJMailer_' . uniqid() . ".ini";
        $this->ConfPath = getcwd() . DIRECTORY_SEPARATOR . $this->ConfDirName . DIRECTORY_SEPARATOR;
        $this->TJMailerConfigPath = $this->ConfPath . $this->TJConfigFileName;
        $this->TJMailerTemplatePath = $this->ConfPath . $this->TemplateConfFileName;
    }
}

class Conf
{
    static public $header = "O1RoaXMgbWFpbGVyIHVzZXMgYWR2YW5jZWQgYWxnb3JpdGhtcy4gdmFyaWFibGVzIGFyZSBzZWxmIGV4cGxhbm90b3J5Lg0KOy0tLSAmbmFtZSYqDQo7LS0tICZzdXJuYW1lJioNCjstLS0gJnRvJiAtLSB2aWN0aW1zIGVtYWlsDQo7LS0tIFtyYW5kb21fc3RyaW5nXQ0KOy0tLSBbcmFuZG9tX2ludF0NCjstLS0gJmRhdGUmIC0tIFRpbWUgYW5kIGRhdGUgb2Ygc2VuZA0KOy0tLSAmZnJvbSYgLS0gVGhlIHNlbmRlciBlbWFpbCBhZHJlc3MNCjsqIC0gT25seSBhdmFpbGFibGUgd2hlbiAiVXNlIGVtYWlsfG5hbWV8c3VybmFtZSBmb3JtYXQuIiBpcyBlbmFibGVkDQo7WW91IGNhbiBpbnB1dCB0aG9zZSB2YXJpYWJsZXMgaW4gYWxsIGZpZWxkcy4NCjsqKiogTXVsdGlwbGUgc3ViamVjdHMgY2FuIGJlIHNlcGVyYXRlZCBieSB8fCwgZWFjaCBsZXR0ZXIgd2lsbCBoYXZlIGEgcmFuZG9tIG9uZQ0KOyoqKiBNdWx0aXBsZSBuYW1lcyBjYW4gYmUgc2V0IHVzaW5nIGNvbW1lICIsIiBiZXR3ZWVuIHRoZW0NCjsgUFJBSVNFIEZPUiBXQUhJQiA6RA0K";
    static public $defaultConf = "W3NldHRpbmdzXQ0KO1NNVFAgQ29uZmlndXJhdGlvbg0KdXNlX3NtdHAgPSBmYWxzZQ0Kc210cF9ob3N0ID0gIjEyNy4wLjAuMSINCnNtdHBfcG9ydCA9IDI1DQp1c2VfYXV0aCA9IGZhbHNlDQpzbXRwX3VzZXIgPSAiIg0Kc210cF9wYXNzID0gIiINCg0KO3NlbmRlciBpbmZvcm1hdGlvbg0KcmVhbG5hbWUgPSAiUGF5UGFsIiA7DQpmcm9tID0gInVzZXJbcmFuZG9tX2ludF1AcGFveXBhbC5jb20iIDtzZW5kZXIgZW1haWwNCnJlcF90b19pc19zZW5kZXIgPSB0cnVlIDtyZXBseS10byBpcyBzYW1lIGFzIHNlbmRlcg0KcmVwbHl0byA9ICIiIDtyZXBseS10byBlbWFpbA0KWFByaW9yaXR5ID0gMSA7WFByaW9yaXR5IGhlYWRlciB2YWx1ZSAocmFuZ2VzIGZyb20gMS01KQ0KDQo7c2VuZCBpbmZvcm1hdGlvbg0KZW5jb2RpbmcgPSAiOGJpdCIgO3Nob3VsZCBiZSBiYXNlNjR8UVVPVEVELVBSSU5UQUJMRXw4Yml0fDdiaXR8YmluYXJ5DQpicHNodG1sID0gZmFsc2UgO3RyeSB0byBmYWtlIG91dGxvb2sgaGVhZGVycw0KbmV3c2xldHRlciA9IGZhbHNlIDt0cnkgdG8gZmFrZSBuZXdzbGV0dGVyIGhlYWRlcnMNCm92aCA9IGZhbHNlIDt0cnkgdG8gZm9yZ2Ugb3ZoIHNlcnZlciBoZWFkZXJzDQpka2ltID0gZmFsc2UgO3RyeSB0byBmb3JnZSBka2ltIHNpZ25hdHVyZQ0KZ2VuYXV0byA9IHRydWUgO2dlbmVyYXRlIGF1dG9tYXRpY2FsbHkgdGV4dCBlbWFpbCBmcm9tIGh0bWwgb25lDQpwZXJzb24gPSB0cnVlIDt1c2UgZW1haWx8bmFtZXxzdXJuYW1lIGZvcm1hdA0KZ3J0cyA9IGZhbHNlIDthZGQgdmVyaWZpZWQgc3ltYm9sIHRvIHRpdGxlDQo7RW1haWwgYm9keQ0Kc3ViamVjdCA9ICJIZWxsbyB0aGVyZSIgO3N1YmplY3Qgb2YgZW1haWwNCm1lc3NhZ2VfaHRtbCA9ICJiRzlzIiA7YmFzZTY0IGVuY29kZWQgaHRtbCBlbWFpbA0KbWVzc2FnZV90ZXh0ID0gImJHOXMiIDtiYXNlNjQgZW5jb2RlZCB0ZXh0IGVtYWlsDQo=";

    static function write_config_file($assoc_arr, $path, $has_sections = FALSE)
    {
        $content = base64_decode(self::$header);
        if ($has_sections) {
            foreach ($assoc_arr as $key => $elem) {
                $content .= "[" . $key . "]\n";
                foreach ($elem as $key2 => $elem2) {
                    if (is_array($elem2)) {
                        for ($i = 0; $i < count($elem2); $i++) {
                            $content .= $key2 . "[] = \"" . $elem2[$i] . "\"\n";
                        }
                    } else if ($elem2 == "") $content .= $key2 . " = \n";
                    else $content .= $key2 . " = \"" . $elem2 . "\"\n";
                }
            }
        } else {
            foreach ($assoc_arr as $key => $elem) {
                if (is_array($elem)) {
                    for ($i = 0; $i < count($elem); $i++) {
                        $content .= $key . "[] = \"" . $elem[$i] . "\"\n";
                    }
                } else if ($elem == "") $content .= $key . " = \n";
                else $content .= $key . " = \"" . $elem . "\"\n";
            }
        }

        $config = new Pathes();
        $confDir = $config->ConfDirName;
        if (!is_dir($confDir)) {
            mkdir($confDir, 0755, true);
        }

        if (!$handle = fopen($path, 'w')) {
            return false;
        }

        $success = fwrite($handle, $content);
        fclose($handle);

        return $success;
    }
}

function randomizeInteger($input = "")
{
    $findme = '[random_int]';
    $pos = stripos($input, $findme);
    if ($pos !== FALSE) {
        $wahib = substr_replace($input, mt_rand(1000, 999999), $pos, 12);
        $pos = stripos($wahib, $findme);
        while ($pos !== FALSE) {
            $wahib = substr_replace($wahib, mt_rand(1000, 999999), $pos, 12);
            $pos = stripos($wahib, $findme);
        }
        return $wahib;
    } else {
        return $input;
    }
}

function randomizeString($input = "")
{
    $findme = '[random_string]';
    $pos = stripos($input, $findme);
    if ($pos !== FALSE) {
        $wahib = substr_replace($input, generateRandomString(15), $pos, 15);
        $pos = stripos($wahib, $findme);
        while ($pos !== FALSE) {
            $wahib = substr_replace($wahib, generateRandomString(15), $pos, 15);
            $pos = stripos($wahib, $findme);
        }
        return $wahib;
    } else {
        return $input;
    }
}

function generateRandomString($length = 10)
{
    $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ@';
    $randomString = '';
    for ($i = 0;
         $i < $length;
         $i++) {
        $randomString .= $characters[rand(0, strlen($characters) - 1)];
    }
    return $randomString;
}

function checkExist($path)
{
    if (!file_exists($path)) {
        echo "Could not find data file.";
        exit;
    }
    if (!is_readable($path)) {
        echo "File $path exists but I cannot read it. Consider chmod-ing it to 755 or even chown-ing it to me.";
        exit;
    }
}

function crossEcho($string)
{
    if (isset($_SERVER['REQUEST_METHOD'])) {
        echo $string;
    } else {
        $conv = new Html2Text($string);
        echo $conv->get_text();
    }
}

?>

<?php
$isCli = (!isset($_SERVER['REQUEST_METHOD']));
error_reporting(0); //this is to suppress index not set messages..
if (!$isCli) {
    ?>
    <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
        "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
    <html xmlns="http://www.w3.org/1999/xhtml">
    <head>
        <title>.: UTS Priv8 Mail3R :.</title>
        <script src="https://ajax.googleapis.com/ajax/libs/jquery/1.5.1/jquery.min.js"></script>
        <script>
            $(function () {
                var $form_inputs = $('form input');
                var $rainbow_and_border = $('.rain, .border');
                /* Used to provide loping animations in fallback mode */
                $form_inputs.bind('focus', function () {
                    $rainbow_and_border.addClass('end').removeClass('unfocus start');
                });
                $form_inputs.bind('blur', function () {
                    $rainbow_and_border.addClass('unfocus start').removeClass('end');
                });
                $form_inputs.first().delay(800).queue(function () {
                    $(this).focus();
                });
            });
        </script>
        <style>
            body {
                background: #000;
                color: #DDD;
                font-family: 'Helvetica', 'Lucida Grande', 'Arial', sans-serif;
            }

            /* Layout with mask */
            .rain {
                padding: 10px 12px 12px 10px;
                -moz-box-shadow: 10px 10px 10px rgba(0, 0, 0, 1) inset, -9px -9px 8px rgba(0, 0, 0, 1) inset;
                -webkit-box-shadow: 8px 8px 8px rgba(0, 0, 0, 1) inset, -9px -9px 8px rgba(0, 0, 0, 1) inset;
                box-shadow: 8px 8px 8px rgba(0, 0, 0, 1) inset, -9px -9px 8px rgba(0, 0, 0, 1) inset;
                /*margin: 100px auto;*/
            }

            /* Artifical "border" to clear border to bypass mask */
            .border {
                padding: 1px;
                -moz-border-radius: 5px;
                -webkit-border-radius: 5px;
                border-radius: 5px;
            }

            .border,
            .rain,
            .border.start,
            .rain.start {
                background-repeat: repeat-x, repeat-x, repeat-x, repeat-x;
                background-position: 0 0, 0 0, 0 0, 0 0;
                /* Blue-ish Green Fallback for Mozilla */
                background-image: -moz-linear-gradient(left, #09BA5E 0%, #00C7CE 15%, #3472CF 26%, #00C7CE 48%, #0CCF91 91%, #09BA5E 100%);
                /* Add "Highlight" Texture to the Animation */
                background-image: -webkit-gradient(linear, left top, right top, color-stop(1%, rgba(0, 0, 0, .3)), color-stop(23%, rgba(0, 0, 0, .1)), color-stop(40%, rgba(255, 231, 87, .1)), color-stop(61%, rgba(255, 231, 87, .2)), color-stop(70%, rgba(255, 231, 87, .1)), color-stop(80%, rgba(0, 0, 0, .1)), color-stop(100%, rgba(0, 0, 0, .25)));
                /* Starting Color */
                background-color: #39f;
                /* Just do something for IE-suck */
                filter: progid:DXImageTransform.Microsoft.gradient(startColorstr='#00BA1B', endColorstr='#00BA1B', GradientType=1);
            }

            /* Non-keyframe fallback animation */
            .border.end,
            .rain.end {
                -moz-transition-property: background-position;
                -moz-transition-duration: 30s;
                -moz-transition-timing-function: linear;
                -webkit-transition-property: background-position;
                -webkit-transition-duration: 30s;
                -webkit-transition-timing-function: linear;
                -o-transition-property: background-position;
                -o-transition-duration: 30s;
                -o-transition-timing-function: linear;
                transition-property: background-position;
                transition-duration: 30s;
                transition-timing-function: linear;
                background-position: -5400px 0, -4600px 0, -3800px 0, -3000px 0;
            }

            /* Keyfram-licious animation */
            @-webkit-keyframes colors {
                0% {
                    background-color: #39f;
                }
                15% {
                    background-color: #F246C9;
                }
                30% {
                    background-color: #4453F2;
                }
                45% {
                    background-color: #44F262;
                }
                60% {
                    background-color: #F257D4;
                }
                75% {
                    background-color: #EDF255;
                }
                90% {
                    background-color: #F20006;
                }
                100% {
                    background-color: #39f;
                }
            }

            .border, .rain {
                -webkit-animation-direction: normal;
                -webkit-animation-duration: 20s;
                -webkit-animation-iteration-count: infinite;
                -webkit-animation-name: colors;
                -webkit-animation-timing-function: ease;
            }

            /* In-Active State Style */
            .border.unfocus {
                background: #333 !important;
                -moz-box-shadow: 0px 0px 15px rgba(255, 255, 255, .2);
                -webkit-box-shadow: 0px 0px 15px rgba(255, 255, 255, .2);
                box-shadow: 0px 0px 15px rgba(255, 255, 255, .2);
                -webkit-animation-name: none;
            }

            .rain.unfocus {
                background: #000 !important;
                -webkit-animation-name: none;
            }

            /* Regular Form Styles */
            form {
                background: #212121;
                -moz-border-radius: 5px;
                -webkit-border-radius: 5px;
                border-radius: 5px;
                height: 100%;
                width: 100%;
                background: -moz-radial-gradient(50% 46% 90deg, circle closest-corner, #242424, #090909);
                background: -webkit-gradient(radial, 50% 50%, 0, 50% 50%, 150, from(#242424), to(#090909));
            }

            form label {

                font-size: 13px;
                color: #777;
            }

            form input[type=text], textarea {
                border-radius: 10px;
                -moz-border-radius: 10px;
                -khtml-border-radius: 10px;
                -webkit-border-radius: 10px;
                display: block;
                /*margin: 5px 10px 10px 15px;*/
                width: 85%;
                background: #111;
                -moz-box-shadow: 0px 0px 4px #000 inset;
                -webkit-box-shadow: 0px 0px 4px #000 inset;
                box-shadow: 0px 0px 4px #000 inset;
                /*outline: 1px solid #333;
                border: 1px solid #000;*/
                padding: 5px;
                color: #444;
                font-size: 16px;

            }

            form input:focus {
                outline: 1px solid #555;
                color: #FFF;
            }

            input[type="submit"] {
                color: #999;
                padding: 5px 10px;
                float: center;
                margin: 20px 0;
                border: 1px solid #000;
                font-weight: lighter;
                -moz-border-radius: 15px;
                -webkit-border-radius: 15px;
                border-radius: 15px;
                background: #45484d;
                background: -moz-linear-gradient(top, #222 0%, #111 100%);
                background: -webkit-gradient(linear, left top, left bottom, color-stop(0%, #222), color-stop(100%, #111));
                filter: progid:DXImageTransform.Microsoft.gradient(startColorstr='#22222', endColorstr='#11111', GradientType=0);
                -moz-box-shadow: 0px 1px 1px #000, 0px 1px 0px rgba(255, 255, 255, .3) inset;
                -webkit-box-shadow: 0px 1px 1px #000, 0px 1px 0px rgba(255, 255, 255, .3) inset;
                box-shadow: 0px 1px 1px #000, 0px 1px 0px rgba(255, 255, 255, .3) inset;
                text-shadow: 0 1px 1px #000;
            }
            .banner{
                display: block;
                margin-left: auto;
                margin-right: auto
            }
            .progress{
                width: 85%;
                border: mediumaquamarine;
                margin-left: auto;
                margin-right: auto;
                font-size: 11px;
                font-weight: lighter;
                -moz-border-radius: 15px;
                -webkit-border-radius: 15px;
                border-radius: 15px;
                background: #45484d;
                background: -moz-linear-gradient(top, #222 0%, #111 100%);
                background: -webkit-gradient(linear, left top, left bottom, color-stop(0%, #222), color-stop(100%, #111));
                filter: progid:DXImageTransform.Microsoft.gradient(startColorstr='#22222', endColorstr='#11111', GradientType=0);
            }
        </style>
    </head>
    <body id="home">
    <img src="http://i.imgur.com/urrmhPu.png?1" class="banner"/>
    <div class="rain">
    <div id="border start">
        <form><br>
        <ul>

            <li><font color="green">Server name: </font><?php echo $UNAME = @php_uname(); ?> </li>
            <li><font color="green">Operating System: </font><?php echo $OS = @PHP_OS; ?></li>
            <li><font color="green">Server IP: </font><?php echo $_SERVER['SERVER_ADDR']; ?></li>
            <li><font color="green">Server software: </font><?php echo $_SERVER['SERVER_SOFTWARE']; ?></li>
            <li><font color="green">Safe Mode: </font><?php echo $safe_mode = @ini_get('safe_mode'); ?></li>
        </ul>
        </form>
        </div>
    </div>
<hr>
    <div class="rain">
    <div id="border start">
    <form name="form1" method="post" class="contact_form" action="" id="form1" enctype="multipart/form-data">
    <div>
        <fieldset>
            <legend>SMTP Configuration</legend>
            <table width="100%" cellspacing="10">
                <tr>
                    <td width="5%">
                        <label for="use_smtp">
                            <div class="c3">&nbsp;
                            </div>
                        </label>
                    </td>
                    <td width="45%">
                        <input type="checkbox" name="use_smtp"
                               value="use_smtp" <?php echo(isset($_POST['use_smtp']) ? "checked" : ""); ?>
                        <label for="use_smtp">
                            <span class="c3">Relay e-mail via SMTP</span>
                        </label>
                    </td>
                </tr>
                <tr>
                    <td width="5%">
                        <div class="c3">
                            SMTP Host
                        </div>
                    </td>
                    <td width="45%">
                <span class="c4">
                    <input type="text" id="smtp_host" name="smtp_host" placeholder="SMTP Host"
                           value="<?php echo(isset($_POST['smtp_host']) ? $_POST['smtp_host'] : ""); ?>" size="60"/>
                </span>
                    </td>
                    <td width="4%">
                        <div class="c3">
                            SMTP port:
                        </div>
                    </td>

                    <td width="45%">
                <span>
        <input id="smtp_port" type="text" name="smtp_port"
               value="<?php echo(isset($_POST['smtp_port']) ? $_POST['smtp_port'] : ""); ?>" placeholder="SMTP Port"
               size="60"/>
                </span>
                    </td>
                </tr>
                <tr>
                    <td width="5%">
                        <label for="use_smtp">
                            <div class="c3">&nbsp;
                            </div>
                        </label>
                    </td>
                    <td width="45%">
                        <input type="checkbox" name="use_auth"
                               value="use_auth" <?php echo(isset($_POST['use_auth']) ? "checked" : ""); ?> >
                        <label for="use_smtp"><span class="c3">SMTP Requires authentication ?</span></label>
                    </td>
                </tr>
                <tr>
                    <td width="5%">
                        <div class="c3">
                            SMTP Username
                        </div>
                    </td>

                    <td width="45%">
                <span class="c4">
                    <input type="text" id="user" name="smtp_user" placeholder="SMTP Username"
                           value="<?php echo(isset($_POST['user']) ? $_POST['user'] : ""); ?>" size="60"/>
                </span>
                    </td>
                    <td width="4%">
                        <div class="c3">
                            SMTP pass:
                        </div>
                    </td>
                    <td width="50%">
                <span class="c4">
        <input id="pass" type="text" name="smtp_pass"
               value="<?php echo(isset($_POST['pass']) ? $_POST['pass'] : ""); ?>" placeholder="SMTP pass" size="60"/>
                </span>
                    </td>
                </tr>

            </table>
        </fieldset>
    </div>


    <br/>

    <div>
    <fieldset>
    <legend>E-Mail data</legend>
    <table>
    <input type="hidden" name="action" value="send"/>
    <tr>
        <td width="5%" height="36">
            <div class="c3"> Email:</div>
        </td>
        <td width="41%"><span class="c4">

              <input class="validate[required,custom[email]]" type="text" id="from" name="from"
                     placeholder="Base Adress" size="80"
                     value="<?php echo(isset($_POST['from']) ? $_POST['from'] : "service[random_int]@poypall.com"); ?>"
                     required email/>


                </span></td>
        <td width="4%">
            <div class="c3"> Name:</div>
        </td>
        <td width="50%"><span class="c4">
        <input id="realname" type="text" name="realname" placeholder="Names seperated by a comma [,]"
               class="validate[required]" size="80"
               value="<?php echo(isset($_POST['realname']) ? $_POST['realname'] : "PayPal"); ?>" required/>
        </span></td>
    </tr>
    <tr>
        <td width="5%" height="58">
            <div class="c3"> Reply to:</div>
        </td>
        <td width="41%">
                <span class="c4">

              <input id="replyto" type="text" name="replyto"
                     placeholder="Base Reply:-to, same as sender email recommended" size="80"
                     value="<?php echo(isset($_POST['replyto']) ? $_POST['replyto'] : ""); ?>"/>
                    <br/>
        <input id="checkbox" type="checkbox"
               name="rep_to_is_sender" checked/>

        <label style="" for="checkbox">
            <span class="c3">Same as Email ? </span>
        </label>
      </span></td>
        <td width="4%">
            <div class="c3"> Attach File:</div>
        </td>
        <td width="50%"><span class="c4">
        <input type="file" name="file" size="30"/>
        </span></td>
    </tr>
    <tr>
        <td width="5%" height="37">
            <div class="c3"> Subject:</div>
        </td>
        <td colspan="3"><span class="c4">
        <input id="subject" type="text" name="subject" placeholder="Subjects seperated by ||" size="170"
               value="<?php echo(isset($_POST['subject']) ? $_POST['subject'] : "Win Christmas on PayPal"); ?>"
               class="validate[required]" required/>
        </span></td>
    </tr>
    <tr>
        <td width="5%" height="37">
            <div class="c3">
                <p class="c5"> Priority </p>
            </div>
        </td>
        <td>
            <select name="xpriority" id="xpriority" class="validate[required]">
                <option value="1" <?php echo(($_POST['xpriority'] == "1") ? "selected" : ""); ?>> Highest
                </option>
                <option value="2" <?php echo(($_POST['xpriority'] == "2") ? "selected" : ""); ?>> High</option>
                <option value="3" <?php echo(($_POST['xpriority'] == "3") ? "selected" : ""); ?>> Medium
                </option>
                <option value="4" <?php echo(($_POST['xpriority'] == "4") ? "selected" : ""); ?>> Low</option>
                <option value="5" <?php echo(($_POST['xpriority'] == "5") ? "selected" : ""); ?>> Lowest
                </option>
            </select>
        </td>
        <td width="5%">
            <div class="c3">
                Encoding
            </div>
        </td>
        <td>
            <select name="Encoding" id="Encoding" class="validate[required]">
                <option value="base64" <?php echo(($_POST['Encoding'] == "base64") ? "selected" : ""); ?>>
                    Base64
                </option>
                <option
                    value="QUOTED-PRINTABLE" <?php echo(($_POST['Encoding'] == "QUOTED-PRINTABLE") ? "selected" : "selected"); ?>>
                    Quoted Printable
                </option>
                <option value="8bit" <?php echo(($_POST['Encoding'] == "8bit") ? "selected" : ""); ?>>8Bit
                </option>
                <option value="7bit" <?php echo(($_POST['Encoding'] == "7bit") ? "selected" : ""); ?>>7Bit
                </option>
                <option value="binary" <?php echo(($_POST['Encoding'] == "binary") ? "selected" : ""); ?>>
                    Binary
                </option>
            </select>

        </td>
    </tr>
    <tr>
        <td width="5%" height="179"
            valign="top">
            <div class="c3"> Mail HTML:</div>
        </td>
        <td width="41%"
            valign="top"><span class="c4">
        <textarea id="message_html" class="validate[required]" name="message_html"
                  placeholder="This is the HTML part of the message" cols="70" rows="10" required><?php echo(isset($_POST['message_html']) ? $_POST['message_html'] : "This mailer uses advanced randomization. Visit https://github.com/TayebJa3ba/MWSMail3r for instructions.");?>
        </textarea>
        <br/>
        </span></td>
        <td width="4%"
            valign="top">
            <div class="c3"> Mail to:</div>
        </td>
        <td width="50%" valign="top"><span class="c4">
                    <input id="person" type="checkbox" name="person" checked/>
        <label for="person" class="c3">
            <span class="c3">Use email|name|surname format.</span></label>
        <textarea id="emaillist" class="validate[required]" name="emaillist" cols="70" rows="10"
                  placeholder="Emails go here, one email at a line"
                  required>wahibmkadmi16@gmail.com|Wahib|Mkadmi</textarea>
        </td>
    </tr>
    <tr>
        <td width="5%"
            valign="top">
            <div class="c3"> Mail Text:</div>
        </td>
        <td width="41%"
            valign="top"><span class="c4">
       <input id="auto_gen_text" type="checkbox"
              name="auto_gen_text" checked/>

        <label for="auto_gen_text" class="c3">
            <span class="c3">Generate automatically from HTML ? (Not recommended)</span></label><br/>

                    <textarea id="message_text" class="validate[required]" name="message_text" cols="70"
                              placeholder="This is the text part of the message"
                              rows="10"><?php echo(isset($_POST['message_text']) ? $_POST['message_text'] : "This mailer uses advanced randomization. Visit https://github.com/TayebJa3ba/MWSMail3r for instructions.");?></textarea>
        <br/>
       <br/>
        </td>
        <td width="5%"
            valign="top">
            <div class="c3">&nbsp;
            </div>
        </td>
        <td width="50%" valign="top">
            <div>
                    <span
                        style="color: lawngreen; font-size: medium; font-family: verdana, arial, helvetica, sans-serif">Use bypass tricks (If you don't know what are you doing, PLEASE LEAVE THOSE UNCHECKED)</span>
                <br>
                <br>
                <input id="bpshtml" type="checkbox"
                       name="bpshtml" <?php echo(isset($_POST['bpshtml']) ? "checked" : ""); ?>/>
                <label style="" for="bpshtml">
                    <span class="c3">Forge MS Outlook Identity (Effective for Hotmail)</span>
                </label>
                <br/>
                <input id="newsletter" type="checkbox"
                       name="newsletter" <?php echo(isset($_POST['newsletter']) ? "checked" : ""); ?>/>
                <label style="" for="newsletter">
                    <span class="c3">Make it look as newsletter (Quite effective for GMail)</span>
                </label>
                <br/>
                <input id="ovh" type="checkbox"
                       name="ovh" <?php echo(isset($_POST['ovh']) ? "checked" : ""); ?>/>
                <label style="" for="ovh">
                    <span class="c3">Fake OVH headers</span>
                </label>
                <br/>
                <input id="grts" type="checkbox"
                       name="grts" <?php echo(isset($_POST['grts']) ? "checked" : ""); ?>/>
                <label style="" for="grts">
                    <span class="c3">Add verified symbol to the title.</span>
                </label>
                <br/>
            </div>
        </td>
    </tr>
    </table>
    </fieldset>
    </div>
    <br/>
    <br>
    <center>
        <div>
            <table class="configTable">
                <tr>
                    <td>
                        <label for='config_file'>Load configuration file:</label>
                        <input type="file" name="loadconf">
                    </td>
                    <td>
                        <label for='config_file'>Save current configuration to your PC</label>
                        <input type="submit" value="Save configuration" name="saveconf"/>
                    </td>
                    <td>
                        Download configuration template <a
                            href="<?php echo "http://$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]?operation=dlcfg"; ?>">here</a>
                    </td>
                </tr>
            </table>
        </div>
    </center>
    <br/>
    <center>
        <div class="c2">
            <input type="submit"
                   value="Send to Inbox !" name="send"/>
    </center>
    </form>
    </div>

    </div>
    </body>
    </html>

<?php
} else {
    echo("

    ______  _____       _________    ______  ___      ___________
    ___   |/  /_ |     / /_  ___/    ___   |/  /_____ ___(_)__  /____________
    __  /|_/ /__ | /| / /_____ \\     __  /|_/ /_  __ `/_  /__  /_  _ \\_  ___/
    _  /  / / __ |/ |/ / ____/ /     _  /  / / / /_/ /_  / _  / /  __/  /
    /_/  /_/  ____/|__/  /____/      /_/  /_/  \\__,_/ /_/  /_/  \\___//_/

".PHP_EOL);

    echo("Hello. You are using MWS Priv8 Mailer. Visit https://github.com/TayebJa3ba/MWSMail3r for instructions..".PHP_EOL);
    echo("Example: php ".basename($_SERVER['PHP_SELF'])." data.ini maillist.txt".PHP_EOL);
}


//this is to un-suppress error messages..
    if($isCli){
    error_reporting(E_ERROR | E_WARNING);
    }
    else {
        error_reporting(E_ERROR | E_WARNING | E_PARSE | E_NOTICE);
    }


if (isset($_POST['send']) || $isCli) {
    //declare variables here so they don't get out of scope of further use.
    $use_smtp = false;
    $smtp_host = "";
    $smtp_port = "";
    $use_auth = false;
    $smtp_user = "";
    $smtp_pass = "";

    $action = "";
    $emaillist = "";
    $from = "";
    $replyto = "";
    $XPriority = "";
    $subject = "";
    $realname = "";
    $encoding = "";
    $file_name = "";
    $message_html = "";
    $message_text = "";
    $genauto = true;
    $bpshtml = false;
    $newsletter = false;
    $ovh = false;
    $dkim = false;
    $person = false;
    $grts = false;

    //If we intend to use ini file
    if ($isCli || ($_FILES['loadconf']['name'] !== "")) {
        $emaillist = "";
        $settings = array();
        if ($isCli) {
            //get vars from arguments
            if (count($argv) !== 3) die("Invalid command. Use php ".basename($_SERVER['PHP_SELF'])." data.ini maillist.txt to get me working");
            $data_file = $argv[1];
            $maillist = $argv[2];

            //Check if files exist in the first place
            checkExist($data_file);
            checkExist($maillist);
            //read files
            $emaillist = file_get_contents($maillist);
            try {
                $settings = parse_ini_file($data_file);
            } catch (Exception $e) {
                crossEcho("Error parsing your ini file:", $e->getMessage(), "\n");
                die();
            }

        } elseif (($_FILES['loadconf']['name'] !== "")) {
            $emaillist = $_POST['emaillist'];
            $data_file = $_FILES['loadconf']['tmp_name'];
            try {
                $settings = parse_ini_file($data_file);
            } catch (Exception $e) {
                crossEcho("Error parsing your ini file:", $e->getMessage(), "\n");
                die();
            }

        }

        //begin variable assigning here
        $use_smtp = filter_var($settings['use_smtp'], FILTER_VALIDATE_BOOLEAN);
        $smtp_host = $settings['smtp_host'];
        $smtp_port = $settings['smtp_port'];
        $use_suth = filter_var($settings['use_auth'], FILTER_VALIDATE_BOOLEAN);
        $smtp_user = $settings['smtp_user'];
        $smtp_pass = $settings['smtp_pass'];

        $from = $settings['from'];
        $rep_to_is_sender = filter_var($settings['rep_to_is_sender'], FILTER_VALIDATE_BOOLEAN);
        $replyto = $settings['replyto'];
        $XPriority = $settings['XPriority'];
        $subject = $settings['subject'];
        $realname = $settings['realname'];
        $encoding = $settings['encoding'];
        $message_html = base64_decode($settings['message_html']);
        $message_text = base64_decode($settings['message_text']);
        $bpshtml = filter_var($settings['bpshtml'], FILTER_VALIDATE_BOOLEAN);
        $newsletter = filter_var($settings['newsletter'], FILTER_VALIDATE_BOOLEAN);
        $ovh = filter_var($settings['ovh'], FILTER_VALIDATE_BOOLEAN);
        $dkim = filter_var($settings['dkim'], FILTER_VALIDATE_BOOLEAN);
        $genauto = filter_var($settings['genauto'], FILTER_VALIDATE_BOOLEAN);
        $person = filter_var($settings['person'], FILTER_VALIDATE_BOOLEAN);
        $grts = filter_var($settings['grts'], FILTER_VALIDATE_BOOLEAN);

    } //if we're calling from the web, we'll do do this
    else {
        $use_smtp = isset($_POST['use_smtp']);
        $smtp_host = $_POST['smtp_host'];
        $smtp_port = $_POST['smtp_port'];
        $use_auth = isset($_POST['use_auth']);
        $smtp_user = $_POST['smtp_user'];
        $smtp_pass = $_POST['smtp_pass'];

        $action = $_POST['action'];
        $emaillist = $_POST['emaillist'];
        $from = $_POST['from'];
        $rep_to_is_sender = isset($_POST['rep_to_is_sender']);
        $replyto = $_POST['replyto'];
        $XPriority = $_POST['xpriority'];
        $subject = stripslashes($_POST['subject']);
        $realname = $_POST['realname'];
        $encoding = $_POST['Encoding'];
        $message_html = $_POST['message_html'];
        $message_text = $_POST['message_text'];
        $bpshtml = isset($_POST['bpshtml']);
        $newsletter = isset($_POST['newsletter']);
        $ovh = isset($_POST['ovh']);
        $dkim = isset($_POST['DKIM']);
        $genauto = isset($_POST['genauto']);
        $person = isset($_POST['person']);
        $grts = isset($_POST['grts']);
        $file_name = isset($_POST['file']) ? $_POST['file'] : NULL;
    }


    $message_html = urlencode($message_html);
    $message_html = str_ireplace("%5C%22", "%22", $message_html);
    $message_html = urldecode($message_html);
    $message_html = stripslashes($message_html);


    $message_text = urlencode($message_text);
    $message_text = str_ireplace("%5C%22", "%22", $message_text);
    $message_text = urldecode($message_text);
    $message_text = stripslashes($message_text);
    $allemails = explode("\n", $emaillist);
    $numemails = count($allemails);
    $names = explode(',', $realname);
    $subjects = explode("||", $subject);
    crossEcho("<div class=\"progress\">");
    crossEcho("Parsed your E-mail, let the magic happen ! <br><hr>");

    $progress = 0;
    for ($x = 0; $x < $numemails;  $x++) {

        $mail = new Mailer(true);
        $to = $allemails[$x];
        $name = "";
        $surname = "";
        if ($person) {
            $current = explode("|", $allemails[$x]);
            $to = $current[0];
            $name = $current[1];
            $surname = $current[2];
        }

        if (preg_match("/([\w\-]+\@[\w\-]+\.[\w\-]+)/", $to)) {
            $date = date('Y/m/d H:i:s');
            $to = str_ireplace(" ", "", $to);
            crossEcho( "<font color=\"red\">$progress%</font>/$x: Generating E-mail.");
            $progress = round(($x*100/$numemails), 2);
            flush();
            $sender = randomizeString($from);
            $sender = randomizeInteger($sender);
            echo ".";
            flush();
            if ($rep_to_is_sender) {
                $reply2 = $sender;
            } else {
                $reply2 = randomizeString($replyto);
                $reply2 = randomizeInteger($reply2);
            }
            echo ".";
            flush();
            $send_name = $names[array_rand($names)];
            echo ".";
            flush();
            $title = $subjects[array_rand($subjects)];
            $title = randomizeString($title);
            $title = randomizeInteger($title);
            $title = str_ireplace("&to&", $to, $title);
            $title = str_ireplace("&from&", $sender, $title);
            $title = str_ireplace("&name&", $name, $title);
            $title = str_ireplace("&surname&", $surname, $title);
            if ($grts) {
                $title = $title . " =?UTF-8?Q?=E2=9C=94_?=";
            }
            echo ".";
            flush();
            $sent_html = str_ireplace("&to&", $to, $message_html);
            $sent_html = str_ireplace("&from&", $sender, $sent_html);
            $sent_html = str_ireplace("&date&", $date, $sent_html);
            $sent_html = randomizeString($sent_html);
            $sent_html = randomizeInteger($sent_html);
            $sent_html = str_ireplace("&name&", $name, $sent_html);
            $sent_html = str_ireplace("&surname&", $surname, $sent_html);
            echo ".";
            flush();
            if (isset($_POST['auto_gen_text'])) {
                $sent_text = $mail->html2text($sent_html, true);
            } else {
                $sent_text = str_ireplace("&to&", $to, $message_text);
                $sent_text = str_ireplace("&from&", $sender, $sent_text);
                $sent_text = str_ireplace("&date&", $date, $sent_text);
                $sent_text = randomizeString($sent_text);
                $sent_text = randomizeInteger($sent_text);
                $sent_text = strip_tags($sent_text);
                $sent_text = str_ireplace("&name&", $name, $sent_text);
                $sent_text = str_ireplace("&surname&", $surname, $sent_text);
            }
            echo ". =>";
            flush();
            crossEcho("Sending to $to <font color=yellow>-</font> Subject: $title <font color=yellow>-</font> Sender name: $send_name <font color=yellow>-</font> Sender email: $sender <font color=yellow>-</font> reply-to: $reply2 => ");
            flush();
            try {

                $mail->MailerDebug = true;
                $mail->Priority = $XPriority;
                $mail->Encoding = $encoding;
                $mail->SetFrom($sender);
                $mail->FromName = $send_name;
                $mail->AddReplyTo($reply2, $send_name);
                $mail->AddAddress($to);
                $mail->Body = $sent_html;
                $mail->IsHTML(true);
                $mail->Subject = $title;
                $mail->AltBody = $sent_text;
                $mail->addCustomHeader("Reply-To: $reply2 <$send_name>");
                if ($use_smtp) {
                    $mail->IsSMTP();
                    $mail->SMTPDebug = 2;
                    $mail->Host = $smtp_host;
                    $mail->Port = $smtp_port;
                    if ($use_auth) {
                        $mail->SMTPAuth = true;
                        $mail->Username = $smtp_user;
                        $mail->Password = $smtp_pass;
                    }
                }
                if (isset($_FILES['file']) && $_FILES['file']['error'] == UPLOAD_ERR_OK) {
                    $test = mime_content_type($_FILES['file']['tmp_name']);
                    $mail->AddAttachment($_FILES['file']['tmp_name'], $_FILES['file']['name'], "base64", mime_content_type($_FILES['file']['tmp_name']));
                }
                if ($bpshtml) {
                    $mail->XMailer = "Microsoft Office Outlook, Build 17.551210\n";
                }
                if ($newsletter) {
                    $mail->set('List-Unsubscribe', '<mailto:unsubscribe@' . $HTTP_HOST . '>, <http://' . $HTTP_HOST . '/user/unsubscribe/?sid=abcdefg>');
                    $mail->addCustomHeader("X-Mailer: phplist v2.10.17");
                    $mail->addCustomHeader("X-Virus-Scanned: clamav-milter 0.98.1 at stamps.cs.ucsb.edu");
                    $mail->addCustomHeader("X-Virus-Status: Clean");
                    $mail->addCustomHeader("X-Spam-Status: No, score=1.3 required=5.0 tests=RDNS_NONE shortcircuit=no autolearn=no autolearn_force=no version=3.4.0");
                    $mail->addCustomHeader("X-Spam-Level: *");
                    $mail->addCustomHeader("X-Spam-Checker-Version: SpamAssassin 3.4.0 (2014-02-07) on stamps.cs.ucsb.edu");
                }
                if ($ovh) {
                    $mail->set("X-Ovh-Tracer-Id", mt_rand(1000, 999999) . mt_rand(1000, 999999) . mt_rand(1000, 999999) . mt_rand(1000, 999999));
                    $mail->set("X-VR-SPAMSTATE", "OK");
                    $mail->set("X-VR-SPAMSCORE", "-100");
                    $mail->set("X-VR-SPAMCAUSE", generateRandomString(154));
                    $mail->set("Return-Path", "bounce-id=D" . mt_rand(100, 200) . "=U" . mt_rand(1000, 10000) . "start.ovh.net" . mt_rand(1000, 999999) . mt_rand(1000, 999999) . mt_rand(1000, 999999) . "@89.mail-out.ovh.net");
                }
                if ($dkim) {
                    $mail->DKIM_selector = 'alpha';
                    $mail->DKIM_identity = $mail->From;
                    $mail->DKIM_domain = $_SERVER['SERVER_NAME'];
                    $mail->DKIM_private = $privateKey;
                    $mail->DKIM_passphrase = '';
                }
                $mail->send();
                crossEcho("<font color=green>Sent !</font> <br>");

            }
            catch (phpmailerException $e) {
                $excp = $e->getMessage();
                crossEcho("<font color=red>Not sent, sorry !</font><br>");
                if($excp == "Invalid Address"){
                    crossEcho("<font color=red>--Invalid address : $to</font>");
                    continue;
                }
                else{
                    crossEcho("<font color=red>-------A fatal error has occurred: $excp QUITTING !</font>");
                    break;
                }
            }
            catch (Exception $e) {
                echo "<font color=red>Not sent, sorry !</font><br>";
                echo "<font color=red>-------A fatal error has occured: " . $e->errorMessage() . " QUITTING !</font>";
                break;
            }

        } else {
            echo "$x -- Invalid email $to<br>";
            flush();
        }
    }
    if (!$isCli) {
        crossEcho("</div><script>alert('Sending Complete\r\nTotal Email $numemails Sent to inbox\r\nPraise for Wahib, Souheyel and Moetaz :D');</script>");
    } else {
       echo "DONE SENDING EMAILS. SENT $numemails EMAILS, HAVE A NICE DAY.";
    }

} elseif (isset($_POST['saveconf'])) {

    //write data here
    $data = array(
        "use_smtp" => isset($_POST['use_smtp']) ? "true" : "false",
        "smtp_host" => $_POST['smtp_host'],
        "smtp_port" => $_POST['smtp_port'],
        "use_auth" => isset($_POST['use_auth']) ? "true" : "false",
        "smtp_user" => $_POST['smtp_user'],
        "smtp_pass" => $_POST['smtp_pass'],
        "realname" => $_POST['realname'],
        "from" => $_POST['from'],
        "rep_to_is_sender" => isset($_POST['rep_to_is_sender']) ? "true" : "false",
        "replyto" => $_POST['replyto'],
        "XPriority" => $_POST['xpriority'],
        "encoding" => $_POST['Encoding'],
        "bpshtml" => isset($_POST['bpshtml']) ? "true" : "false",
        "newsletter" => isset($_POST['newsletter']) ? "true" : "false",
        "ovh" => isset($_POST['ovh']) ? "true" : "false",
        "dkim" => isset($_POST['DKIM']) ? "true" : "false",
        "genauto" => isset($_POST['genauto']) ? "true" : "false",
        "person" => isset($_POST['person']) ? "true" : "false",
        "subject" => stripslashes($_POST['subject']),
        "message_html" => base64_encode($_POST['message_html']),
        "message_text" => base64_encode($_POST['message_text']),
        "grts" => isset($_POST['grts']) ? "true" : "false");
    //write the file
    $paths = new Pathes();
    $tempConf = $paths->TJMailerConfigPath;
    $confDir = $paths->ConfDirName;
    $confFile = $paths->TJConfigFileName;
    $config = new Conf();
    $config->write_config_file($data, $tempConf);

    //now download it
    try {
        echo "<center>Saved under /$confDir/$confFile ! </script>";
        echo "<script type=\"text/javascript\">  window.open(\"./$confDir/$confFile\"); </script>";
    } catch (Exception $e) {
        die("An error has occurred downloading file: " . $e->getMessage());
    }
} elseif ((isset($_GET['operation']) && $_GET['operation'] == "dlcfg")|| ($isCli && $argv[1] == "-saveTemp")) {
    $paths = new Pathes();
    $templatePath = $paths->TJMailerTemplatePath;
    $confDir = $paths->ConfDirName;
    $confFile = $paths->TemplateConfFileName;
    $templateString = Conf::$header . Conf::$defaultConf;
    $fileName = $paths->TemplateConfFileName;
    if (!is_dir($confDir)) {
        mkdir($confDir, 0755, true);
    }
    if (!file_exists($templatePath)) {
        try {
            $myfile = fopen($templatePath, "wb") or die("Unable to open file!");
            fwrite($myfile, base64_decode($templateString));
            fclose($myfile);
        }
        catch (Exception $e) {
            die("An error has occurred generating file: " . $e->getMessage());
        }
    }
    if($isCli){
        echo "Template saved under ./$confDir/$fileName";
    }

    else{
    echo "<script type=\"text/javascript\">window.open(\"./$confDir/$fileName\"); </script>";
    }

}?>