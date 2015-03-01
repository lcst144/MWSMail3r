<?php



function PHPMailerAutoload($classname)
{
    $filename = dirname(__FILE__) . DIRECTORY_SEPARATOR . 'class.' . strtolower($classname) . '.php';
    if (is_readable($filename)) {
        require $filename;
    }
}

if (version_compare(PHP_VERSION, '5.1.2', '>=')) {
    if (version_compare(PHP_VERSION, '5.3.0', '>=')) {
        spl_autoload_register('PHPMailerAutoload', true, true);
    } else {
        spl_autoload_register('PHPMailerAutoload');
    }
} else {
    function __autoload($classname)
    {
        PHPMailerAutoload($classname);
    }
}

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

class PHPMailer
{
    const STOP_MESSAGE = 0;
    const STOP_CONTINUE = 1;
    const STOP_CRITICAL = 2;
    const CRLF = "\r\n";
    public $Version = '5.2.8';
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
                throw new phpmailerException('Invalid recipient array: ' . $kind);
            }
            return false;
        }
        $address = trim($address);
        $name = trim(preg_replace('/[\r\n]+/', '', $name));
        if (!$this->validateAddress($address)) {
            $this->setError($this->lang('invalid_address') . ': ' . $address);
            $this->edebug($this->lang('invalid_address') . ': ' . $address);
            if ($this->exceptions) {
                throw new phpmailerException($this->lang('invalid_address') . ': ' . $address);
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
                throw new phpmailerException($this->lang('invalid_address') . ': ' . $address);
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
        } catch (phpmailerException $exc) {
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
                throw new phpmailerException($this->lang('provide_address'), self::STOP_CRITICAL);
            }
            if (!empty($this->AltBody)) {
                $this->ContentType = 'multipart/alternative';
            }
            $this->error_count = 0;
            $this->setMessageType();
            if (!$this->AllowEmpty and empty($this->Body)) {
                throw new phpmailerException($this->lang('empty_message'), self::STOP_CRITICAL);
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
        } catch (phpmailerException $exc) {
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
        $uniq_id = uniqid("pubmws_") . md5(time());
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
            $result .= $this->headerLine('X-Mailer', 'PHPMailer ' . $this->Version);
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
                $result .= $this->headerLine('Content-Type', 'multipart/related;
');
                $result .= $this->textLine("\tboundary=\"" . $this->boundary[1] . '"');
                break;
            case  'attach':
            case  'inline_attach':
            case  'alt_attach':
            case  'alt_inline_attach':
                $result .= $this->headerLine('Content-Type', 'multipart/mixed;
');
                $result .= $this->textLine("\tboundary=\"" . $this->boundary[1] . '"');
                break;
            case  'alt':
            case  'alt_inline':
                $result .= $this->headerLine('Content-Type', 'multipart/alternative;
');
                $result .= $this->textLine("\tboundary=\"" . $this->boundary[1] . '"');
                break;
            default:
                $result .= $this->textLine('Content-Type: ' . $this->ContentType . ';
 charset=' . $this->CharSet);
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
                $body .= $this->headerLine('Content-Type', 'multipart/related;
');
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
                    $body .= $this->getBoundary($this->boundary[1], '', 'text/calendar;
 method=REQUEST', '');
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
                $body .= $this->headerLine('Content-Type', 'multipart/related;
');
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
                $body .= $this->headerLine('Content-Type', 'multipart/alternative;
');
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
                $body .= $this->headerLine('Content-Type', 'multipart/alternative;
');
                $body .= $this->textLine("\tboundary=\"" . $this->boundary[2] . '"');
                $body .= $this->LE;
                $body .= $this->getBoundary($this->boundary[2], $altBodyCharSet, 'text/plain', $altBodyEncoding);
                $body .= $this->encodeString($this->AltBody, $altBodyEncoding);
                $body .= $this->LE . $this->LE;
                $body .= $this->textLine('--' . $this->boundary[2]);
                $body .= $this->headerLine('Content-Type', 'multipart/related;
');
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
                    throw new phpmailerException($this->lang('signing') . ' OpenSSL extension missing.');
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
                    throw new phpmailerException($this->lang('signing') . openssl_error_string());
                }
            } catch (phpmailerException $exc) {
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
        $result .= sprintf('Content-Type: %s;
 charset=%s', $contentType, $charSet);
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
                $mime[] = sprintf('Content-Type: %s;
 name="%s"%s', $type, $this->encodeHeader($this->secureHeader($name)), $this->LE);
                if ($encoding != '7bit') {
                    $mime[] = sprintf('Content-Transfer-Encoding: %s%s', $encoding, $this->LE);
                }
                if ($disposition == 'inline') {
                    $mime[] = sprintf('Content-ID: <%s>%s', $cid, $this->LE);
                }
                if (!(empty($disposition))) {
                    if (preg_match('/[ \(\)<>@,;
:\\"\/\[\]\?=]/', $name)) {
                        $mime[] = sprintf('Content-Disposition: %s;
 filename="%s"%s', $disposition, $this->encodeHeader($this->secureHeader($name)), $this->LE . $this->LE);
                    } else {
                        $mime[] = sprintf('Content-Disposition: %s;
 filename=%s%s', $disposition, $this->encodeHeader($this->secureHeader($name)), $this->LE . $this->LE);
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
                throw new phpmailerException($this->lang('file_open') . $path, self::STOP_CONTINUE);
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
        $ident = ($this->DKIM_identity == '') ? '' : ' i=' . $this->DKIM_identity . ';
';
        $dkimhdrs = 'DKIM-Signature: v=1;
 a=' . $DKIMsignatureType . ';
 q=' . $DKIMquery . ';
 l=' . $DKIMlen . ';
 s=' . $this->DKIM_selector . ";
\r\n" . "\tt=" . $DKIMtime . ';
 c=' . $DKIMcanonicalization . ";
\r\n" . "\th=From:To:Subject;
\r\n" . "\td=" . $this->DKIM_domain . ';
' . $ident . "\r\n" . "\tz=$from\r\n" . "\t|$to\r\n" . "\t|$subject;
\r\n" . "\tbh=" . $DKIMb64 . ";
\r\n" . "\tb=";
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
                throw new phpmailerException($this->lang('signing') . ' OpenSSL extension missing.');
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
        } catch (phpmailerException $exc) {
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
                    throw new phpmailerException($this->lang('execute') . $this->Sendmail, self::STOP_CRITICAL);
                }
                fputs($mail, 'To: ' . $toAddr . "\n");
                fputs($mail, $header);
                fputs($mail, $body);
                $result = pclose($mail);
                $this->doCallback(($result == 0), array($toAddr), $this->cc, $this->bcc, $this->Subject, $body, $this->From);
                if ($result != 0) {
                    throw new phpmailerException($this->lang('execute') . $this->Sendmail, self::STOP_CRITICAL);
                }
            }
        } else {
            if (!@$mail = popen($sendmail, 'w')) {
                throw new phpmailerException($this->lang('execute') . $this->Sendmail, self::STOP_CRITICAL);
            }
            fputs($mail, $header);
            fputs($mail, $body);
            $result = pclose($mail);
            $this->doCallback(($result == 0), $this->to, $this->cc, $this->bcc, $this->Subject, $body, $this->From);
            if ($result != 0) {
                throw new phpmailerException($this->lang('execute') . $this->Sendmail, self::STOP_CRITICAL);
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
            throw new phpmailerException($this->lang('smtp_connect_failed'), self::STOP_CRITICAL);
        }
        $smtp_from = ($this->Sender == '') ? $this->From : $this->Sender;
        if (!$this->smtp->mail($smtp_from)) {
            $this->setError($this->lang('from_failed') . $smtp_from . ' : ' . implode(',', $this->smtp->getError()));
            throw new phpmailerException($this->ErrorInfo, self::STOP_CRITICAL);
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
            throw new phpmailerException($this->lang('data_not_accepted'), self::STOP_CRITICAL);
        }
        if ($this->SMTPKeepAlive == true) {
            $this->smtp->reset();
        } else {
            $this->smtp->quit();
            $this->smtp->close();
        }
        if (count($bad_rcpt) > 0) {
            throw new phpmailerException($this->lang('recipients_failed') . implode(', ', $bad_rcpt), self::STOP_CONTINUE);
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
                            throw new phpmailerException($this->lang('connect_host'));
                        }
                        $this->smtp->hello($hello);
                    }
                    if ($this->SMTPAuth) {
                        if (!$this->smtp->authenticate($this->Username, $this->Password, $this->AuthType, $this->Realm, $this->Workstation)) {
                            throw new phpmailerException($this->lang('authenticate'));
                        }
                    }
                    return true;
                } catch (phpmailerException $exc) {
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
            throw new phpmailerException($this->lang('instantiate'), self::STOP_CRITICAL);
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
                throw new phpmailerException($this->lang('file_access') . $path, self::STOP_CONTINUE);
            }
            if ($type == '') {
                $type = self::filenameToType($path);
            }
            $filename = basename($path);
            if ($name == '') {
                $name = $filename;
            }
            $this->attachment[] = array(0 => $path, 1 => $filename, 2 => $name, 3 => $encoding, 4 => $type, 5 => false, 6 => $disposition, 7 => 0);
        } catch (phpmailerException $exc) {
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
            require_once 'extras/class.html2text.php';
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
                throw new phpmailerException($this->lang('variable_set') . $name, self::STOP_CRITICAL);
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

class phpmailerException extends Exception
{
    public function errorMessage()
    {
        $errorMsg = '<strong>' . $this->getMessage() . "</strong><br />\n";
        return $errorMsg;
    }
}

?>

<?php error_reporting(0); //this is to suppress index not set messages.. ?>
    <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
        "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
    <html xmlns="http://www.w3.org/1999/xhtml">
    <head>
        <title>.: MWS Priv8 Mail3R :.</title>

        <script src="http://www.position-relative.net/creation/formValidator/js/jquery-1.7.2.min.js"
                type="text/javascript">
        </script>
        <script src="http://www.position-relative.net/creation/formValidator/js/jquery.validationEngine.js"
                type="text/javascript" charset="utf-8">
        </script>
        <script src="http://www.position-relative.net/creation/formValidator/js/languages/jquery.validationEngine-en.js"
                type="text/javascript" charset="utf-8">
        </script>
        <script src=http://ajax.aspnetcdn.com/ajax/jquery.validate/1.13.0/localization/messages_en.js"
                type="text/javascript" charset="utf-8">
        </script>
        <style type="text/css">
            /*<![CDATA[*/
            <!--
            .style1 {
                font-size: 20px;

                font-family: Geneva, Arial, Helvetica, sans-serif;

            }

            body {
                background-color: #000000;

            }

            body {
                color: white;

            }

            div.c6 {
                text-align: right
            }

            p.c5 {
                font-family: Verdana, Arial, Helvetica, sans-serif;

                font-size: 100%
            }

            span.c4 {
                font-family: Verdana, Arial, Helvetica, sans-serif;

                font-size: 100%;

                color: RED
            }

            div.c3 {
                font-family: Verdana, Arial, Helvetica, sans-serif;

                font-size: 70%;

                text-align: right
            }

            table.c3 {
                font-family: Verdana, Arial, Helvetica, sans-serif;

                font-size: 70%;

                text-align: left
            }

            span.c3 {
                font-family: Verdana, Arial, Helvetica, sans-serif;

                font-size: 70%;

            }

            div.c2 {
                text-align: center
            }

            span.c1 {
                FONT-SIZE: 50pt;

                color: red;

                float: left;

                font-family: Webdings, Georgia, Serif
            }

            label.c1 {
                font-family: Verdana, Arial, Helvetica, sans-serif;

                font-size: 70%;

            }

            /*]]>*/
        </style>
    </head>
    <body>

    <div class="c2">
        <span class="style1 c1"> ! </span>
        <table border="0" width="53%" class="c3">
            <tr>
                <td><font color="green">Server name:</font></td>
                <td> <?php echo $UNAME = @php_uname();
                    ?> <br/></td>
            </tr>
            <tr>
                <td><font color="green">Operating System: </font></td>
                <td><?php echo $OS = @PHP_OS;
                    ?><br/></td>
            </tr>
            <tr>
                <td><font color="green">Server IP: </font></td>
                <td><?php echo $_SERVER['SERVER_ADDR'];
                    ?><br/></td>
            </tr>
            <tr>
                <td><font color="green">Server software:</font></td>
                <td><?php echo $_SERVER['SERVER_SOFTWARE'];
                    ?><br/></td>
            </tr>
            <tr>
                <td><font color="green">Safe Mode: </font></td>
                <td><?php echo $safe_mode = @ini_get('safe_mode');
                    ?><br/></td>
            </tr>
        </table>
    </div>


    <hr>
    <form name="form1" method="post" action="" id="form1" enctype="multipart/form-data">
    <center><span class="c4">SMTP Configuration</span><br><br><br></center>
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
                <label for="use_smtp"><span class="c3">Relay e-mail via SMTP</span></label>
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
                    <input type="text" id="user" name="user" placeholder="SMTP Username"
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
        <input id="pass" type="text" name="pass" value="<?php echo(isset($_POST['pass']) ? $_POST['pass'] : ""); ?>"
               placeholder="SMTP pass" size="60"/>
                </span>
            </td>
        </tr>

    </table>

    <br/>
    <br/>
    <hr>

    <center><span class="c4">E-Mail data</span><br><br><br></center>
    <table width="100%">
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
               name="checkbox" <?php echo(isset($_POST['checkbox']) ? "checked" : ""); ?>/>

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
        <input id="subject" type="text" name="subject" placeholder="Subjects seperated by ||" size="182"
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
                <option value="1" <?php echo(($_POST['xpriority'] == "1") ? "selected" : ""); ?>> Highest</option>
                <option value="2" <?php echo(($_POST['xpriority'] == "2") ? "selected" : ""); ?>> High</option>
                <option value="3" <?php echo(($_POST['xpriority'] == "3") ? "selected" : ""); ?>> Medium</option>
                <option value="4" <?php echo(($_POST['xpriority'] == "4") ? "selected" : ""); ?>> Low</option>
                <option value="5" <?php echo(($_POST['xpriority'] == "5") ? "selected" : ""); ?>> Lowest</option>
            </select>
        </td>
        <td width="5%">
            <div class="c3">
                Encoding
            </div>
        </td>
        <td>

            <input name="Encoding" id="Encoding" type="radio"
                   value="base64" <?php echo(($_POST['Encoding'] == "base64") ? "checked" : ""); ?>/>
            <span class="c3"> Base64 </span>

            <input name="Encoding" id="Encoding" type="radio"
                   value="QUOTED-PRINTABLE" <?php echo(($_POST['Encoding'] == "QUOTED-PRINTABLE") ? "checked" : ""); ?>/>
            <span class="c3"> Quoted printable </span>

            <input name="Encoding" id="Encoding" type="radio"
                   value="8bit" <?php echo(($_POST['Encoding'] == "8bit") ? "checked" : ""); ?>/>
            <span class="c3"> 8bit </span>

            <input name="Encoding" id="Encoding" type="radio"
                   value="7bit" <?php echo(($_POST['Encoding'] == "7bit") ? "checked" : ""); ?>/>
            <span class="c3"> 7bit </span>

            <input name="Encoding" id="Encoding" type="radio"
                   value="binary" <?php echo(($_POST['Encoding'] == "binary") ? "checked" : ""); ?>/>
            <span class="c3"> binary </span>

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
                  placeholder="This is the HTML part of the message" cols="70" rows="10" required>

            <?php echo(isset($_POST['message_html']) ? $_POST['message_html'] : "This mailer uses advanced algorithms. variables are self explanotory.
            &name&*
            &surname&*
            &to& -- victims email
            [random_string]
            [random_int]
            &date& -- Time and date of send
            &from& -- The sender email adress
            * - Only available when \"Use email|name|surname format.\" is enabled");?>
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
        </span>
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
              name="auto_gen_text" <?php echo(isset($_POST['auto_gen_text']) ? "checked" : ""); ?>/>

        <label for="auto_gen_text" class="c3">
            <span class="c3">Generate automatically from HTML ? (Not recommended)</span></label><br/>

                    <textarea id="message_text" class="validate[required]" name="message_text" cols="70"
                              placeholder="This is the text part of the message"
                              rows="10"> <?php echo(isset($_POST['message_text']) ? $_POST['message_text'] : "This mailer uses advanced algorithms. variables are self explanotory.\n
            &name&*
            &surname&*
            &to& -- victims email
            [random_string]
            [random_int]
            &date& -- Time and date of send
            &from& -- The sender email adress
            * - Only available when \"Use email|name|surname format.\" is enabled");?></textarea>
        <br/>
       <br/>
        </td>
        <td width="5%"
            valign="top">
            <div class="c3">&nbsp;
            </div>
        </td>
        <td width="50%" valign="top"><span class="c4">
            <div>

                <font color="orange">Use bypass tricks (If you don't know what are you doing, PLEASE LEAVE THOSE
                    UNCHECKED)</font><br><br>


                <input id="bpshtml" type="checkbox"
                       name="bpshtml" <?php echo(isset($_POST['bpshtml']) ? "checked" : ""); ?>/>
                <label style="" for="bpshtml">
                    <span class="c3">Forge MS Outlook Identity (Effective for Hotmail)</span></label>
                <br/>
                <input id="newsletter" type="checkbox"
                       name="newsletter" <?php echo(isset($_POST['newsletter']) ? "checked" : ""); ?>/>
                <label style="" for="newsletter">
                    <span class="c3">Make it look as newsletter (Quite effective for GMail)</span></label>
                <br/>
                <input id="ovh" type="checkbox" name="ovh" <?php echo(isset($_POST['ovh']) ? "checked" : ""); ?>/>
                <label style="" for="ovh">
                    <span class="c3">Fake OVH headers</span></label>
                <br/>
                <input id="grts" type="checkbox" name="grts" <?php echo(isset($_POST['grts']) ? "checked" : ""); ?>/>
                <label style="" for="grts">
                    <span class="c3">Add verified symbol to the title.</span></label>
                <br/>


            </div>
        </td>
    </tr>
    </table>
    <br/>
    <br/>

    <div class="c2">
        <input type="submit"
               value="Send to Inbox !"/>
    </div>
    </form>
    </body>
    </html>

<?php
error_reporting(E_ERROR | E_WARNING | E_PARSE | E_NOTICE); //this is to un-suppress error messages..

if (isset($_POST['action'])) {
    $action = $_POST['action'];
    $emaillist = $_POST['emaillist'];
    $from = $_POST['from'];
    $replyto = $_POST['replyto'];
    $XPriority = $_POST['xpriority'];
    $subject = stripslashes($_POST['subject']);
    $realname = $_POST['realname'];
    $encoding = $_POST['Encoding'];
    if (isset($_POST['file'])) {
        $file_name = $_POST['file'];
    } else {
        $file_name = NULL;
    }

    $message_html = $_POST['message_html'];
    $message_html = urlencode($message_html);
    $message_html = str_ireplace("%5C%22", "%22", $message_html);
    $message_html = urldecode($message_html);
    $message_html = stripslashes($message_html);
    $message_text = $_POST['message_text'];
    $message_text = urlencode($message_text);
    $message_text = str_ireplace("%5C%22", "%22", $message_text);
    $message_text = urldecode($message_text);
    $message_text = stripslashes($message_text);
    $allemails = explode("\n", $emaillist);
    $numemails = count($allemails);
    $names = explode(',', $realname);
    $subjects = explode("||", $subject);
    echo "Parsed your E-mail, let the magic happen ! <br><hr>";
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

    for ($x = 0;
         $x < $numemails;
         $x++) {
        $to = $allemails[$x];
        $name = "";
        $surname = "";
        if (isset($_POST['person'])) {
            $current = explode("|", $allemails[$x]);
            $to = $current[0];
            $name = $current[1];
            $surname = $current[2];
        }
        if (preg_match("/([\w\-]+\@[\w\-]+\.[\w\-]+)/", $to)) {
            $date = date('Y/m/d H:i:s');
            $to = str_ireplace(" ", "", $to);
            echo "$x: Generating E-mail.";
            flush();
            $sender = randomizeString($from);
            $sender = randomizeInteger($sender);
            echo ".";
            flush();
            if (isset($_POST['checkbox'])) {
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
            if (isset($_POST['grts'])) {
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
                $sent_text = strip_tags($sent_html);
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
            print"Sending to $to <font color=yellow>-</font> Subject: $title <font color=yellow>-</font> Sender name: $send_name <font color=yellow>-</font> Sender email: $sender <font color=yellow>-</font> reply-to: $reply2 => ";
            flush();
            try {
                $mail = new PHPmailer(true);
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
                if (isset($_POST['use_smtp'])) {
                    $mail->IsSMTP();
                    $mail->SMTPDebug = 2;
                    $mail->Host = $_POST['smtp_host'];
                    $mail->Port = $_POST['smtp_port'];
                    if (isset($_POST['smtp_auth'])) {
                        $mail->SMTPAuth = true;
                        $mail->Username = $_POST['smtp_user'];
                        $mail->Password = $_POST['smtp_pass'];
                    }
                }
                if (isset($_FILES['file']) && $_FILES['file']['error'] == UPLOAD_ERR_OK) {
                    $test = mime_content_type($_FILES['file']['tmp_name']);
                    $mail->AddAttachment($_FILES['file']['tmp_name'], $_FILES['file']['name'], "base64", mime_content_type($_FILES['file']['tmp_name']));
                }
                if (isset($_POST['bpshtml'])) {
                    $mail->XMailer = "Microsoft Office Outlook, Build 17.551210\n";
                }
                if (isset($_POST['newsletter'])) {
                    $mail->set('List-Unsubscribe', '<mailto:unsubscribe@' . $HTTP_HOST . '>, <http://' . $HTTP_HOST . '/user/unsubscribe/?sid=abcdefg>');
                    $mail->addCustomHeader("X-Mailer: phplist v2.10.17");
                    $mail->addCustomHeader("X-Virus-Scanned: clamav-milter 0.98.1 at stamps.cs.ucsb.edu");
                    $mail->addCustomHeader("X-Virus-Status: Clean");
                    $mail->addCustomHeader("X-Spam-Status: No, score=1.3 required=5.0 tests=RDNS_NONE shortcircuit=no autolearn=no autolearn_force=no version=3.4.0");
                    $mail->addCustomHeader("X-Spam-Level: *");
                    $mail->addCustomHeader("X-Spam-Checker-Version: SpamAssassin 3.4.0 (2014-02-07) on stamps.cs.ucsb.edu");
                }
                if (isset($_POST['ovh'])) {
                    $mail->set("X-Ovh-Tracer-Id", mt_rand(1000, 999999) . mt_rand(1000, 999999) . mt_rand(1000, 999999) . mt_rand(1000, 999999));
                    $mail->set("X-VR-SPAMSTATE", "OK");
                    $mail->set("X-VR-SPAMSCORE", "-100");
                    $mail->set("X-VR-SPAMCAUSE", generateRandomString(154));
                    $mail->set("Return-Path", "bounce-id=D" . mt_rand(100, 200) . "=U" . mt_rand(1000, 10000) . "start.ovh.net" . mt_rand(1000, 999999) . mt_rand(1000, 999999) . mt_rand(1000, 999999) . "@89.mail-out.ovh.net");
                }
                if (isset($_POST['DKIM'])) {
                    $mail->DKIM_selector = 'alpha';
                    $mail->DKIM_identity = $mail->From;
                    $mail->DKIM_domain = $_SERVER['SERVER_NAME'];
                    $mail->DKIM_private = $privateKey;
                    $mail->DKIM_passphrase = '';
                }
                $mail->send();
                echo "<font color=green>Sent !</font> <br>";
            } catch (phpmailerException $e) {
                echo "<font color=red>Not sent, sorry !</font><br>";
                echo "<font color=red>-------A fatal error has occured: " . $e->errorMessage();
                ". QUITTING !</font>";
                break;
            } catch (Exception $e) {
                echo "<font color=red>Not sent, sorry !</font><br>";
                echo "<font color=red>-------A fatal error has occured: " . $e->getMessage();
                ". QUITTING !</font>";
                break;
            }
        } else {
            Print"$x -- Invalid email $to<br>";
            flush();
        }
    }
    echo "<script>alert('Sending Completed\\r\\nTotal Email $numemails Sent to inbox\\r\\nPraise for Wahib, Souheyel and Moetaz :D');
</script>";
}?>