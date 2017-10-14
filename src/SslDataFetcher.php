<?php

/**
 * Fetch information about a domain's SSL certificate.
 *
 * Chris Ullyott <contact@chrisullyott.com>
 */
class SslDataFetcher
{
    /**
     * The hostname.
     *
     * @var string
     */
    private $hostname;

    /**
     * The SSL data.
     *
     * @var array
     */
    private $data;

    /**
     * Constructor.
     *
     * @param string $url The URL or domain to fetch information about
     */
    public function __construct($url)
    {
        $this->setHostname(self::getHostFromUrl($url));
    }

    /**
     * Set the hostname.
     *
     * @param string $hostname The hostname.
     * @return self
     */
    public function setHostname($hostname)
    {
        $this->hostname = $hostname;

        return $this;
    }

    /**
     * Get the hostname.
     *
     * @return string
     */
    public function getHostname()
    {
        return $this->hostname;
    }

    /**
     * Get data from the SSL certificate, optionall by key.
     *
     * @param string $key A given array key
     * @return mixed
     */
    public function get($key = null)
    {
        if (is_null($this->data)) {
            $this->data = self::fetch($this->getHostname());
        }

        if ($key) {
            return isset($this->data[$key]) ? $this->data[$key] : null;
        }

        return $this->data;
    }

    /**
     * Fetch the SSL expiration.
     *
     * @param string $hostname The hostname
     * @return self
     */
    private static function fetch($hostname)
    {
        $socket = "ssl://{$hostname}:443";

        $context = stream_context_create(array(
            'ssl' => array(
                'capture_peer_cert' => true,
                'verify_peer' => false
            )
        ));

        $stream = stream_socket_client($socket, $errno, $errstr, 30, STREAM_CLIENT_CONNECT, $context);
        $streamParams = stream_context_get_params($stream);

        if (!empty($streamParams['options']['ssl']['peer_certificate'])) {
            return openssl_x509_parse($streamParams['options']['ssl']['peer_certificate']);
        }

        return array();
    }

    /**
     * Get the domain from a URL string.
     *
     * @param  string $url A URL to operate on
     * @return string
     */
    private static function getHostFromUrl($url)
    {
        // parse_url() doesn't work without a URL scheme.
        if (!preg_match('/[a-z]+:\/\//', $url)) {
            $url = "http://{$url}";
        }

        return parse_url($url, PHP_URL_HOST);
    }
}
