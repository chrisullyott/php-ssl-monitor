<?php

/**
 * Fetch information about a domain's SSL certificate.
 *
 * Chris Ullyott <contact@chrisullyott.com>
 */

use ChrisUllyott\Cache;

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
     * The path to the cache directory.
     * 
     * @var string
     */
    private $cacheDir;

    /**
     * Constructor.
     *
     * @param string $url The URL or domain to fetch information about
     * @param string $cacheDir The cache directory
     */
    public function __construct($url, $cacheDir)
    {
        $this->setHostname(self::getHostFromUrl($url));
        $this->setCacheDir($cacheDir);
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
     * Set the cache directory.
     *
     * @param string $cacheDir The cache directory.
     * @return self
     */
    public function setCacheDir($cacheDir)
    {
        $this->cacheDir = $cacheDir;

        return $this;
    }

    /**
     * Get the cache directory.
     *
     * @return string
     */
    public function getCacheDir()
    {
        return $this->cacheDir;
    }

    /**
     * Get the cache key.
     * 
     * @return string 
     */
    private function getCacheKey()
    {
        return md5($this->getHostname());
    }

    /**
     * Get data from the SSL certificate, optionally by a key.
     *
     * @param string $key A given array key
     * @return mixed
     */
    public function get($key = null)
    {
        if (is_null($this->data)) {
            $this->data = $this->fetchOrGetFromCache('1 hour');
        }

        if ($key) {
            return isset($this->data[$key]) ? $this->data[$key] : null;
        }

        return $this->data;
    }

    /**
     * Get the host data from the cache or fetch it fresh.
     * 
     * @param  string $hostname   
     * @param  string $expiration 
     * @return array 
     */
    private function fetchOrGetFromCache($expiration)
    {
        $cacheObj = new Cache($this->getCacheKey(), $this->getCacheDir());

        $cache = $cacheObj->get();

        if (isset($cache['time']) && strtotime("-{$expiration}") < $cache['time']) {
            $this->data = $cache['data'];
        } else {
            $this->data = self::fetch($this->getHostname());
            $cacheObj->set(['time' => time(), 'data' => $this->data]);
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

        $context = stream_context_create([
            'ssl' => [
                'capture_peer_cert' => true,
                'verify_peer' => false
            ]
        ]);

        $stream = stream_socket_client($socket, $errno, $errstr, 30, STREAM_CLIENT_CONNECT, $context);
        $streamParams = stream_context_get_params($stream);

        if (!empty($streamParams['options']['ssl']['peer_certificate'])) {
            return openssl_x509_parse($streamParams['options']['ssl']['peer_certificate']);
        }

        return [];
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
