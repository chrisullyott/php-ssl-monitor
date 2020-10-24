<?php

/**
 * Check a group of URLs for their SSL expiration times and build a notification.
 *
 * Chris Ullyott <contact@chrisullyott.com>
 */
class SslMonitor
{
    /**
     * The current time.
     *
     * @var integer
     */
    private $time;

    /**
     * A list of domains to check.
     *
     * @var array
     */
    private $domains = [];

    /**
     * The path to the cache directory.
     * 
     * @var string
     */
    private $cacheDir;

    /**
     * A list of domains paired with their SSL certificate expiration times.
     *
     * @var array
     */
    private $expirations = [];

    /**
     * The number of days into the future to include expirations (ie, will expire).
     *
     * @var integer
     */
    private $beforeDays = 30;

    /**
     * The number of days after expiration to still be notified.
     *
     * @var integer
     */
    private $afterDays = 7;

    /**
     * The number of days before expiration when action becomes critical.
     *
     * @var integer
     */
    private $criticalDays = null;

    /**
     * Constructor.
     *
     * @param array $domains A list of domains to check.
     */
    public function __construct($domains, $cacheDir = null)
    {
        $this->domains = (array) $domains;
        $this->cacheDir = $cacheDir ? $cacheDir : __DIR__ . '/cache';
    }

    /**
     * Get the domains.
     *
     * @return array
     */
    public function getDomains()
    {
        return $this->domains;
    }

    /**
     * Set the number of days into the future to include expirations (ie, will expire).
     *
     * @param integer $beforeDays
     * @return self
     */
    public function setBeforeDays($beforeDays)
    {
        $this->beforeDays = $beforeDays;

        return $this;
    }

    /**
     * Get the number of days into the future to include expirations (ie, will expire).
     *
     * @return integer
     */
    public function getBeforeDays()
    {
        return $this->beforeDays;
    }

    /**
     * Set the number of days before expiration when action becomes critical.
     *
     * @param integer $criticalDays
     * @return self
     */
    public function setCriticalDays($criticalDays)
    {
        $this->criticalDays = $criticalDays;

        return $this;
    }

    /**
     * Get the number of days before expiration when action becomes critical.
     *
     * @return integer
     */
    public function getCriticalDays()
    {
        return $this->criticalDays;
    }

    /**
     * Set the number of days after expiration to still be notified.
     *
     * @param integer $afterDays
     * @return self
     */
    public function setAfterDays($afterDays)
    {
        $this->afterDays = $afterDays;

        return $this;
    }

    /**
     * Get the number of days after expiration to still be notified.
     *
     * @return integer
     */
    public function getAfterDays()
    {
        return $this->afterDays;
    }

    /**
     * Get the current timestamp at runtime.
     *
     * @return int
     */
    private function getTime()
    {
        if (!$this->time) {
            $this->time = time();
        }

        return $this->time;
    }

    /**
     * Whether it's the weekend :)
     *
     * @return boolean
     */
    private function isWeekend()
    {
        return in_array(date('D', $this->getTime()), ['Sat', 'Sun']);
    }

    /**
     * Fetch the SSL expiration times for all domains.
     *
     * @return array
     */
    private function getExpirations()
    {
        if (!$this->expirations) {
            foreach ($this->getDomains() as $domain) {
                $fetcher = new SslDataFetcher($domain, $this->cacheDir);

                if ($expTime = $fetcher->get('validTo_time_t')) {
                    $this->expirations[] = [
                        'domain' => $domain,
                        'time' => $expTime
                    ];
                }
            }

            $this->expirations = self::sortByKey($this->expirations, 'time');
        }

        return $this->expirations;
    }

    /**
     * Whether a given expiration timestamp should be included in the notification.
     *
     * @param  int $expTime The expiration timestamp
     * @return boolean
     */
    private function shouldNotify($expTime = null)
    {
        // There is no expiration time.
        if (!$expTime) {
            return false;
        }

        // Expiration does not happen between the set time ranges.
        $min = $expTime - self::secondsOfDays($this->getBeforeDays());
        $max = $expTime + self::secondsOfDays($this->getAfterDays());

        if (!self::isBetween($this->getTime(), $min, $max)) {
            return false;
        }

        // Expiration is approaching but do not notify on weekends unless critical.
        if ($this->getCriticalDays()) {
            $critical = $expTime - self::secondsOfDays($this->getCriticalDays());

            if (self::isBetween($this->getTime(), $min, $critical) && $this->isWeekend()) {
                return false;
            }
        }

        return true;
    }

    /**
     * Build a list of expiring SSL certificates, grouped by expiration date.
     *
     * @return array
     */
    private function buildExpirationList()
    {
        $list = [];

        foreach ($this->getExpirations() as $exp) {
            if (!$this->shouldNotify($exp['time'])) {
                continue;
            }

            $remaining = $exp['time'] - $this->getTime();

            if ($remaining > 0) {
                $group = 'SSL expires in ' . self::secondsToString($remaining);
            } else {
                $group = 'SSL EXPIRED';
            }

            if (!isset($list[$group])) {
                $list[$group] = [];
            }

            $list[$group][] = $exp;
        }

        return $list;
    }

    /**
     * Build the notification text.
     *
     * @return string
     */
    public function buildMessage()
    {
        $message = '';

        foreach ($this->buildExpirationList() as $k => $v) {
            $message .= "{$k}:\n";

            foreach ($v as $kk => $vv) {
                $message .= $vv['domain'];
                $message .= ' (' . date('l F j, Y', $vv['time']) . ')' . "\n";
            }

            $message .= "\n";
        }

        return trim($message);
    }

    /**
     * Whether an integer is between two other integers.
     *
     * @param  int $value The integer to check
     * @param  int $min   The lower limit
     * @param  int $max   The upper limit
     * @return boolean
     */
    private static function isBetween($value, $min, $max)
    {
        return ($min <= $value) && ($value <= $max);
    }

    /**
     * Translate a number of seconds into a string, ie "4 hours", "2 days", etc.
     *
     * @param  int $seconds A number of seconds
     * @return string
     */
    private static function secondsToString($seconds)
    {
        $units = [
            'year'   => 60 * 60 * 24 * 365,
            'month'  => 60 * 60 * 24 * 30,
            'week'   => 60 * 60 * 24 * 7,
            'day'    => 60 * 60 * 24,
            'hour'   => 60 * 60,
            'minute' => 60,
            'second' => 1
        ];

        foreach ($units as $n => $s) {
            if ($seconds >= $s) {
                $v = floor($seconds / $s);
                $text = $v == 1 ? "{$v} {$n}" : "{$v} {$n}s";
                return "{$text}";
            }
        }
    }

    /**
     * Get the number of seconds in X days.
     *
     * @param  int $days A number of days
     * @return int
     */
    private static function secondsOfDays($days)
    {
        return 60 * 60 * 24 * $days;
    }

    /**
     * Sort an associative array by key values.
     *
     * @param  array  $array    The array to sort
     * @param  string $key      The key name
     * @param  boolean $reverse Whether to reverse the order
     * @return array
     */
    private static function sortByKey($array, $key, $reverse = false)
    {
        $sorter = [];
        $ret = [];
        reset($array);

        foreach ($array as $ii => $va) {
            $sorter[$ii] = $va[$key];
        }

        asort($sorter);

        foreach ($sorter as $ii => $va) {
            $ret[$ii] = $array[$ii];
        }

        if ($reverse) {
            $ret = array_reverse($ret);
        }

        return array_values($ret);
    }
}
