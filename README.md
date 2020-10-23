# php-ssl-monitor

Monitor SSL certificate expiration dates.

### Installation

With Composer:

```
composer require chrisullyott/php-ssl-monitor
```

### Setup

```php
include 'vendor/autoload.php';

$domains = [
    'www.domainone.com',
    'www.domaintwo.com',
    'www.domainthree.com'
];

$monitor = new SslMonitor($domains);

// The maximum number of days before expiration in order to be notified.
$monitor->setBeforeDays(30);

// Must expire within this many days in order to be notified on weekends.
$monitor->setCriticalDays(7);

// The maximum number of days after expiration in order to still be notified.
$monitor->setAfterDays(7);

echo $monitor->buildMessage() . "\n";
```

### Output

```
SSL expires in 5 hours:
www.domaintwo.com (Saturday October 14, 2018)

SSL expires in 1 week:
www.domainone.com (Saturday October 20, 2018)
```
