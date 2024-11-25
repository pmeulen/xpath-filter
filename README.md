# XPath filter PoC

This is a proof of concept for a simple regular expression-based XPath filter function for detecting XPahs that could cause a DoS by taking too long to evaluate.

## Run tests

```bash
./composer install
./vendor/bin/phpunit
``` 

## Usage

```php
use XPATH_FILTER\xpath_filter;

new xpath_filter();

// OK
xpath_filter::filter("//ElementToEncrypt[not(@attribute='value')");

// Throws
xpath_filter::filter('count(//. | //@* | //namespace::*)');
```