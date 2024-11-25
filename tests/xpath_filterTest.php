<?php


use XPATH_FILTER\xpath_filter;
use PHPUnit\Framework\TestCase;

class xpath_filterTest extends TestCase
{

    /**
     * @dataProvider provideFilter
     */
    public function testFilter(string $xpath_expression, bool $allowed) : void
    {
        if ($allowed) {
            $this->expectNotToPerformAssertions();
        } else {
            $this->expectException(\Exception::class);
        }

        $xpath_filter = new xpath_filter();
        $xpath_filter->filter($xpath_expression);
    }

    public function provideFilter() : array
    {
        return [
            // [ 'xpath_expression', allowed ]

            // Evil
            ['count(//. | //@* | //namespace::*)', false],

            // Perfectly normal
            ["//ElementToEncrypt[@attribute='value']", true],
            ["/RootElement/ChildElement[@id='123']", true],
            ["not(self::UnwantedNode)", true ],
            ["//ElementToEncrypt[not(@attribute='value')]", true],

            // From https://www.w3.org/TR/xmlenc-core1/
            ['self::text()[parent::enc:CipherValue[@Id="example1"]]', false ],
            ['self::xenc:EncryptedData[@Id="example1"]', true],

            // Nonsense, but allowed by the filter as it doesn't understand XPath.
            ['self::not()[parent::enc:CipherValue[@Id="example1"]]', true ],

            // namespace in element name
            ["not(self::namespace)", true],

            // using "namespace" as a Namespace prefix
            ["//namespace:ElementName", true],

            // namespace in attribute value
            ["//ElementToEncrypt[@attribute='namespace::x']", true],

            // function in attribute value
            ["//ElementToEncrypt[@attribute='ns1::count()']", true],
        ];
    }
}
