<?php

namespace XPATH_FILTER\tests;

use PHPUnit\Framework\TestCase;
use XPATH_FILTER\xpath_filter_utils;

class Xpath_filter_utilsTest extends TestCase
{
    public function test_remove_string_contents_speed()
    {
        // Measure the time it takes to process a large input, should be less than 1 second
        $start = microtime(true);
        $input = str_repeat('""', 10000) . str_repeat("''", 10000);
        $this->assertEquals($input, xpath_filter_utils::remove_string_contents($input));
        $end = microtime(true);
        $this->assertLessThan(1, $end - $start, "Processing time was too long");
    }

    /**
     * @dataProvider provideStringContents
     */
    public function test_remove_string_contents($input, $expected)
    {
        $this->assertEquals($expected, xpath_filter_utils::remove_string_contents($input));
    }

    public static function provideStringContents() : array
    {
        return [
            // Newline
            ["\n", "\n"], // 0

            // Empty string
            ['', ''],   // 1

            // No quotes
            ['foo', 'foo'], // 2
            ['foo bar', 'foo bar'], //3

            // Empty quotes
            ['""', '""'], //4
            ["''", "''"], //5
            ['"" ""', '"" ""'], //6
            ["'' ''", "'' ''"], //7
            ['"" "" ""', '"" "" ""'], //8
            ["'' '' ''", "'' '' ''"], //9

            // Quoted string
            ['"foo"', '""'], //10
            ["'foo'", "''"], //11

            // Multiple quoted strings
            ['"foo" "bar"', '"" ""'], //12
            ["'foo' 'bar'", "'' ''"], //13

            // Multiple quoted strings with newlines
            ['"foo" "bar"'."\n".'"abc"', '"" ""'."\n".'""'], //14
            ["'foo' 'bar'\n'abc'", "'' ''\n''"], //15

            // Multiple quoted strings with text
            ['"foo"abc"bar"', '""abc""'], //16
            ["'foo'abc'bar'", "''abc''"], //17
            ["'foo'def'bar'", "''def''"], //18

            // Mixed quotes
            ['"foo" \'bar\'', '"" \'\''], //19
            ["'foo' \"bar\"", "'' \"\""], //20

            // No WS between quotes
            ['"foo""bar"', '""""'], //21
            ["'foo''bar'", "''''"], //22
            ['"foo" "bar" "baz"', '"" "" ""'], //23
            ["'foo' 'bar' 'baz'", "'' '' ''"], //24
            ['"foo" \'"bar" "baz"\' "qux"', '"" \'\' ""'], //25
            ["'foo' \"'bar' 'baz'\" 'qux'", "'' \"\" ''"], //26
            ["'foo' 'bar' 'baz'", "'' '' ''"], //27
            ['"foo" \'"bar" "baz"\' "qux"', '"" \'\' ""'], //28
            ["'foo' \"'bar' 'baz'\" 'qux'", "'' \"\" ''"], //29
        ];
    }


    /**
     * @dataProvider provideXpathFunction
     */
    public function test_filter_xpath_function(string $input, $allowed_functions, $expected=null)
    {
        if ($expected) {
            // Function must throw an exception
            $this->expectException(\Exception::class);
            $this->expectExceptionMessage("Invalid function: '" . $expected . "'");
        } else {
            // Function must not throw an exception
            $this->expectNotToPerformAssertions();
        }
        xpath_filter_utils::filter_xpath_function($input, $allowed_functions);
    }

    public static function provideXpathFunction() : array
    {
        return [
            // [xpath, allowed functions, expected result (null = OK; string = name of the denied function)]
            ['', ['not'], null],
            ['not()', ['not'], null],
            ['count()', ['bar'], 'count'],
            ['not()', [], 'not'],
            ['count ()', ['foo', 'bar'], 'count'], 
            [' count ()', [], 'count'], 
            ['-count ()', [], 'count'], 
            ['- count ()', [], 'count'], 
            ['- (count ())', [], 'count'], 
            ['(-count())', [], 'count'], 
            ['not(not(),not())', ['not'], null], 
            ['not((not()),(not()))', ['not'], null], // 11;
            ['not(not(.),not(""))', ['not'], null], // 12;
            ['not( not(.), not(""))', ['not'], null], // 13;

            ['', [], null], 
            ['not(count(),not())', ['not'], 'count'], 
            ['not(not(),count())', ['not'], 'count'], 
            ['count(not(),not())', ['not'], 'count'], 
            ['(count(not(),not()))', ['not'], 'count'], 
            ['( count(not(),not()))', ['not'], 'count'], 
            ['(count (not(),not()))', ['not'], 'count'], 
            ['not((not()),(not()))', [], 'not'], 
            ['not(not(.),not(""))', [], 'not'], // 22;
            ['not( not(.), not(""))', [], 'not'], 

            ['abc-def', [], ''], 
            ['(abc-def)', [], ''], 
            ['(abc-def ( ) )', [], 'abc-def'], 

            ['abc-def', ['abc', 'def'], null], 
            ['(abc-def)', ['abc', 'def'], null], 
            ['(abc-def ( ) )', ['abc', 'def'], 'abc-def'], 
            ['', ['not'], null], 
            ['not()', ['not'], null], 
            ['count()', ['bar'], 'count'], 
            ['not()', [], 'not'], 
            ['count ()', ['foo', 'bar'], 'count'], 
            [' count ()', [], 'count'], 
            ['-count ()', [], 'count'], 
            ['- count ()', [], 'count'], 
            ['- (count ())', [], 'count'], 
            ['(-count())', [], 'count'], 
            ['not(not(),not())', ['not'], null], 
            ['not((not()),(not()))', ['not'], null], // 11;
            ['not(not(.),not(""))', ['not'], null], // 12;
            ['not( not(.), not(""))', ['not'], null], // 13;

            ['', [], null], 
            ['not(count(),not())', ['not'], 'count'], 
            ['not(not(),count())', ['not'], 'count'], 
            ['count(not(),not())', ['not'], 'count'], 
            ['(count(not(),not()))', ['not'], 'count'], 
            ['( count(not(),not()))', ['not'], 'count'], 
            ['(count (not(),not()))', ['not'], 'count'], 
            ['not((not()),(not()))', [], 'not'], 
            ['not(not(.),not(""))', [], 'not'], // 22;
            ['not( not(.), not(""))', [], 'not'], 

            ['abc-def', [], ''], 
            ['(abc-def)', [], ''], 
            ['(abc-def ( ) )', [], 'abc-def'], 

            ['abc-def', ['abc', 'def'], null], 
            ['(abc-def)', ['abc', 'def'], null], 
            ['(abc-def ( ) )', ['abc', 'def'], 'abc-def'], 

            // Evil
            ['count(//. | //@* | //namespace::*)', ['not', 'foo', 'bar'], 'count'], 

            // Perfectly normal
            ["//ElementToEncrypt[@attribute='value']", ['not', 'foo', 'bar'], null],
            ["/RootElement/ChildElement[@id='123']", ['not', 'foo', 'bar'], null],
            ["not(self::UnwantedNode)", ['not', 'foo', 'bar'], null],
            ["//ElementToEncrypt[not(@attribute='value')]", ['not', 'foo', 'bar'], null], 

            // From https://www.w3.org/TR/xmlenc-core1/
            ['self::text()[parent::enc:CipherValue[@Id="example1"]]', ['not', 'text'], null], 
            ['self::xenc:EncryptedData[@Id="example1"]', ['not', 'foo', 'bar'], null], 

            // count in element name
            ["not(self::count)", ['not', 'foo', 'bar'], null], 

            // using "namespace" as a Namespace prefix
            ["//namespace:ElementName", ['not', 'foo', 'bar'], null], 

            // count in attribute value
            //["//ElementToEncrypt[@attribute='count()']", ['not', 'foo', 'bar'], null], 
        ];
    }


    /**
     * @dataProvider provideXpathAxis
     */
    public function test_filter_xpath_axis(string $input, $allowed_axes, $expected=null)
    {
        if ($expected) {
            // Function must throw an exception
            $this->expectException(\Exception::class);
            $this->expectExceptionMessage("Invalid axis: '" . $expected . "'");
        } else {
            // Function must not throw an exception
            $this->expectNotToPerformAssertions();
        }
        xpath_filter_utils::filter_xpath_axis($input, $allowed_axes);
    }

    public static function provideXpathAxis() : array
    {
        return [
            // [xpath, allowed axes, exception (null = OK; string = is name of the denied axis)]
            ['', ['self'], null],
            ['self::', [], 'self'],
            [' self::', [], 'self'],
            [' self ::', [], 'self'],
            ['//self::X', [], 'self'],
            ['./self::', [], 'self'],
            ['namespace:element', [], null],
            ['ancestor-or-self::some-node', ['self'], 'ancestor-or-self'],
            [' ancestor-or-self::some-node', ['self'], 'ancestor-or-self'],
            ['/ancestor-or-self::some-node', ['self'], 'ancestor-or-self'],

            ['self::*/child::price', ['self'], 'child'],

            // Evil
            ['count(//. | //@* | //namespace::*)', ['self', 'foo', 'bar'], 'namespace'],

            // Perfectly normal
            ["//ElementToEncrypt[@attribute='value']", ['self'], null],
            ["/RootElement/ChildElement[@id='123']", ['self'], null],
            ["not(self::UnwantedNode)", ['self'], null],
            ["not(self::UnwantedNode)", [], 'self'],
            ["//ElementToEncrypt[not(@attribute='value')]", ['self'], null],

            // From https://www.w3.org/TR/xmlenc-core1/
            ['self::text()[parent::enc:CipherValue[@Id="example1"]]', ['self', 'parent'], null],
            ['self::text()[parent::enc:CipherValue[@Id="example1"]]', ['self'], 'parent'],
            ['self::text()[parent::enc:CipherValue[@Id="example1"]]', ['parent'], 'self'],
            ['self::xenc:EncryptedData[@Id="example1"]', ['self'], null],
            ['self::xenc:EncryptedData[@Id="example1"]', [], 'self'],

            // namespace in element name
            ["not(self::namespace)", ['self'], null],

            // using "namespace" as a Namespace prefix
            ["//namespace:ElementName", ['self'], null],

            // namespace in attribute value
            // ["//ElementToEncrypt[@attribute='namespace::x']", ['self'], null],
        ];
    }
}