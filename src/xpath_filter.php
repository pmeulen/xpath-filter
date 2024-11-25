<?php declare(strict_types=1);

namespace XPATH_FILTER;

class xpath_filter
{
    static $DEFAULT_ALLOWED_AXES = array(
        'ancestor',
        'ancestor-or-self',
        'attribute',
        'child',
        'descendant',
        'descendant-or-self',
        'following',
        'following-sibling',
        // 'namespace', // By default, we do not allow using the namespace axis
        'parent',
        'preceding',
        'preceding-sibling',
        'self'
    );

    static $DEFAULT_ALLOWED_FUNCTIONS = array(
        // 'boolean',
        // 'ceiling',
        // 'concat',
        // 'contains',
        // 'count',
        // 'false',
        // 'floor',
        // 'id',
        // 'lang',
        // 'last',
        // 'local-name',
        // 'name',
        // 'namespace-uri',
        // 'normalize-space',
        'not',
        // 'number',
        // 'position',
        // 'round'
        // 'starts-with',
        // 'string',
        // 'string-length',
        // 'substring',
        // 'substring-after',
        // 'substring-before',
        // 'sum',
        // 'text'
        // 'translate',
        // 'true',
    );

    private $allowed_axes = array(); // Array of string. List of allowed function names
    private $allowed_functions = array(); // Array of string. List of allowed axis names

    /**
     * Constructor
     * @param array(string) | null $allowed_functions array of string with a list of allowed function names
     * @param array(string) | null $allowed_axes array of string with a list of allowed axes names
     */
    public function __construct($allowed_functions=null, $allowed_axes=null)
    {
        if (null === $allowed_functions) {
            $this->allowed_functions = self::$DEFAULT_ALLOWED_FUNCTIONS;
        }
        if (null === $allowed_axes) {
            $this->allowed_axes = self::$DEFAULT_ALLOWED_AXES;
        }
    }

    /** Check an XPath expression for allowed axes and functions
     * The goal is preventing DoS attacks by limiting the complexity of the XPath expression by only allowing
     * a select subset of functions and axes.
     * The check uses a list of allowed functions and axes, and throws an exception when an unknown function
     * or axis is found in the $xpath_expression.
     *
     * Limitations:
     * - The implementation is based on regular expressions, and does not employ an XPath 1.0 parser. It may not
     *   evaluate all possible valid XPath expressions correctly and cause either false positives for valid
     *   expressions or false negatives for invalid expressions.
     * - The check may still allow expressions that are not safe, I.e. expressions that consist of only
     *   functions and axes that are deemed "save", but that are still slow to evaluate. The time it takes to
     *   evaluate an XPath expression depends on the complexity of both the XPath expression and the XML document.
     *   This check, however, does not take the XML document into account, nor is it aware of the internals of the
     *   XPath processor that will evaluate the expression.
     * - The check was written with the XPath 1.0 syntax in mind, but should work equally well for XPath 2.0 and 3.0.
     *
     * @param string $xpath_expression the expression to check. Should be a valid xpath expression
     * @throws \Exception when the $xpath_expression contains a function or axis that is not in the list of allowed
     *                    functions or axes
     */
    public function filter(string $xpath): void
    {
        // First remove the contents of any string literals in the $xpath to prevent false positives
        $xpath_without_string_literals = xpath_filter_utils::remove_string_contents($xpath);

        // Then check that the xpath expression only contains allowed functions and axes, throws when it doesn't
        xpath_filter_utils::filter_xpath_function($xpath_without_string_literals, $this->allowed_functions);
        xpath_filter_utils::filter_xpath_axis($xpath_without_string_literals, $this->allowed_axes);
    }
}