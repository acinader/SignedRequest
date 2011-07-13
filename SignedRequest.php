<?

/**
 * A General purpose request signer and validator object.
 *
 * Built to enable server to server http requests that can be authenticated through the use
 * of a shared secret.
 *
 * Usage:
 *
 *   $params = array('foo' => 'bar', 'Fid' => array('fig' => 'floo', 'soo' => 'tid'), 'nid' => 'nad');
 *   echo "http://localhost/SignedRequest.php/?" . $signer->generateValidQueryString($params) . "\n";
 *
 * To validate the current request:
 *
 *   echo $signer->validateCurrentRequest() ? "valid\n" : "invalid";
 *
 * @copyright (C) 2011 Arthur Cinader Jr.
 * @license see LICENSE
 */
class SignedRequest {

    /**
     * Shared secret between the two parties exchanging requests
     * @access private
     * @var string
     */
    private $secret;

    /**
     * Time to live for a particular request.  A request is valid only if
     * it was signed and received within the time to live.
     * @access private
     * @var string
     */
    private $ttl;

    /**
     * The hashing algorithm to use for the signature. Valid algorithms can be
     * found by running "print_r(hash_algos())"
     *
     * http://www.php.net/manual/en/function.hash-algos.php
     *
     * @access private
     * @var string
     */
    private $hash_algorithm;


    /**
     * Sign a request to allow for authentication by the recipient
     *
     * @param array $params name value pairs to sign
     * @return array with added timestamp and signature
     */
    public function signRequest($params) {
        $params['timestamp'] = time();
        $params['signature'] = $this->createSignature($params);
        return $params;
    }

    /**
     * Validate an array of parameters
     *
     * @param array $params name value pairs to validate
     * @return boolean indicating if the params are valid and received within the ttl
     */
    public function validateRequest($params) {
        $is_valid = false;

        if(isset($params['signature']) && isset($params['timestamp'])) {
            $signature = $params['signature'];
            // remove the signature from the params array as it is not part of the calculation
            $params = array_diff_key($params, array('signature' => 1));
            $is_expired = ($params['timestamp'] + $this->ttl) < time();
            if(!$is_expired) {
                $is_sig_match = $signature == $this->createSignature($params);
                if($is_sig_match) {
                    $is_valid = true;
                }
                else {
                    trigger_error("Request signature match failed", E_USER_WARNING);
                }

            }
            else {
                trigger_error("Request is expired", E_USER_WARNING);
            }
        }

        return $is_valid;
    }

    /**
     * Convenience function to validate the currently active request
     *
     * @return boolean indicating if the current request can be authenticated and is received
     *      within the ttl
     * @TODO: add error handling and trigger warnings
     */
    public function validateCurrentRequest() {
        // put the current query string into the passed by reference array $params
        parse_str($_SERVER['QUERY_STRING'], $params);
        return $this->validateRequest($params);
    }

    /**
     * Convenience function to generate a signed query string
     *
     * @param array $params name value pairs to sign and turn into a query string
     * @returns string in query string format
     * @see http_build_query
     */
    public function generateValidQueryString($params) {
        $signed_params = $this->signRequest($params);
        return http_build_query($signed_params);
    }

    /**
     * Create a SignedRequest object
     *
     * @param string $secret shared secret to use in signing requests
     * @param int $ttl the time to live to a requests (Default 3600 seconds)
     * @param string $hash_algorithm (default 'sha256')
     * @thorws Exception when instantiated with an invalid $hash_algorithm
     * @see http://www.php.net/manual/en/function.hash-algos.php
     */
    function __construct($secret, $ttl = 3600, $hash_algorithm = 'sha256') {
        $this->secret = $secret;
        $this->ttl = $ttl;

        // Validate hash algorithm
        if (in_array($hash_algorithm, hash_algos())) {
            $this->hash_algorithm = $hash_algorithm;
        }
        else {
            throw new Exception("Invalid hash algorithm specified: {$hash_algorithm}.");
        }
    }

    /**
     * Recursively flatten an associative array into a non nested array
     *
     * This function may lose some implied structure to data and is really only to be used
     * for the limited comparison purpose of validating a request.
     *
     * @param array $params the array to flatten
     * @return array a flat array that contains no sub arrays
     */
    protected function flatten($params) {
        $return = array();

        foreach($params as $key => $value) {
            if(is_array($value)) {
                $return = array_merge($return, $this->flatten($value));
            }
            else {
                $return[$key] = $value;
            }
        }

        return $return;
    }

    /**
     * Change case of an associative array's keys and values to lower case
     *
     * @param array $params to change case of
     * @return array with all keys and value in lower case
     */
    protected function lower($params) {
        $return = array();

        foreach($params as $key => $value) {
            $return[strtolower($key)] = strtolower($value);
        }

        return $return;
    }

    /**
     * Generate a signature from an associative array using a shared secret
     *
     * @param array $params to create a signature from
     * @return string signature of the supplied array
     */
    protected function createSignature($params) {
        // flatten any sub arrays
        $params = $this->flatten($params);

        // make all lower case
        $params = $this->lower($params);

        ksort($params);

        // make a string from the array
        foreach($params as $key => $value) {
            $stringToSign .= $key . $value;
        }

        // Note there is no need to base64 encode or url encode this content since it returns hexits by default
        return hash_hmac($this->hash_algorithm, $stringToSign, $this->secret);
    }
}
