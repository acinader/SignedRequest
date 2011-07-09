<?

/**
 * A General purpose request signer and validator object.
 *
 * Built to enable server to server http requsts that can be authenticated through the use
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
 * @copyright: Arthur Cinader 2011: Unlimited use is granted
 */
class SignedRequest {
    private $secret;
    private $ttl;

    // Public functions that clients will use....
    public function signRequest($params) {
        $params['timestamp'] = time();
        $params['signature'] = $this->createSignature($params);
        return $params;
    }

    public function validateRequest($params) {
        $is_valid = false;

        if(isset($params['signature']) && isset($params['timestamp'])) {
            $signature = $params['signature'];
            $params = array_diff_key($params, array('signature' => 1));
            $is_expired = ($params['timestamp'] + $this->ttl) < time();
            if(!$is_expired) {
                $is_sig_match = $signature == $this->createSignature($params);
                if($is_sig_match) {
                    $is_valid = true;
                }
                else {
                    trigger_error("request signature match failed", E_USER_ERROR);
                }

            }
            else {
                trigger_error("request is expired", E_USER_ERROR);
            }
        }

        return $is_valid;
    }

    public function validateCurrentRequest() {
        parse_str($_SERVER['QUERY_STRING'], $params);
        return $this->validateRequest($params);
    }

    public function generateValidQueryString($params) {
        $signed_params = $this->signRequest($params);
        return http_build_query($signed_params);
    }


    // internals....
    function __construct($secret, $ttl = 3600) {
        $this->secret = $secret;
        $this->ttl = $ttl;
    }

    // recursive array flattener
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

    protected function lower($params) {
        $return = array();

        foreach($params as $key => $value) {
            $return[strtolower($key)] = strtolower($value);
        }

        return $return;
    }

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
        return hash_hmac('sha256', $stringToSign, $this->secret);
    }
}


/***
 *
 * Uh, unit test and stuff to come if used? so this can be removed...
 */

$signer = new SignedRequest(123);
// little tester.
if($_GET) {
    echo $signer->validateCurrentRequest() ? "valid\n" : "invalid\n";
}
else {
    $params = array('foo' => 'bar', 'Fid' => array('fig' => 'floo', 'soo' => 'tid'), 'nid' => 'nad');
    echo "http://localhost/SignedRequest.php/?" . $signer->generateValidQueryString($params);
    echo "\n";
}
