<style>
    span { font-size:11px; }
    div  { margin: 5px; }
</style>

<?php
/**
 * This is a simple test of SignedRequest object
 *
 *
 * This page has three states:
 *
 *  1. No GET or POST in the request: Display a simple form to enter name value pairs into
 *  2. POST vars means the form has just been submitted, so build a signed link for the user to click
 *  3. GET vars mean that a link has been clicked with query params that should be signed, so validate
 *
 * The interaction on this page should be enough to use this class for signing and validating requests.
 *
 * Any input? Please let me know.
 */
require './vendor/autoload.php';

use Acinader\SignedRequest;

$secret = 123; // obviously this is not a good choice ;)
// make ttl really short (seconds) so we can see it time out
$ttl = 30;

$signedRequest = new SignedRequest($secret, $ttl);

if (!($_GET || $_POST)) {
    ?>
        Enter some name value pairs to make up your query string to sign
        <form method="post">
        <table>
            <tr>
                <th>Name</th>
                <th>Value</th>
            </tr>
            <tr>
                <td><input type='text' name='name1' /></td>
                <td><input type='text' name='value1' /></td>
            </tr>
            <tr>
                <td><input type='text' name='name2' /></td>
                <td><input type='text' name='value2' /></td>
            </tr>
            <tr>
                <td><input type='text' name='name3' /></td>
                <td><input type='text' name='value3' /></td>
            </tr>
            <tr>
                <td colspan=2><input type='submit' value='submit' /></td>
            </tr>
        </table>

    <?php
}
// Process the form and build a link that validates
else if ($_POST) {

    // Get the filled out fields only - very little validation here :)
    $params = array_filter($_POST);

    // Get signed params just so we can print it out
    $signed_params = $signedRequest->signRequest($params);

    // Get the query string that we'll use in the href
    $query_string =  $signedRequest->generateValidQueryString($params);
    ?>
        <div>Here's what the signature looks like: <span><?= $signed_params['signature'] ?></span></div>
        <div><a href="<?= "?" . $query_string ?>">Click me to validate</a></div>
        <div><a href=>Go Back</a></div>
    <?php
}
// validate the link that was just clicked
else if($_GET) {
    $is_valid = $signedRequest->validateCurrentRequest();
    if($is_valid) {
        ?>
            <div>The current request is valid and was created with a shared secret</div>
            <div>To make it invalid, change some query parameters and reload.</div>
        <?php
    }
    else {
        ?>
            <div>The current request is invalid.  <a href="<?= $_SERVER['PHP_SELF']; ?>">Try Again</a></div>
        <?php
    }
}
