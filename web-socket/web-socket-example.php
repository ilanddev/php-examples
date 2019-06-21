<?php
require __DIR__ . '/vendor/autoload.php';

define('USERNAME', '');
define('PASSWORD', '');
define('CLIENT_ID', '');
define('CLIENT_SECRET', '');
define('TOKEN_URI', 'https://console.ilandcloud.com/auth/realms/iland-core/protocol/openid-connect/token');
define('BASE_API', 'https://api.ilandcloud.com/v1');
define('WS_URI', 'wss://api.ilandcloud.com/v1/event-websocket');

$company_id = getCompanyFromUserInventory(USERNAME);

$vm_event_types = array('vm_antimalware_event', 'vm_dpi_event', 'vm_firewall_event', 'vm_integrity_event',
    'vm_log_inspection_event', 'vm_web_reputation_event');

$org_event_types = array('org_vulnerability_scan_launch', 'org_vulnerability_scan_pause', 'org_vulnerability_scan_resume',
    'org_vulnerability_scan_stop');

\Ratchet\Client\connect(WS_URI)->then(function($conn) {
    $conn->on('message', function($msg) use ($conn) {
        if($msg == 'AUTHORIZATION') {
            $conn->send(sprintf('companyId=%s,Bearer %s', $GLOBALS['company_id'], getAccessToken()));
        } else {
            $message = json_decode($msg);
            if($message->type == 'EVENT') {
                $event = $message->data;
                if (($event->entity_type == 'IAAS_VM' && in_array($event->type, $GLOBALS['vm_event_types'])) ||
                    ($event->entity_type == 'IAAS_ORGANIZATION' && in_array($event->type, $GLOBALS['org_event_types']))) {
                    echo sprintf('User %s initiated event %s for entity %s',
                            $event->initiated_by_username, $event->type, $event->entity_name) . PHP_EOL;
                }
            }
        }
    });

}, function ($e) {
    echo "Could not connect: {$e->getMessage()}\n";
});


/**
 * Gets the inventory of given user and lazily grab's a company id.
 *
 * @param string $username user to get inventory for
 * @return array first company
 */
function getCompanyFromUserInventory($username)
{
    $company_id = doRequest(sprintf('%s/users/%s/inventory', BASE_API, $username))['inventory'][0]['company_id'];
    return $company_id;
}

/**
 * Get the access token using defined credentials.
 *
 * @return string access token
 */
function getAccessToken()
{
    $provider = new \League\OAuth2\Client\Provider\GenericProvider([
        'clientId' => CLIENT_ID,
        'clientSecret' => CLIENT_SECRET,
        'urlAccessToken' => TOKEN_URI,
        'urlResourceOwnerDetails' => '',
        'redirectUri' => '',
        'urlAuthorize' => ''
    ]);
    try {
        $access_token = $provider->getAccessToken('password', [
            'username' => USERNAME,
            'password' => PASSWORD
        ]);
        return $access_token;

    } catch (\League\OAuth2\Client\Provider\Exception\IdentityProviderException $e) {

        // Failed to get the access token
        exit($e->getMessage());

    }
}

/**
 * Function that handles executing the requests. Can pass custom cURL options.
 *
 * @param string $path the URI path
 * @param null $options custom cURL options, optional
 * @return string api response
 */
function doRequest($path, $options = NULL)
{
    if ($options == null) {
        $options = array(CURLOPT_FAILONERROR => true,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => array(
                'Accept: application/vnd.ilandcloud.api.v1.0+json',
                'Authorization: Bearer ' . getAccessToken()));
    }
    $req = curl_init($path);
    curl_setopt_array($req, $options);
    $resp = json_decode(curl_exec($req), true);
    if (curl_error($req)) {
        echo curl_error($req);
    }
    return $resp;
}


?>

