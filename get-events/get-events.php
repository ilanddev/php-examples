<?php
require __DIR__ . '/vendor/autoload.php';

define('USERNAME', '');
define('PASSWORD', '');
define('CLIENT_ID', '');
define('CLIENT_SECRET', '');
define('TOKEN_URI', 'https://console.ilandcloud.com/auth/realms/iland-core/protocol/openid-connect/token');
define('BASE_API', 'https://api.ilandcloud.com/v1');
date_default_timezone_set('UTC');

$vm_event_types = array('vm_antimalware_event', 'vm_dpi_event', 'vm_firewall_event', 'vm_integrity_event',
    'vm_log_inspection_event', 'vm_web_reputation_event');

$org_event_types = array('org_vulnerability_scan_launch', 'org_vulnerability_scan_pause', 'org_vulnerability_scan_resume',
    'org_vulnerability_scan_stop');

$company_id = getCompanyFromUserInventory(USERNAME);

while (true) {
    $current_time = time();
    $one_minute_ago = strtotime(date("Y-m-d H:i:s", $current_time) . " -60 second");
    $events = getEvents('COMPANY', $company_id, $one_minute_ago * 1000, $current_time * 1000);
    if (count($events['data']) > 0) {
        foreach ($events['data'] as $event) {
            if (($event['entity_type'] == 'IAAS_VM' && in_array($event['type'], $vm_event_types)) ||
                ($event['entity_type'] == 'IAAS_ORGANIZATION' && in_array($event['type'], $org_event_types))) {
                echo sprintf('User %s initiated event %s for entity %s',
                        $event['initiated_by_username'], $event['type'], $event['entity_name']) . PHP_EOL;
            }
        }
    }
    sleep(60);
}

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
 * Get events for the given entity, entity type, start and end date.
 *
 * @param string $entity_type type of entity
 * @param string $entity_uuid entity's uuid
 * @param string $start start time
 * @param string $end end time
 * @return string events
 */
function getEvents($entity_type, $entity_uuid, $start, $end)
{
    $uri_path = '%s/events?entityUuid=%s&entityType=%s&timestampAfter=%s&timestampBefore=%s&includeDescendantEvents=true';
    return doRequest(sprintf($uri_path, BASE_API, $entity_uuid,
        $entity_type, $start, $end));
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


?>
