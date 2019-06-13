<?php
require __DIR__ . '/vendor/autoload.php';

define('USERNAME', '');
define('PASSWORD', '');
define('CLIENT_ID', '');
define('CLIENT_SECRET', '');
define('TOKEN_URI', 'https://console.ilandcloud.com/auth/realms/iland-core/protocol/openid-connect/token');
define('BASE_API', 'https://api.ilandcloud.com/v1');
date_default_timezone_set('UTC');

$org = getOrgFromUserInventory(USERNAME);
$org_uuid = $org['uuid'];
$org_name = $org['name'];

$latest_report_uuid = getLatestEventReportUuid($org_uuid, 'vulnerability');

$current_date = time();
$week_ago = strtotime(date("Y-m-d H:i:s", $current_date) . " -7 day");
$task_uuid = generateEventReport($org_uuid, 'vulnerability', $week_ago * 1000, $current_date * 1000);
$generated_report_uuid = waitForSyncedTask($task_uuid)['other_attributes']['file_uuid'];

createVulnerabilityByHostTable($org_uuid, $org_name, $latest_report_uuid);
createVulnerabilityByHostTable($org_uuid, $org_name, $generated_report_uuid);

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

/**
 * Gets the inventory of given user and lazily grab's an org.
 *
 * @param string $username user to get inventory for
 * @return array first organization
 */
function getOrgFromUserInventory($username)
{
    $orgs = doRequest(sprintf('%s/users/%s/inventory', BASE_API, $username))['inventory']['0']['entities']['IAAS_ORGANIZATION'];
    return $orgs['0'];
}

/**
 * Generate an event report you specify and return's the task uuid.
 *
 * @param string $org_uuid organization's uuid you want the report for
 * @param string $type report type
 * @param string $start start date (optional)
 * @param string $end end date (optional)
 * @return string uuid of the generate report task
 */
function generateEventReport($org_uuid, $type, $start = NULL, $end = NULL)
{
    $options = array(CURLOPT_FAILONERROR => true,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST => 1,
        CURLOPT_HTTPHEADER => array(
            'Accept: application/vnd.ilandcloud.api.v1.0+json',
            'Authorization: Bearer ' . getAccessToken(),
            'Content-Type: application/json'
        ));
    return doRequest(sprintf("%s/orgs/%s/actions/generate-%s-report?start=%s&end=%s", BASE_API, $org_uuid, $type, $start, $end), $options)['uuid'];
}

/**
 * Given a task's uuid wait for it to sync.
 *
 * @param  string $task_uuid uuid of task to sync
 * @return string the synced task
 */
function waitForSyncedTask($task_uuid)
{
    $task = doRequest(sprintf('%s/tasks/%s', BASE_API, $task_uuid));
    while ($task['synced'] != 'true') {
        // wait 5 seconds before checking if the task has synced.
        sleep(5);
        $task = doRequest(sprintf('%s/tasks/%s', BASE_API, $task_uuid));
    }
    return $task;
}

/**
 * Get the latest report given an organization's uuid and event type.
 *
 * @param string $org_uuid organization's uuid
 * @param string $type event type
 * @return string latest report uuid
 */
function getLatestEventReportUuid($org_uuid, $type)
{
    return doRequest(sprintf("%s/orgs/%s/%s-reports?latest=true", BASE_API, $org_uuid, $type))['data']['0']['uuid'];
}

/**
 * Get the JSON content of the event report given it's uuid and the organization's uuid.
 *
 * @param string $org_uuid organization's uuid
 * @param string $report_uuid report uuid
 * @return string report json
 */
function getReportJson($org_uuid, $report_uuid)
{
    return doRequest(sprintf("%s/orgs/%s/reports/%s", BASE_API, $org_uuid, $report_uuid));
}

/**
 * Create's a HTML table given an array.
 *
 * @param array $array
 * @return string html table
 */
function createHtmlTable($array)
{
    $html = '<table>';
    // headers
    $html .= '<tr>';
    foreach ($array[0] as $key => $value) {
        $html .= '<th>' . htmlspecialchars($key) . '</th>';
    }
    $html .= '</tr>';
    // data rows
    foreach ($array as $key => $value) {
        $html .= '<tr>';
        foreach ($value as $key2 => $value2) {
            $html .= '<td>' . htmlspecialchars($value2) . '</td>';
        }
        $html .= '</tr>';
    }
    $html .= '</table>';
    return $html;
}

/**
 * Given a org uuid, org name and a report uuid generate a html table showing the vulnerabilities by host.
 *
 * @param string $org_uuid organization's uuid
 * @param string $org_name organization's name
 * @param string $report_uuid report uuid
 */
function createVulnerabilityByHostTable($org_uuid, $org_name, $report_uuid)
{
    echo '<h1>Vulnerability By Hosts for Organization: ' . $org_name . '</h1>';
    $vuln_json = json_decode(getReportJson($org_uuid, $report_uuid)['json_content'], true);
    foreach ($vuln_json['vulns_by_host'] as $value) {
        echo createHtmlTable($value);
    }
}

?>

