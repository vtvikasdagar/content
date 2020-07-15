from typing import Dict, Tuple, List

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
from datetime import datetime
from typing import Callable

import urllib3
import traceback

# Disable insecure warnings
urllib3.disable_warnings()


''' GLOBAL VARIABLES '''


MALICIOUS_DICTIONARY = {
    'low': 1,
    'medium': 2,
    'high': 3
}

MALICIOUS_THRESHOLD = demisto.params().get('threshold')


''' CLIENT '''


class Client:
    """
    bla bla
    """
    def __init__(self, params):
        self._cs_client = CrowdStrikeClient(params=params)
        self.query_params = ['offset', 'limit', 'sort', 'q', 'query']
        self.date_params = {
            'created_date': {'operator': '', 'raw_name': 'created_date'},
            'max_last_modified_date': {'operator': '<=', 'api_key': 'last_modified_date'},
            'min_last_activity_date': {'operator': '>=', 'api_key': 'first_activity_date'},
            'max_last_activity_date': {'operator': '<=', 'api_key': 'last_activity_date'}
        }

    def build_request_params(self, args: dict) -> dict:
        """
        Build the params dict for the request
        :param args: Cortex XSOAR args
        :return: The params dict
        """
        params: dict = {key: args.get(key) for key in self.query_params}
        params['filter'] = self.build_filter_query(args)
        return assign_params(**params)

    @staticmethod
    def date_to_epoch(date: str) -> int:
        """
        Converts date of ISO format to epoch timestamp
        :param date: The date in ISO format
        :return: The timestamp
        """
        return int(datetime.fromisoformat(date).timestamp())

    def build_filter_query(self, args: dict) -> str:
        """
        Builds the filter query in Falcon Query Language (FQL)
        :param args: Cortex XSOAR args
        :return: The query
        """
        filter_query: str = str()

        for key in args:
            if key not in self.query_params:
                if key not in self.date_params:
                    values: list = argToList(args[key], ',')
                    for value in values:
                        filter_query += f"{key}:'{value}'+"
                else:
                    operator: str = self.date_params.get(key, {}).get('operator')
                    api_key: str = self.date_params.get(key, {}).get('api_key')
                    filter_query += f"{api_key}:{operator}{self.date_to_epoch(args[key])}+"

        if filter_query.endswith('+'):
            filter_query = filter_query[:-1]

        return filter_query

    def check_quota_status(self):
        return self._cs_client.check_quota_status()

    def file(self):
        pass

    def ip(self):
        pass

    def url(self):
        pass

    def domain(self):
        pass

    def cs_actors(self, args):
        params = self.build_request_params(args)
        return self._cs_client.http_request(method='GET', url_suffix='intel/combined/actors/v1', params=params)

    def cs_indicators(self, args):
        params = self.build_request_params(args)
        return self._cs_client.http_request(method='GET', url_suffix='intel/combined/indicators/v1', params=params)

    def cs_reports(self, args):
        params = self.build_request_params(args)
        return self._cs_client.http_request(method='GET', url_suffix='intel/combined/reports/v1', params=params)


''' HELPER FUNCTIONS '''


def build_indicator(indicator_object: dict, indicator_type: str, title: str, append_context_function: Callable) -> dict:
    ec: dict = dict()
    return ec


def get_values(l: list) -> str:
    """
    Returns the values of list's items
    :param l: The items list
    :return: The values list
    """
    new_list: list = [item.get('value') for item in l]
    return ', '.join(new_list)


def indicator_to_md(o: dict) -> str:
    """
    Build the human readable of an indicator
    :param o: The indicator's object
    :return: The indicator's human readable
    """
    md: str = str()

    if o:
        indicator_value = o.get('indicator')
        indicator_type: str = o.get('type')
        last_update: int = o.get('last_update')
        publish_date: int = o.get('publish_date')
        malicious_confidence: str = o.get('malicious_confidence')
        reports: list = o.get('reports')
        actors: list = o.get('actors')
        malware_families: list = o.get('malware_families')
        kill_chains: list = o.get('kill_chains')
        domain_types: list = o.get('domain_types')
        ip_address_types: list = o.get('ip_address_types')
        relations: list = o.get('relations')
        labels: list = o.get('labels')

        md += '### ' + indicator_value + '\n' if indicator_value else ''
        md += '- Type: ' + indicator_type + '\n' if indicator_type else ''
        md += '- Last update: ' + timestamp_to_datestring(last_update) + '\n' if last_update else ''
        md += '- Publish date: ' + timestamp_to_datestring(publish_date) + '\n' if publish_date else ''
        md += '- Malicious confidence: ' + malicious_confidence + '\n' if malicious_confidence else ''
        md += '- Reports: ' + ', '.join(reports) + '\n' if reports else ''
        md += '- Actors: ' + ', '.join(actors) + '\n' if actors else ''
        md += '- Malware families: ' + ', '.join(malware_families) + '\n' if malware_families else ''
        md += '- Kill chains: ' + ', '.join(kill_chains) + '\n' if kill_chains else ''
        md += '- Domain types: ' + ', '.join(domain_types) + '\n' if domain_types else ''
        md += '- IP Address types: ' + ', '.join(ip_address_types) + '\n' if ip_address_types else ''

        if relations:
            md += '#### Relations\n'
            md += tableToMarkdown(name='', t=relations[:10]) + '\n'
        if labels:
            md += '#### Labels\n'
            md += tableToMarkdown(name='', t=labels[:10]) + '\n'

    return md


def add_indicator_to_context(indicator_type: str, indicator_object: dict, dbot_score: int, ec: dict, path: str) -> None:
    """
    Creates an indicator's context entry
    :param indicator_type: The indicator's type
    :param indicator_object: The indicator's object
    :param dbot_score: The indicator's DBotScore
    :param ec: The entry context
    :param path: The path in the context
    :return: None
    """
    indicator_ec: dict = dict()
    indicator_ec[indicator_type] = indicator_object.get('indicator')

    if indicator_object.get('reports'):
        indicator_ec['Report'] = indicator_object.get('reports')
    if indicator_object.get('actors'):
        indicator_ec['Actor'] = indicator_object.get('actors')
    if indicator_object.get('malware_families'):
        indicator_ec['Malware families'] = indicator_object.get('malware_families')
    if indicator_object.get('kill_chains'):
        indicator_ec['Kill Chains'] = indicator_object.get('kill_chains')
    if dbot_score == 3:
        indicator_ec['Malicious'] = {'Vendor': 'FalconIntel', 'Description': 'High confidence'}

    ec[path] = indicator_ec


def dbot_type_hash_list(indicator, score) -> list:
    """
    Creates a DBotScore entry
    :param indicator: The indicator value
    :param score: The Score
    :return: The DBotScore entry
    """
    return [{
        'Indicator': indicator,
        'Type': 'hash',
        'Vendor': 'FalconIntel',
        'Score': score
    }, {
        'Indicator': indicator,
        'Type': 'file',
        'Vendor': 'FalconIntel',
        'Score': score
    }]


''' COMMANDS '''


def test_module(client: Client):
    """
    If a client is successfully constructed then an accesses token was successfully reached,
    therefore the username and password are valid and a connection was made.
    Additionally, checks if not using all the optional quota and check that an http request to actors & indicators
    endpoints in successful.
    :param client: the client object with an access token
    :return: ok if got a valid accesses token and not all the quota is used at the moment
    """
    output = client.check_quota_status()

    error: list = output.get('errors')
    if error:
        return error[0]

    meta: dict = output.get('meta')
    if meta is not None:
        quota: dict = meta.get('quota')
        if quota is not None:
            total: int = quota.get('total')
            used: int = quota.get('used')
            if total <= used:
                raise Exception(f'Quota limitation has been reached: {used}')
            else:
                client._cs_client.http_request('GET', 'intel/combined/indicators/v1', params={'limit': 1})
                client._cs_client.http_request('GET', 'intel/combined/actors/v1', params={'limit': 1})
                return 'ok'
    raise Exception('Quota limitation is unreachable')


def file_command(client: Client):
    pass


def ip_command(client: Client):
    pass


def url_command(client: Client):
    pass


def domain_command(client: Client):
    pass


def cs_actors_command(client: Client):
    res = client.cs_actors(demisto.args())
    resources: list = res.get('resources', [])

    if not resources:
        return 'No actors found.', {}, res

    md = '## Falcon Intel Actor search\n'
    for r in resources:
        image_url = r.get('image', {}).get('url')
        name = r.get('name')
        actor_id = r.get('id')
        url = r.get('url')
        slug = r.get('slug')
        short_description = r.get('short_description')
        first_activity_date = r.get('first_activity_date')
        last_activity_date = r.get('last_activity_date')
        active = r.get('active')
        known_as = r.get('known_as')
        target_industries = r.get('target_industries')
        target_countries = r.get('target_countries')
        origins = r.get('origins')
        motivations = r.get('motivations')
        capability = r.get('capability', {}).get('value')
        group = r.get('group')
        region = r.get('region', {}).get('value')
        kill_chain = r.get('kill_chain')

        if image_url:
            md += '![' + name + '](' + image_url + ' "' + name + '")\n'

        md += '### ' + name + '\n'
        md += 'ID: [' + str(actor_id) + '](' + url + ')\n'
        md += 'Slug: ' + slug + '\n'
        md += 'Short description: ' + short_description + '\n'
        md += 'First/Last activity: ' + timestamp_to_datestring(first_activity_date) + ' / ' + \
              timestamp_to_datestring(last_activity_date) + '\n'
        md += 'Active: ' + str(active) + '\n' if active is not None else ''
        md += 'Known as: ' + known_as + '\n' if known_as else ''
        md += '- Target industries: ' + get_values(target_industries) + '\n' if target_industries else ''
        md += '- Target countries: ' + get_values(target_countries) + '\n' if target_countries else ''
        md += '- Origins: ' + get_values(origins) + '\n' if origins else ''
        md += '- Motivations: ' + get_values(motivations) + '\n' if motivations else ''
        md += '- Capability: ' + capability + '\n' if capability else ''
        md += '- Group: ' + group + '\n' if group else ''
        md += '- Region: ' + region + '\n' if region else ''

        if kill_chain:
            md += '#### Kill chain\n'
            for kc_field in kill_chain:
                if 'rich_text' in kc_field and kc_field.index('rich_text') == 0:
                    continue
                md += '- ' + string_to_table_header(kc_field) + ': ' + kill_chain.get(kc_field)
            md += '\n'

    return md, {}, res


def cs_indicators_command(client: Client):
    args: dict = demisto.args()
    res = client.cs_indicators(args)
    resources: list = res.get('resources', [])

    if not resources:
        return 'No reports found.', {}, res

    md: str = f"## Falcon Intel Indicator Search for: {args.get('indicator')}\n"
    ec: dict = dict()

    for r in resources:
        md += indicator_to_md(r)
        dbot_type: str = str()
        malicious_confidence: int = MALICIOUS_DICTIONARY.get(r.get('malicious_confidence'), 0)
        indicator_type: str = r.get('type')

        if malicious_confidence == 3 or MALICIOUS_THRESHOLD == 1:
            dbot_score = 3
        elif malicious_confidence == 2 or MALICIOUS_THRESHOLD == 2:
            dbot_score = 2
        else:
            dbot_score = 1

        if indicator_type == 'hash_md5':
            add_indicator_to_context('MD5', r, dbot_score, ec, outputPaths['file'])
            dbot_type = 'hash'
        elif indicator_type == 'hash_sha1':
            add_indicator_to_context('SHA1', r, dbot_score, ec, outputPaths['file'])
            dbot_type = 'hash'
        elif indicator_type == 'hash_sha256':
            add_indicator_to_context('SHA256', r, dbot_score, ec, outputPaths['file'])
            dbot_type = 'hash'
        elif indicator_type == 'ip_address':
            add_indicator_to_context('Address', r, dbot_score, ec, outputPaths['ip'])
            dbot_type = 'ip'
        elif indicator_type == 'url':
            add_indicator_to_context('Data', r, dbot_score, ec, outputPaths['url'])
            dbot_type = 'url'
        elif indicator_type == 'domain':
            add_indicator_to_context('Name', r, dbot_score, ec, outputPaths['domain'])
            dbot_type = 'domain'

        if dbot_type:
            if dbot_type == 'hash':
                ec['DBotScore'] = dbot_type_hash_list(r.get('indicator'), dbot_score)
            else:
                ec['DBotScore'] = [{
                    'Indicator': r.get('indicator'),
                    'Type': dbot_type,
                    'Vendor': 'FalconIntel',
                    'Score': dbot_score
                }]

    return md, ec, res


def cs_reports_command(client: Client):
    res = client.cs_reports(demisto.args())
    resources: list = res.get('resources', [])

    if not resources:
        return 'No reports found.', {}, res

    md: str = '## Falcon Intel Report search\n'
    for r in resources:
        report_id: int = r.get('id')
        url: str = r.get('url')
        name: str = r.get('name')
        report_type: str = r.get('type', {}).get('name')
        sub_type: str = r.get('sub_type', {}).get('name')
        slug: str = r.get('slug')
        created_date: int = r.get('created_date')
        last_modified_date: int = r.get('last_modified_date')
        short_description: str = r.get('short_description')
        target_industries: list = r.get('target_industries')
        target_countries: list = r.get('target_countries')
        motivations: list = r.get('motivations')
        tags: list = r.get('tags')

        md += '### ' + name + '\n'
        md += 'ID: [' + str(report_id) + '](' + url + ')\n'
        md += 'Type: ' + report_type + '\n'
        md += 'Sub type: ' + sub_type + '\n'
        md += 'Slug: ' + slug + '\n'
        md += 'Created: ' + timestamp_to_datestring(created_date) + '\n'
        md += 'Last modified: ' + timestamp_to_datestring(last_modified_date) + '\n'
        md += 'Description: ' + short_description + '\n'
        md += '- Target industries: ' + get_values(target_industries) + '\n' if target_industries else ''
        md += '- Target countries: ' + get_values(target_countries) + '\n' if target_countries else ''
        md += '- Motivations: ' + get_values(motivations) + '\n' if motivations else ''
        md += '- Tags: ' + get_values(tags) + '\n' if motivations else ''

    return md, {}, res


def main():
    params: dict = demisto.params()
    try:
        command = demisto.command()
        LOG(f'Command being called in CrowdStrikeFalconIntel is: {command}')
        client = Client(params=params)
        if command == 'test-module':
            return_outputs(test_module(client))
        elif command == 'file':
            hr, ops, raw = file_command(client)
            return_outputs(hr, ops, raw)
        elif command == 'ip':
            hr, ops, raw = ip_command(client)
            return_outputs(hr, ops, raw)
        elif command == 'url':
            hr, ops, raw = url_command(client)
            return_outputs(hr, ops, raw)
        elif command == 'domain':
            hr, ops, raw = domain_command(client)
            return_outputs(hr, ops, raw)
        elif command == 'cs-actors':
            hr, ops, raw = cs_actors_command(client)
            return_outputs(hr, ops, raw)
        elif command == 'cs-indicators':
            hr, ops, raw = cs_indicators_command(client)
            return_outputs(hr, ops, raw)
        elif command == 'cs-reports':
            hr, ops, raw = cs_reports_command(client)
            return_outputs(hr, ops, raw)
        else:
            raise NotImplementedError(f'{command} is not an existing CrowdStrikeFalconIntel command')
    except Exception as err:
        return_error(f'Unexpected error:\n{str(err)}', error=traceback.format_exc())


from CrowdStrikeApiModule import *  # noqa: E402

if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
