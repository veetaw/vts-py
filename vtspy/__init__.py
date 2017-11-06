import requests
import json

URL = 'https://www.virustotal.com/vtapi/v2/'
HEADERS = {
    'Accept-Encoding': 'gzip, deflate',
    'User-Agent': 'gzip,  virus total scan python library'
}


class VirusTotal:
    def __init__(self, token, custom_headers=None):
        """
        The API response format is a JSON object containing at least the following two properties:
        response_code: if the item you searched for was not present in VirusTotal's dataset this result
            will be 0. If the requested item is still queued for analysis it will be -2. If the item was indeed
            present and it could be retrieved it will be 1. Any other case is detailed in the following sections.
        verbose_msg: provides verbose information regarding the response_code property.
        Whenever you exceed the public API request rate limit a 204 HTTP status code is returned. If you try to
            perform calls to functions for which you do not have the required privileges an HTTP Error 403
            Forbidden is raised.
        :param token: virus total API token
        :param custom_headers: optional, custom headers
        """
        self.t = token
        if custom_headers is not None:
            self.headers = custom_headers
        else:
            self.headers = HEADERS

    def __get_resp(self, method, file_name=None, file=None, **params):
        """
        get json from request
        :param method: virus total method
        :param file_name: name of the file to scan
        :param file: bytes of the file to scan (open in rb mode)
        :param params: dict api params
        :return:
        """
        if file is not None and file_name is not None:
            f = {'file': (file_name, file)}
            r = requests.post(URL + method, files=f, headers=self.headers, params=params)
            if r.status_code != 200:
                raise VirusTotalException('status_code' + r.text)
            elif r.headers['content-type'] != 'application/json':
                raise VirusTotalException('bad_response' + r.text)
            elif r.status_code == 200 and r.headers['content-type'] == 'application/json':
                try:
                    return r.json()
                except json.decoder.JSONDecodeError:
                    return dict(r.text())
            else:
                raise VirusTotalException('unknown' + r.text)
        else:
            r = requests.post(URL + method, headers=self.headers, params=params)
            if r.status_code != 200:
                raise VirusTotalException('status_code' + r.text)
            elif r.headers['content-type'] != 'application/json':
                raise VirusTotalException('bad_response' + r.text)
            elif r.status_code == 200 and r.headers['content-type'] == 'application/json':
                try:
                    return r.json()
                except json.decoder.JSONDecodeError:
                    return dict(r.text())
            else:
                raise VirusTotalException('unknown' + r.text)

    def scan(self, file, file_name):
        """
        The VirusTotal API allows you to send files. Before performing your submissions we encourage you
        to retrieve the latest report on the files, if it is recent enough you might want to save time and
        bandwidth by making use of it. File size limit is 32MB. If you have a need to scan larger files, please
        contact us, and tell us your use case.
        :param file: bytes of the file to scan (open in rb mode)
        :param file_name: name of the file to scan
        :return: example response:
            {
                'permalink': 'permalink to the file on virus total',
                'resource': u'hash (string)',
                'response_code': response code (int),
                'scan_id': 'scan id (string)',
                'verbose_msg': 'verbose msg (string)',
                'sha256': 'sha256 of the file (string)'
            }
        """
        params = {'apikey': self.t}
        method = 'file/scan'

        return self.__get_resp(method=method, file_name=file_name, file=file, **params)

    def rescan(self, resource):
        """
        The call allows you to rescan files in VirusTotal's file store without having to resubmit them,
        thus saving bandwidth.
        The VirusTotal public API allows you to rescan files that you or other users already sent in the past
        and, hence, are already present in our file store. Before requesting a rescan we encourage you to
        retrieve the latest report on the files, if it is recent enough you might want to save time and bandwidth
        by making use of it.
        :param resource: a md5/sha1/sha256 hash. You can also specify a CSV list made up of a combination of any
            of the three allowed hashes (up to 25 items), this allows you to perform a batch request with
            one single call. Note that the file must already be present in our file store.
        :return:Example response:
        {
            'response_code': response code (int),
            'scan_id': 'hash (string)'
            'permalink': 'permalink to virus total scan',
            'sha256': 'sha256 (string)',
            'resource': 'resource (string)',
        }
        The response_code field of the individual responses will be 1 if the file corresponding to the given
        hash was successfully queued for rescanning. If the file was not present in our file store this code will
        be 0. In the event of some unexpected error the code will be fixed to -1.
        The scan_id field of the individual responses lets us query the report later making use of the file
        report retrieving API. Keep in mind that files sent using the API have the lowest scanning priority,
        depending on VirusTotal's load, it may take several hours before the file is scanned, so query the report
        at regular intervals until the result shows up and do not keep sending the file rescan requests once and
        over again.
        """
        params = {'apikey': self.t, 'resource': resource}
        method = 'file/rescan'

        return self.__get_resp(method=method, **params)

    def get_report(self, resource):
        """
        retrieve scan report
        :param resource: a md5/sha1/sha256 hash will retrieve the most recent report on a given sample.
        You may also specify a scan_id (sha256-timestamp as returned by the file upload API) to access a
        specific report. You can also specify a CSV list made up of a combination of hashes and scan_ids
        (up to 4 items with the standard request rate), this allows you to perform a batch request with one
        single call.
        :return: example response:
        {
            'response_code': response code (int),
            'verbose_msg': 'verbose msg (string)',
            'resource': 'resource (string)',
            'scan_id': 'hash (string)'
            'md5': 'md5',
            'sha1': 'sha1',
            'sha256': 'sha256',
            'scan_date': 'yyyy-mm-hh dd:mm:ss date',
            'positives': number of positive scan (int),
            'total': total scan (int),
            'scans': {
                   'anti virus name': {'detected': BOOL, 'version': 'VERSION', 'result': 'RESULT', 'update': 'DATE'},
                   },
            permalink': 'permalink'
        }
        """
        params = {'apikey': self.t, 'resource': resource}
        method = 'file/report'

        return self.__get_resp(method=method, **params)

    def scan_url(self, url):
        """
        URLs can also be submitted for scanning. Once again, before performing your submission we encourage
        you to retrieve the latest report on the URL, if it is recent enough you might want to save time and
        bandwidth by making use of it.
        :param url: The URL that should be scanned. This parameter accepts a list of URLs (up to 4 with the
        standard request rate) so as to perform a batch scanning request with one single call.
        The URLs must be separated by a new line character.
        :return: example response:
        {
            'response_code': response code (int),
            'verbose_msg': 'verbose msg (string)',
            'scan_id': 'hash of the scan (string)',
            'scan_date': 'yyyy-mm-dd hh:mm:ss date',
            'url': 'url of the site you scanned',
            'permalink': 'permalink to the scan'
        }
        The scan_id parameter of the JSON object can then be used to query for the scan report making use of
        the URL scan report retrieving API described in the next section. Keep in mind that URLs sent using
        the API have the lowest scanning priority, depending on VirusTotal's load, it may take several hours
        before the URL is scanned, so query the report at regular intervals until the result shows up and do
        not keep submitting the URL once and over again.
        """
        params = {'apikey': self.t, 'url': url}
        method = 'url/scan'

        return self.__get_resp(method=method, **params)

    def get_url_report(self, resource, scan=None):
        """
        get url scan result
        :param resource: a URL will retrieve the most recent report on the given URL. You may also specify
            a scan_id (sha256-timestamp as returned by the URL submission API) to access a specific report.
            At the same time, you can specify a CSV list made up of a combination of hashes and scan_ids so
            as to perform a batch request with one single call (up to 4 resources per call with the standard
            request rate). When sending multiples, the scan_ids or URLs must be separated by a new line character.
        :param scan: this is an optional parameter that when set to '1' will automatically submit the URL for
            analysis if no report is found for it in VirusTotal's database. In this case the result will contain
            a scan_id field that can be used to query the analysis report later on.
        :return: example response:
        {
            'response_code': response code (int),
            'verbose_msg': 'verbose msg (string)',
            'scan_id': 'hash (string)'
            'url': 'url of the site you scanned',
            'permalink': 'permalink to the scan'
            'scan_date': 'yyyy-mm-dd hh:mm:ss date',
            'filescan_id': None,
            'positives': number of positive scan (int),
            'total': total scan (int),
            'scans': {
                'anti virus': {'detected': BOOL, 'result': 'RESULT'},
                [... continues ...]
            }
        }
        """
        method = 'url/report'

        if scan is not None and scan == 1:
            params = {'apikey': self.t, 'resource': resource, 'scan': scan}
        elif scan != 1:
            raise ValueError('pass only 1 if you want, else don\'t pass anything')
        else:
            params = {'apikey': self.t, 'resource': resource}

        return self.__get_resp(method=method, **params)


class VirusTotalException(Exception):
    def __init__(self, msg):
        super(VirusTotalException, self).__init__(msg)
