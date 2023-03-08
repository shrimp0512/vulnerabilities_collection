import requests
import datetime
import xmltodict
from cpeparser import CpeParser 
from collections import defaultdict
import dateutil.parser
import json

def nvd():
    # get current time
    now = datetime.datetime.now()
    pubStartDate = datetime.datetime(now.year,now.month,now.day,now.hour-2,0,0,0)
    pubEndDate = datetime.datetime(now.year,now.month,now.day,now.hour-1,0,0,0)

    # change str
    pubStartDate_Str = pubStartDate.strftime('%Y-%m-%dT%H:00:00.000') + '%2B09:00'
    pubEndDate_Str = pubEndDate.strftime('%Y-%m-%dT%H:00:00.000') + '%2B09:00'

    # NVD base url
    url = 'https://services.nvd.nist.gov/rest/json/cves/2.0'

    # request paylaod
    payload = {
        'lastModStartDate':pubStartDate_Str,
        'lastModEndDate':pubEndDate_Str
    }

    # change payload str
    payload_str = "&".join("%s=%s" % (k,v) for k,v in payload.items())

    # requests http headers
    headers = {
        "content-type":"application/json"
    }

    res = requests.get(url, params=payload_str, headers=headers)
    data = res.json()
    vulnerabilities = defaultdict(list)
    for i in range(len(data['vulnerabilities'])):
        if data['vulnerabilities'][i]['cve']['vulnStatus'] == 'Analyzed' or data['vulnerabilities'][i]['cve']['vulnStatus'] == 'Modified':
            vulnerabilities['source'] = 'NVD'
            vulnerabilities['cve'] = data['vulnerabilities'][i]['cve']['id']
            GMT = datetime.timezone(datetime.timedelta(hours=+9),'GMT')
            utc_time = dateutil.parser.parse(data['vulnerabilities'][i]['cve']['lastModified']).astimezone(GMT)
            utc_time_Str = utc_time.strftime('%Y-%m-%dT%H:%M:%S%z')
            vulnerabilities['last_modified_date'] = utc_time_Str
            vulnerabilities['descriptions'] = data['vulnerabilities'][i]['cve']['descriptions'][0]['value']
            for j in range(len(data['vulnerabilities'][i]['cve']['weaknesses'])):
                vulnerabilities['cwe'] = data['vulnerabilities'][i]['cve']['weaknesses'][j]['description'][0]['value']
            for t in range(len(data['vulnerabilities'][i]['cve']['configurations'][0]['nodes'][0]['cpeMatch'])):
                vulnerabilities['cpe'] = data['vulnerabilities'][i]['cve']['configurations'][0]['nodes'][0]['cpeMatch'][t]['criteria']
                cpe = CpeParser()
                results = cpe.parser(data['vulnerabilities'][i]['cve']['configurations'][0]['nodes'][0]['cpeMatch'][t]['criteria'])
                vulnerabilities['vendor'] = results['vendor']       
                vulnerabilities['product'] = results['product']
                vulnerabilities['product_version'] = results['version']
                if True == ['versionEndIncluding'] in data['vulnerabilities'][i]['cve']['configurations'][0]['nodes'][0]['cpeMatch'][t]:
                    vulnerabilities['versionEndIncluding'] = data['vulnerabilities'][i]['cve']['configurations'][0]['nodes'][0]['cpeMatch'][t]['versionEndIncluding']
            try:
                vulnerabilities['cvss_version'] = data['vulnerabilities'][i]['cve']['metrics']['cvssMetricV31'][0]['cvssData']['version']
                vulnerabilities['cvss_vector'] = data['vulnerabilities'][i]['cve']['metrics']['cvssMetricV31'][0]['cvssData']['vectorString']
                vulnerabilities['cvss_score'] = data['vulnerabilities'][i]['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseScore']   
                vulnerabilities['cvss_severity'] = data['vulnerabilities'][i]['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseSeverity']
                vulnerabilities['cvss_Data_attackVector'] = data['vulnerabilities'][i]['cve']['metrics']['cvssMetricV31'][0]['cvssData']['attackVector']    
                vulnerabilities['attackComplexity'] = data['vulnerabilities'][i]['cve']['metrics']['cvssMetricV31'][0]['cvssData']['attackComplexity']
                vulnerabilities['privilegesRequired'] = data['vulnerabilities'][i]['cve']['metrics']['cvssMetricV31'][0]['cvssData']['privilegesRequired']       
                vulnerabilities['userInteraction'] = data['vulnerabilities'][i]['cve']['metrics']['cvssMetricV31'][0]['cvssData']['userInteraction']  
                vulnerabilities['scope'] = data['vulnerabilities'][i]['cve']['metrics']['cvssMetricV31'][0]['cvssData']['scope']
                vulnerabilities['confidentialityImapact'] = data['vulnerabilities'][i]['cve']['metrics']['cvssMetricV31'][0]['cvssData']['confidentialityImpact']     
                vulnerabilities['integrityImpact'] = data['vulnerabilities'][i]['cve']['metrics']['cvssMetricV31'][0]['cvssData']['integrityImpact']  
                vulnerabilities['availabilityImpact'] = data['vulnerabilities'][i]['cve']['metrics']['cvssMetricV31'][0]['cvssData']['availabilityImpact']     
            except:
                if True == ['cvssMetricV30'] in data['vulnerabilities'][i]['cve']['metrics']:
                    vulnerabilities['cvss_version'] = data['vulnerabilities'][i]['cve']['metrics']['cvssMetricV30'][0]['cvssData']['version']  
                    vulnerabilities['cvss_vector'] = data['vulnerabilities'][i]['cve']['metrics']['cvssMetricV30'][0]['cvssData']['vectorString']
                    vulnerabilities['cvss_score'] = data['vulnerabilities'][i]['cve']['metrics']['cvssMetricV30'][0]['cvssData']['baseScore']   
                    vulnerabilities['cvss_severity'] = data['vulnerabilities'][i]['cve']['metrics']['cvssMetricV30'][0]['cvssData']['baseSeverity']
                    vulnerabilities['cvss_Data_attackVector'] = data['vulnerabilities'][i]['cve']['metrics']['cvssMetricV30'][0]['cvssData']['attackVector']    
                    vulnerabilities['attackComplexity'] = data['vulnerabilities'][i]['cve']['metrics']['cvssMetricV30'][0]['cvssData']['attackComplexity']
                    vulnerabilities['privilegesRequired'] = data['vulnerabilities'][i]['cve']['metrics']['cvssMetricV30'][0]['cvssData']['privilegesRequired']       
                    vulnerabilities['userInteraction'] = data['vulnerabilities'][i]['cve']['metrics']['cvssMetricV30'][0]['cvssData']['userInteraction']  
                    vulnerabilities['scope'] = data['vulnerabilities'][i]['cve']['metrics']['cvssMetricV30'][0]['cvssData']['scope']
                    vulnerabilities['confidentialityImapact'] = data['vulnerabilities'][i]['cve']['metrics']['cvssMetricV30'][0]['cvssData']['confidentialityImpact']     
                    vulnerabilities['integrityImpact'] = data['vulnerabilities'][i]['cve']['metrics']['cvssMetricV30'][0]['cvssData']['integrityImpact']  
                    vulnerabilities['availabilityImpact'] = data['vulnerabilities'][i]['cve']['metrics']['cvssMetricV30'][0]['cvssData']['availabilityImpact']
                else:
                    vulnerabilities['cvss_version'] = data['vulnerabilities'][i]['cve']['metrics']['cvssMetricV2'][0]['cvssData']['version']  
                    vulnerabilities['cvss_vector'] = data['vulnerabilities'][i]['cve']['metrics']['cvssMetricV2'][0]['cvssData']['vectorString']
                    vulnerabilities['cvss_score'] = data['vulnerabilities'][i]['cve']['metrics']['cvssMetricV2'][0]['cvssData']['baseScore']   
                    vulnerabilities['cvss_severity'] = data['vulnerabilities'][i]['cve']['metrics']['cvssMetricV2'][0]['cvssData']['baseSeverity']
                    vulnerabilities['cvss_accsessVector'] = data['vulnerabilities'][i]['cve']['metrics']['cvssMetricV2'][0]['cvssData']['attackVector']    
                    vulnerabilities['cvss_accessComplexity'] = data['vulnerabilities'][i]['cve']['metrics']['cvssMetricV2'][0]['cvssData']['attackComplexity']
                    vulnerabilities['cvss_authentication'] = data['vulnerabilities'][i]['cve']['metrics']['cvssMetricV2'][0]['cvssData']['privilegesRequired']       
                    vulnerabilities['confidentialityImapact'] = data['vulnerabilities'][i]['cve']['metrics']['cvssMetricV2'][0]['cvssData']['confidentialityImpact']     
                    vulnerabilities['integrityImpact'] = data['vulnerabilities'][i]['cve']['metrics']['cvssMetricV2'][0]['cvssData']['integrityImpact']  
                    vulnerabilities['availabilityImpact'] = data['vulnerabilities'][i]['cve']['metrics']['cvssMetricV2'][0]['cvssData']['availabilityImpact']
            send_graylog(vulnerabilities)
            
def send_graylog(vulnerabilities):
    #The URL should be in your enviroment
    url = "http://xxx.xx.x.x:xxxxx/gelf"
    headers = {
        "Content-Type":"application/json"
    }
    data = {
        "version" : "1.1", 
        "host" : "NVD", 
        "short_message" : "nvd_vulnerabilities",
        "cve":vulnerabilities['cve'],
        "last_modified_date":vulnerabilities['last_modified_date'],
        "descriptions":vulnerabilities['descriptions'],
        "cwe":vulnerabilities['cwe'],
        "cpe":vulnerabilities['cpe'],
        "vendor":vulnerabilities['vendor'],
        "product":vulnerabilities['product'],
        "product_vension":vulnerabilities['product_version'],
        "cvss_version":vulnerabilities['cvss_version'],
        "cvss_vector":vulnerabilities['cvss_vector'],
        "cvss_score":vulnerabilities['cvss_score'],
        "cvss_severity":vulnerabilities['cvss_severity'],
        "cvss_Data_attackVector":vulnerabilities['cvss_Data_attackVector'],
        "attackComplexity":vulnerabilities['attackComplexity'],
        "privilegesRequired":vulnerabilities['privilegesRequired'],
        "userInteraction":vulnerabilities['userInteraction'],
        "scope":vulnerabilities['scope'],
        "confidentialityImpact":vulnerabilities['confidentialityImapact'],
        "integrityImapct":vulnerabilities['integrityImpact'],
        "availabilityImpact":vulnerabilities['availabilityImpact']
    }
    
    json_data = json.dumps(data).encode("utf-8")
    res = requests.post(url, data=json_data, headers=headers)
    print(res)
    
def main():
    nvd()
    
if __name__ == "__main__":
    main()
