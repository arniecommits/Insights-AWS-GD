# AWS Guard-Duty Integration Lambda Function v0.2 08/11/2021, Arnab Roy
# Needs more work on error logging
# MV API Class - Credit Martin Ohl 

import sys
import os, io, time, base64
import requests
import logging
import json
import csv
import boto3,botocore
from botocore.exceptions import ClientError
from random import randint, randrange
import dateutil.parser as dp
from datetime import datetime, timedelta


ins_dur = int(os.environ["ins_dur"])
bucket_name = os.environ["bucket_name"]
intel_file = os.environ["intel_file"]
aws_region = os.environ["aws_region"]
gd_ti_name = os.environ["gd_ti_name"]
gd_ti_uri = os.environ["gd_ti_uri"]

logger = logging.getLogger()
logger.setLevel(logging.INFO)


class AWS():

    def write_csv_s3(self,content):
        
        s3 = boto3.resource('s3')
        obj = s3.Object(bucket_name, intel_file)
        try:
            obj.load()
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == "404":    
                obj.put(Body=content)
                    
        else: 
                  
            prev_contents = obj.get()['Body'].read().decode('utf-8') 
            final_contents = prev_contents + content    
            obj.put(Body=final_contents)
   

    def guard_duty(self):
        guardduty = boto3.client(service_name = 'guardduty', region_name = aws_region)
        response = guardduty.list_detectors()
        if len(response['DetectorIds']) == 0:
            raise Exception('Failed to read GuardDuty info. Please check if the service is activated')
        detectorId = response['DetectorIds'][0]
        response = guardduty.list_threat_intel_sets(DetectorId=detectorId)
        for setId in response['ThreatIntelSetIds']:
                    response = guardduty.get_threat_intel_set(DetectorId=detectorId, ThreatIntelSetId=setId)
                    
                    if (gd_ti_name == response['Name']):
                        found = True
                        response = guardduty.update_threat_intel_set(
                            Activate=True,
                            DetectorId=detectorId,
                            Location=gd_ti_uri,
                            Name=gd_ti_name,
                            ThreatIntelSetId=setId
                        )
                        if not found:
                            logging.error("Configured Threat intel set not found ")
    
    def get_secret(self):
        logging.info("Extracting API Keys from store")
        secret_name = os.environ["secret_name"]
        region_name = os.environ["aws_region"]

        # Create a Secrets Manager client
        session = boto3.session.Session()
        client = session.client(
            service_name='secretsmanager',
            region_name=region_name
        )

        try:
            get_secret_value_response = client.get_secret_value(
                SecretId=secret_name
            )
            
        except ClientError as e:
            if e.response['Error']['Code'] == 'DecryptionFailureException':
                raise e
            elif e.response['Error']['Code'] == 'InternalServiceErrorException':
                raise e
            elif e.response['Error']['Code'] == 'InvalidParameterException':
                raise e
            elif e.response['Error']['Code'] == 'InvalidRequestException':
                raise e
            elif e.response['Error']['Code'] == 'ResourceNotFoundException':
                raise e
        else:
            
            if 'SecretString' in get_secret_value_response:
                secret = get_secret_value_response['SecretString']
                secret = json.loads(secret)
                return secret    



class MVAPI():
    def __init__(self,secrets):
        self.base_url = 'https://api.mvision.mcafee.com'
        self.mfesession = requests.Session()
        api_key = secrets['mv_api_key']
        client_id = secrets['mv_client_id']
        client_token = secrets['mv_secret']
        
        self.headers = {
            'x-api-key': api_key,
            'Content-Type': 'application/vnd.api+json'
        }

        auth = (client_id, client_token)

        self.auth(auth)
        self.pattern = '%Y-%m-%dT%H:%M:%S'
        self.last_run = (datetime.utcnow() - timedelta(days=ins_dur)).strftime(self.pattern)

    def auth(self, auth):
        try:
            iam_url = "https://iam.mcafee-cloud.com/iam/v1.1/token"

            payload = {
                "grant_type": "client_credentials",
                "scope": "ins.user"
            }

            res = self.mfesession.post(iam_url, headers=self.headers, auth=auth, data=payload)

            if res.ok:
                access_token = res.json()['access_token']
                self.headers['Authorization'] = 'Bearer ' + access_token

                self.mfesession.headers.update(self.headers)
                logging.info('MVISION: Successful authenticated.')
            else:
                raise Exception('HTTP {0} - {1}'.format(str(res.status_code), res.text))

        except Exception as error:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            logging.error("Error in {location}.{funct_name}() - line {line_no} : {error}"
                          .format(location=__name__, funct_name=sys._getframe().f_code.co_name,
                                  line_no=exc_tb.tb_lineno, error=str(error)))

    def get_campaigns(self):
        try:
            next = True

            insights_campaign_url = self.base_url + '/insights/v2/campaigns'
            filters = {
                'fields': 'id,name,description, threat_level_id,kb_article_link,coverage,external_analysis,'
                          'updated_on,external_analysis,is_coat,last_detected_on',
                'limit': 1000
            }
            camp_list = None

            while next is True:
                res = self.mfesession.get(insights_campaign_url, params=filters)
                if res.ok:
                    if camp_list is None:
                        camp_list = res.json()['data']
                    else:
                        camp_list += res.json()['data']

                    if res.json()['links']['next'] is None:
                        next = False
                    else:
                        insights_campaign_url = res.json()['links']['next']
                        filters = None
                else:
                    raise Exception('HTTP {0} - {1}'.format(str(res.status_code), res.text))

            return camp_list

        except Exception as error:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            logging.error("Error in {location}.{funct_name}() - line {line_no} : {error}"
                          .format(location=__name__, funct_name=sys._getframe().f_code.co_name,
                                  line_no=exc_tb.tb_lineno, error=str(error)))

    def get_iocs(self, url):
        try:
            res = self.mfesession.get(url)

            if res.ok:
                return res.json()
            else:
                raise Exception('HTTP {0} - {1}'.format(str(res.status_code), res.text))

        except Exception as error:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            logging.error("Error in {location}.{funct_name}() - line {line_no} : {error}"
                          .format(location=__name__, funct_name=sys._getframe().f_code.co_name,
                                  line_no=exc_tb.tb_lineno, error=str(error)))

    def main(self):
        try:
            main_container = []
            campaigns = self.get_campaigns()
            ioc_count = 0

            
            for campaign in campaigns:
                updated_on = datetime.strptime(campaign['attributes']['updated-on'], '%Y-%m-%dT%H:%M:%S.%fZ')
                check_updated_on = updated_on.strftime('%Y-%m-%dT%H:%M:%S')

                if self.last_run <= check_updated_on:
                    campaign_container = {}
                    campaign_container['name'] = campaign['attributes']['name']
                    campaign_container['description'] = campaign['attributes']['description']
                    campaign_container['threat-level-id'] = campaign['attributes']['threat-level-id']
                    campaign_container['updated-on'] = campaign['attributes']['updated-on']
                    campaign_container['kb-article-link'] = campaign['attributes']['kb-article-link']
                    campaign_container['external-link'] = ",".join(campaign['attributes']['external-analysis']['links'])
                    campaign_container['iocs'] = []

                    iocs = self.get_iocs(campaign['relationships']['iocs']['links']['related'])
                    for ioc in iocs['data']:
                        if ioc['attributes']['type']:
                            tmp_ioc_dict = {
                                'type': ioc['attributes']['type'],
                                'value': ioc['attributes']['value']
                            }
                            campaign_container['iocs'].append(tmp_ioc_dict)

                    ioc_count += len(campaign_container['iocs'])
                    main_container.append(campaign_container)

            logging.info ('MVISION: Retrieved {} Campaigns including {} Indicators updated in the last 1 day.'
                        .format(str(len(main_container)), str(ioc_count)))
            
            return main_container

        except Exception as error:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            logging.error("Error in {location}.{funct_name}() - line {line_no} : {error}"
                          .format(location=__name__, funct_name=sys._getframe().f_code.co_name,
                                  line_no=exc_tb.tb_lineno, error=str(error)))

class FEYECSV():

    def gen_feye_csv(self, campaigns,status):
        csv_columns = ['reportId','title','ThreatScape','productType','publishDate','reportLink','webLink','emailIdentifier',
        'senderAddress','senderName','sourceDomain','sourceIp','subject','recipient','language','fileName','fileSize','fuzzyHash',
        'fileIdentifier','md5','sha1','sha256','description','fileType','packer','userAgent','registry','networkName','asn','cidr','domain',
        'domainTimeOfLookup','networkIdentifier','ip','port','url','protocol','registrantName','registrantEmail','networkType',
        'malwareFamily','observationTime']
        csv_string = io.StringIO()
        writer = csv.DictWriter(csv_string, fieldnames=csv_columns)
        if (status == 0):
            writer.writeheader()
        for campaign in campaigns:
                for ioc in campaign['iocs']:      
                    dict_campaign = {} 
                    repid = time.strftime("%y", time.localtime()) + "-" + str(randint(10000, 99999))
                    dict_campaign['reportId'] = str(repid)
                    dict_campaign['title'] = campaign["name"]
                    dict_campaign['ThreatScape'] = ""
                    dict_campaign['productType'] = "MAL"
                    dict_campaign['publishDate'] = dp.parse(campaign["updated-on"]).timestamp()
                    if(campaign['kb-article-link']):
                        dict_campaign['reportLink'] = campaign['kb-article-link']
                    else:
                        dict_campaign['reportLink'] = 'https://mvision.mcafee.com'
                    if(campaign['external-link']):        
                        dict_campaign['webLink'] = campaign['external-link']
                    else:
                        dict_campaign['webLink'] = ''
                    dict_campaign['emailIdentifier'] = ''
                    dict_campaign['senderAddress'] = ''
                    dict_campaign['senderName'] = ''
                    if ioc['type'] == 'domain' or ioc['type'] == 'hostname':
                        dict_campaign['sourceDomain'] = ioc['value']
                    else:
                        dict_campaign['sourceDomain'] = ''   
                    if ioc['type'] == 'ip':
                        dict_campaign['sourceIp'] = ioc['value']    
                    else:
                        dict_campaign['sourceIp'] = ''
                    dict_campaign['subject'] = ''
                    dict_campaign['recipient'] = ''
                    dict_campaign['language'] = ''
                    dict_campaign['fileName'] = ''
                    dict_campaign['fileSize'] = ''
                    if ioc['type'] == 'imphash' :
                        dict_campaign['fuzzyHash'] = ioc['value']
                    else:
                        dict_campaign['fuzzyHash'] = ''    
                    dict_campaign['fileIdentifier'] = 'Compromised'
                    if ioc['type'] == 'md5':
                        dict_campaign['md5'] = ioc['value']
                    else:
                        dict_campaign['md5'] = ''
                    if ioc['type'] == 'sha1':
                        dict_campaign['sha1'] = ioc['value']
                    else:
                        dict_campaign['sha1'] = ''
                    if ioc['type'] == 'sha256':
                        dict_campaign['sha256'] = ioc['value']
                    else:
                        dict_campaign['sha256'] = ''    
                    dict_campaign['description'] = campaign['description']
                    dict_campaign['fileType'] = ''
                    dict_campaign['packer'] = ''
                    dict_campaign['userAgent'] = ''
                    dict_campaign['registry'] = ''
                    dict_campaign['networkName'] = ''
                    dict_campaign['asn'] = ''
                    dict_campaign['cidr'] = ''
                    if ioc['type'] == 'domain' or ioc['type'] == 'hostname':
                        dict_campaign['domain'] = ioc['value']
                    else:
                        dict_campaign['domain'] = ''   
                    dict_campaign['domainTimeOfLookup'] = ''
                    dict_campaign['networkIdentifier'] = ''
                    if ioc['type'] == 'ip':
                        dict_campaign['ip'] = ioc['value']    
                    else:
                        dict_campaign['ip'] = ''
                    if ioc['type'] == 'ip_port':
                        ip_port = ioc['value'].split(":")
                        dict_campaign['port'] = ip_port[1]
                        dict_campaign['ip'] = ip_port[0]
                    else:
                        dict_campaign['port'] = ''
                    if ioc['type'] == 'url':                       
                        if str(ioc['value']).startswith('https://') or str(ioc['value']).startswith('http://'):
                            pass
                        else:
                            ioc['value'] = 'https://{0}'.format(ioc['value'])       
                        dict_campaign ['url'] = ioc['value']
                    else:
                        dict_campaign ['url'] = ''
                    dict_campaign['protocol'] = ''
                    dict_campaign['registrantName'] = ''
                    dict_campaign['registrantEmail'] = ''
                    dict_campaign['networkType'] = ''
                    dict_campaign['malwareFamily'] = ''
                    dict_campaign['observationTime'] =''
                    writer.writerow(dict_campaign)   
        return csv_string.getvalue()


def lambda_handler(event, context):
    try:
        
        logging.info (" Starting IOC sync with MVISION Insights ")
        aws = AWS()
        secrets = aws.get_secret()
        mvapi = MVAPI(secrets)
        campaigns = mvapi.main()
        s3 = boto3.resource('s3')
        obj = s3.Object(bucket_name, intel_file)
        feye = FEYECSV()
        feye_csv = ""
        try:
            obj.load()
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == "404":
                    logging.info("S3 Bucket/Update File not Found Creating new CSV")
                    feye_csv = feye.gen_feye_csv(campaigns,0)
                        
            else: 
                    logging.error(datetime.now()+ "Unknown Error checking existing S3 bucket")
        else:
            logging.info( "S3 Bucket/Update File found updating CSV")
            feye_csv = feye.gen_feye_csv(campaigns,1)
        
        aws.write_csv_s3(feye_csv)
        aws.guard_duty()
    
    except Exception as error:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        logging.error("Error in {location}.{funct_name}() - line {line_no} : {error}"
                        .format(location=__name__, funct_name=sys._getframe().f_code.co_name,
                                line_no=exc_tb.tb_lineno, error=str(error)))


