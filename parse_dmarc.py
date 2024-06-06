import glob
import os
import shutil
from datetime import datetime
import xml.etree.ElementTree as ET

dmarc_report_file_path = "dmarc_report.txt"

if os.path.exists(dmarc_report_file_path):
    f = open(dmarc_report_file_path, "a")
else:
    f = open(dmarc_report_file_path, "w")

dmarc_files = glob.glob(os.path.join("data", "*.xml"))
path_after_parsing = os.path.join("data", "already_parsed")
os.makedirs(path_after_parsing, exist_ok=True)

for dmarc_file in dmarc_files:
    try:
        tree = ET.parse(dmarc_file)
        f.write("----\n")
        f.write("----\n")
    except Exception as e:
        continue

    filename = os.path.basename(dmarc_file)
    shutil.move(dmarc_file, os.path.join(path_after_parsing, filename))
    root = tree.getroot()
    metadata = root.find("report_metadata")
    org_name = metadata.find("org_name").text if metadata.find("org_name") is not None else -1
    org_email = metadata.find("email").text if metadata.find("email") is not None else -1
    date_range = metadata.find("date_range") if metadata.find("date_range") is not None else -1
    if date_range != -1:
        begin_date = int(date_range.find("begin").text)
        end_date = int(date_range.find("end").text)

        begin_date = datetime.fromtimestamp(begin_date)
        end_date = datetime.fromtimestamp(end_date)
    
    f.write(f"ORGANIZATION_NAME: {org_name}\n")
    f.write(f"ORGANIZATION_EMAIL: {org_email}\n")
    f.write(f"BEGIN_DATE: {begin_date}\n")
    f.write(f"END_DATE: {end_date}\n")

    policy_published = root.find("policy_published")
    if policy_published is not None:
        domain = policy_published.find("domain").text if policy_published.find("domain") is not None else -1
        dkim_policy = policy_published.find("adkim").text if policy_published.find("adkim") is not None else -1
        if dkim_policy == "r" and dkim_policy != -1:
            dkim_policy = "relaxed"
        spf_policy = policy_published.find("aspf").text if policy_published.find("aspf") is not None else -1
        if spf_policy == "r" and spf_policy != -1:
            spf_policy = "relaxed"
        dmarc_policy_top_domain = policy_published.find("p").text if policy_published.find("p") is not None else -1
        dmarc_policy_subdomain = policy_published.find("sp").text if policy_published.find("sp") is not None else -1
    
    f.write(f"DOMAIN: {domain}\n")
    f.write(f"DKIM_POLICY: {dkim_policy}\n")
    f.write(f"SPF_POLICY: {spf_policy}\n")
    f.write(f"DMARC_POLICY_TOP_DOMAIN: {dmarc_policy_top_domain}\n")
    f.write(f"DMARC_POLICY_SUB_DOMAIN: {dmarc_policy_subdomain}\n")

    f.write("----\n")
                              
    records = root.findall("record")
    f.write("SOURCE_IP\tCOUNT\tPOLICY_ACTION\tDKIM_RESULT\tSPF_RESULT\tFROM_DOMAIN\tTO_DOMAIN\tFROM_HEADER\tDOMAIN_CHECKED\tSPF_SCOPE\tSPF_RESULT\n")
    for record in records:
        row = record.find("row")
        if row is not None:
            source_ip = row.find("source_ip").text if row.find("source_ip") is not None else -1
            count = row.find("count").text if row.find("count") is not None else -1
            policy_action = row.find("policy_evaluated/disposition").text if row.find("policy_evaluated/disposition") is not None else -1
            dkim_result = row.find("policy_evaluated/dkim").text if row.find("policy_evaluated/dkim") is not None else -1
            spf_result = row.find("policy_evaluated/spf").text if row.find("policy_evaluated/spf") is not None else -1

            identifiers = record.find("identifiers")
            if identifiers is not None:
                from_domain = identifiers.find("envelope_from").text if identifiers.find("envelope_from") is not None else -1
                to_domain = identifiers.find("envelope_to").text if identifiers.find("envelope_to") is not None else -1
                from_header = identifiers.find("header_from").text if identifiers.find("header_from") is not None else -1

            auth_results = record.find("auth_results")
            if auth_results is not None:
                spf_auth_results = auth_results.find("spf")
                if spf_auth_results is not None:
                    domain_checked = spf_auth_results.find("domain").text if spf_auth_results.find("domain") is not None else -1
                    spf_scope = spf_auth_results.find("scope").text if spf_auth_results.find("scope") is not None else -1
                    spf_result = spf_auth_results.find("result").text if spf_auth_results.find("result") is not None else -1
        
        f.write(f"{source_ip}\t{count}\t{policy_action}\t{dkim_result}\t{spf_result}\t{from_domain}\t{to_domain}\t{from_header}\t{domain_checked}\t{spf_scope}\t{spf_result}\n")

f.close()