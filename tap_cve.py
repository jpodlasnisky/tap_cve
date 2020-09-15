import singer
import urllib.request, json
from datetime import datetime, timezone
from attr import attrs, attrib, asdict

url = 'https://cve.circl.lu/api/last'
now = datetime.now(timezone.utc).isoformat()
schema = {
    'properties':   {
        'Modified': {'type': 'string', 'format': 'date-time'},
        'Published': {'type': 'string', 'format': 'date-time'},
        'access': {'type': 'string'},
        'assigner': {'type': 'string'},
        'cvss': {'type': 'int'},
        'cwe': {'type': 'string'},
        'id': {'type': 'string'},
        'impact': {'type': 'string'},
        'last-modified': {'type': 'string', 'format': 'date-time'},
        'references': {'type': 'list'},
        'summary': {'type': 'string'},
        'vulnerable_configuration': {'type': 'list'},
        'vulnerable_configuration_cpe_2_2': {'type': 'list'},
        'vulnerable_product': {'type': 'list'},
        'timestamp': {'type': 'string', 'format': 'date-time'},
    },
}

@attrs
class LastCVE(object):
    modified = attrib()
    published = attrib()
    access = attrib()
    assigner = attrib()
    cvss = attrib()
    cwe = attrib()
    id = attrib()
    impact = attrib()
    last_modified = attrib()
    references = attrib()
    summary = attrib()
    vulnerable_configuration = attrib()
    vulnerable_configuration_cpe_2_2 = attrib()
    vulnerable_product = attrib()
    timestamp = attrib()

arr_cve = []
dict_cve = {}
with urllib.request.urlopen(url) as json_url:
    data = json.loads(json_url.read().decode('utf-8'))    
    for obj in data:
        for param in obj:
            dict_cve[param] = obj[param]
        dict_cve['timestamp'] = now
        arr_cve.append(dict_cve)

### Agora funciona!
new_json = json.dumps(arr_cve)
print(new_json)

