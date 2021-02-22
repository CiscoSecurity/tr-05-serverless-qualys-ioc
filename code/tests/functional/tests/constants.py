TITLE = (
    'Known Good',
    'Remediated',
    'Suspicious Low File event',
    'Suspicious Low Process event',
    'Suspicious Low Network event',
    'Suspicious Medium File event',
    'Suspicious Medium Process event',
    'Suspicious Medium Network event',
    'Malicious File event',
    'Malicious Process event',
    'Malicious Network event'
)
MODULE_NAME = 'Qualys IOC'
CONFIDENCE = 'High'
SEVERITY = ('High', 'Info', 'Low', 'Medium', 'None', 'Unknown')
OBSERVABLE_HUMAN_READABLE_NAME = {
    'ip': 'IP',
    'sha256': 'SHA256',
    'md5': 'MD5',
    'file_name': 'file name',
    'domain': 'domain'
}
CTR_ENTITIES_LIMIT = 100
