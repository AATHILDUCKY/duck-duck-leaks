# git_secret.py
import re
import os
import git
import tempfile

# Define regex patterns for sensitive information
patterns = {
    'google_api': r'AIza[0-9A-Za-z-_]{35}',
    'google_oauth': r'ya29\.[0-9A-Za-z\-_]+',
    'google_api_key': r"(?i)AIza[0-9A-Za-z\\-_]{35}",
    'google_recaptcha_key': r"(?i)(\"|\')6[0-9a-zA-Z-_]{39}(\"|\')",
    'generic_api_key_inurl': r'https?://[^\s]+[?&](key|api_key|apikey|apiKey|ApiKey|access_token|auth|authentication|token|secret|client_id|client_secret|API_KEY|private_key)=[a-zA-Z0-9_\-]+',
    'generic_api_key_incode': r'\b(key|api_key|apikey|apiKey|ApiKey|access_token|auth|authentication|token|secret|client_id|client_secret|API_KEY|private_key)\s*=\s*["\']([a-zA-Z0-9_\-]+)["\']\s*;?',
    'firebase'  : r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}',
    'firebase_api_key_pattern' : r'AIza[0-9A-Za-z-_]{35}',
    'firebase_database_url_pattern' : r'https://[a-z0-9-]+\.firebaseio\.com',
    'Firebase API Key': r"(?i)firebase_api_key[:=]\s*['\"]?([a-zA-Z0-9]{40})['\"]?",

    'recaptcha_secret_key_pattern' : r'(?i)(?:=|\'|")?(6L[0-9A-Za-z]{39})(?:=|\'|")?',


    #'openai_api_key_pattern' : r'(?i)sk-[a-zA-Z0-9]{48}',
    'openai_api_key': r'sk-[a-zA-Z0-9]{48}',


    'AWS Access Key ID': r'\bAKIA[0-9A-Z]{16}\b',
    'AWS Access Key ID': r"(?i)aws_access_key_id[:=]\s*['\"]?([A-Z0-9]{20})['\"]?",
    'AWS Secret Access Key': r"(?i)aws_secret_access_key[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
    'aws_access_key_id': r'AWS_ACCESS_KEY_ID=([A-Z0-9]{20})',
    'aws_secret_access_key': r'AWS_SECRET_ACCESS_KEY=([A-Za-z0-9/+=]{40})',
    'aws_access_key_id': r'aws_access_key_id\s*=\s*([A-Za-z0-9]{20})',
    'aws_secret_access_key': r'aws_secret_access_key\s*=\s*([A-Za-z0-9/+=]{40})',


    'AWS_Access_Key': r'AKIA[0-9A-Z]{16}',
    'AWS_Secret_Key': r'(?i)aws_secret_access_key[\s:=\'"]*[A-Za-z0-9\/+=]{40}',
    'amazon_aws_access_key_id' : r'A[SK]IA[0-9A-Z]{16}',
    'amazon_mws_auth_toke' : r'amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
    'amazon_aws_url' : r's3\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\.s3\.amazonaws.com',
    'azure_appinsights_api_key': r'x-api-key:\s*([a-zA-Z0-9-_]{32})',
    'azure_appinsights_app_id': r'https://api\.applicationinsights\.io/v1/apps/([a-zA-Z0-9-]{36})',


    'facebook_access_token' : r'EAACEdEose0cBA[0-9A-Za-z]+',
    'authorization_bearer' : r'bearer [a-zA-Z0-9_\-\.=:_\+\/]{5,100}',
    #'authorization_api' : r'api[key|_key|\s+]+[a-zA-Z0-9_\-]{5,100}',
    'mailgun_api_key' : r'key-[0-9a-zA-Z]{32}',

    'twilio_api_key_pattern' : r'(?:=|["\'])?(SK[0-9a-fA-F]{32})(?:["\']|;)?',
    'twilio_account_sid_pattern' : r'(?:=|["\'])?(AC[0-9a-fA-F]{32})(?:["\']|;)?',
    'twilio_app_sid_pattern' : r'(?:=|["\'])?(AP[0-9a-fA-F]{32})(?:["\']|;)?',
    'Twilio Account SID': r"(?i)twilio_account_sid[:=]\s*['\"]?([A-Za-z0-9]{34})['\"]?",
    'Twilio Auth Token': r"(?i)twilio_auth_token[:=]\s*['\"]?([a-zA-Z0-9]{32})['\"]?",


    'paypal_braintree_access_token' : r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',
    'square_oauth_secret' : r'sq0csp-[ 0-9A-Za-z\-_]{43}|sq0[a-z]{3}-[0-9A-Za-z\-_]{22,43}',
    'square_access_token' : r'sqOatp-[0-9A-Za-z\-_]{22}|EAAA[a-zA-Z0-9]{60}',
    'square_oauth_token_pattern' : r'sandbox-sq0[a-z0-9-]{22,44}',

    'stripe_standard_api' : r'sk_live_[0-9a-zA-Z]{24}',
    'stripe_restricted_api' : r'rk_live_[0-9a-zA-Z]{24}',
    'picatic_api_key_pattern' : r'(?i)sk_live_[0-9a-z]{32}',
    
    'URL API Key': r"https?://[^\s]+[?&](api[-_]?key|key|token|access[-_]?token)=\"[^\"]+\"",
    #'General Token': r"(?i)(token|access[-_]?token|auth[-_]?token|client[-_]?secret|secret[-_]?key|private[-_]?key)[:=]\s*['\"]?([a-zA-Z0-9_\-]+)['\"]?",
    
    # GitHub keys
    'GitHub Token': r"gh[pous]_[A-Za-z0-9_]{36,40}",
    'GitHub Client ID': r"(?i)github_client_id[:=]\s*['\"]?([a-zA-Z0-9]{20})['\"]?",
    'GitHub Client Secret': r"(?i)github_client_secret[:=]\s*['\"]?([a-zA-Z0-9]{40})['\"]?",
    'github_access_token' : r'[a-zA-Z0-9_-]*:[a-zA-Z0-9_\-]+@github\.com*',
    'gitlab_access_token_pattern' : r'glpat-[0-9a-zA-Z\-]{20}',
    'github_oauth_token_pattern' : r'ghp_[0-9a-zA-Z]{36}',
    'github_private_ssh_key': r'-----BEGIN OPENSSH PRIVATE KEY-----\s([A-Za-z0-9+/=]+)\s-----END OPENSSH PRIVATE KEY-----',
    'github_client_id': r'client_id=([a-zA-Z0-9]{20})',
    'github_client_secret': r'client_secret=([a-zA-Z0-9]{40})',

    
    # General API Key patterns
    'Generic API Key': r"(?i)(api[-_]?key|access[-_]?key|secret[-_]?key|client[-_]?id|client[-_]?secret)[:=]\s*['\"]?([a-zA-Z0-9_\-]{16,64})['\"]?",
    
    # OAuth & Access Tokens
    'OAuth Access Token': r"(?i)access_token[:=]\s*['\"]?([a-zA-Z0-9\-._~+/]+=*)['\"]?",
    'Bearer Token': r"(?i)bearer\s+[a-zA-Z0-9\-._~+/]+=*",
    
    # Social Media & Cloud Platform Tokens
    'Facebook Access Token': r"(?i)facebook_access_token[:=]\s*['\"]?([a-zA-Z0-9]{64})['\"]?",
    'Instagram Access Token': r"(?i)instagram_access_token[:=]\s*['\"]?([a-zA-Z0-9]{64})['\"]?",
    'Twitter API Key': r"(?i)twitter_api_key[:=]\s*['\"]?([a-zA-Z0-9]{25,35})['\"]?",
    'Twitter API Secret': r"(?i)twitter_api_secret[:=]\s*['\"]?([a-zA-Z0-9]{35,45})['\"]?",
    'foursquare_api_key_pattern' : r'(?i)FSQ[a-zA-Z0-9]{32}',
    
    
    # Payment Platform Credentials
    'Stripe Secret Key': r"(?i)sk_live_[0-9a-zA-Z]{24}",
    #'Stripe Publishable Key': r"(?i)pk_live_[0-9a-zA-Z]{24}",
    'PayPal Client ID': r"(?i)paypal_client_id[:=]\s*['\"]?([a-zA-Z0-9]{16,64})['\"]?",
    'PayPal Secret': r"(?i)paypal_secret[:=]\s*['\"]?([a-zA-Z0-9]{32})['\"]?",
    'shopify_access_token_pattern' : r'shpat_[0-9a-fA-F]{32}',
    'sendgrid_api_key_pattern' : r'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}',
    #'twitch_api_key_pattern' : r'[a-z0-9]{30}',
    'teams_webhook_pattern' : r'https://[a-zA-Z0-9]+\.webhook\.office\.com/webhookb2/[A-Za-z0-9-]+@[A-Za-z0-9-]+/IncomingWebhook/[A-Za-z0-9-]+/[A-Za-z0-9-]+',
    'mailchimp_api_key_pattern' : r'(?i)[a-z0-9]{32}-us[0-9]{1,2}',



    # SaaS Service Tokens and Keys
    'SendGrid API Key': r"(?i)sendgrid_api_key[:=]\s*['\"]?([a-zA-Z0-9]{40})['\"]?",
    'Slack API Token': r"(?i)xox[baprs]-[0-9a-zA-Z]{10,48}",
    'Slack Webhook URL': r"https?://hooks.slack.com/services/[A-Za-z0-9/_]+",
    'Microsoft Azure SAS': r"(?i)SharedAccessSignature\s*sig=[a-zA-Z0-9%+/]+",

    'Algolia API Key': r"(?i)algolia_api_key[:=]\s*['\"]?([a-zA-Z0-9]{32})['\"]?",
    'api_key_pattern1' : r"x-algolia-api-key:\s*([a-zA-Z0-9]+)",
    'api_key_pattern2' : r"x-algolia-api-key:\s*([a-zA-Z0-9]{32})",
    'api_key_pattern3' : r"x-algolia-api-key:\s*([a-zA-Z0-9]{32})",
    'app_id_pattern' : r"x-algolia-application-id:\s*([a-zA-Z0-9]+)",
    'app_id_pattern' : r"x-algolia-application-id:\s*([a-zA-Z0-9]{8})",

    'abtasty_api_key': r'x-api-key:\s*[a-zA-Z0-9]{32}',
    'custom_token': r'"token":"([a-zA-Z0-9_-]{43})"',
    'api_key': r'\?key=([a-zA-Z0-9]{39})',
    'API key': r'[A-Za-z0-9]{32}:[A-Za-z0-9]{32}',
    'API_key': r'API_Key:\s*([a-zA-Z0-9-_]{32})',
    'x_api_key': r'x-api-key:\s*([a-zA-Z0-9]{32})',
    'private_key_id': r'"private_key_id":\s*"([a-zA-Z0-9_-]+)"',
    'private_key': r'"private_key":\s*"([^"]+)"',
    'access_token': r'accounts\?access_token=([a-zA-Z0-9_-]+)',
    'secret_key': r'Secret_Key:\s*([a-zA-Z0-9-_]{32})',
    'access_token': r'access_token=([a-zA-Z0-9]{32,})',
    'api_key': r'api_key=([a-zA-Z0-9]{32})',
    'application_key': r'application_key=([a-zA-Z0-9]{32})',
    'api_token': r'auth_token=([a-zA-Z0-9]{32})',
    'private_token': r'private_token=([a-zA-Z0-9_-]+)',
    'access_key': r'access_key=([a-zA-Z0-9_-]+)',
    'key': r'\?Key=([a-zA-Z0-9_-]+)',
    'client_secret': r'"client_secret":\s?"([a-zA-Z0-9_-]+)"',
    'secret1': r'"secret\s*:\s*"([^"]+)"',
    'consumer_key': r'CONSUMER_KEY\s*:\s*([a-zA-Z0-9_-]+)',
    'consumer_secret': r'CONSUMER_SECRET\s*:\s*([a-zA-Z0-9_-]+)',
    'api_key': r'api_key\s*:\s*\'([a-zA-Z0-9_-]+)\'',
    'key': r'"key"\s*:\s*"([a-zA-Z0-9_-]+)"',
    #'base64_encoded': r'\b([A-Za-z0-9+/=]{4})*([A-Za-z0-9+/=]{2,3})\b',
    'mongo_password': r'mongoPassword\s*:\s*"([^"]+)"',
    'authorization_token': r'payload\["Authorization"\]\s*=\s*"token\s([a-f0-9]{40})"',
    'x_api_key': r'\("x-api-key",\s*"([A-Za-z0-9]+)"\)',
    'client_id': r'client_id\s*=\s*([A-Za-z0-9-_]+)',


    'twitter_consumer_key': r'TWITTER_CONSUMER_KEY\s*=\s*([a-zA-Z0-9]{35})',
    'twitter_consumer_secret': r'TWITTER_CONSUMER_SECRET\s*=\s*([a-zA-Z0-9]{50})',
    'twitter_access_key': r'TWITTER_ACCESS_KEY\s*=\s*([0-9]{8}-[a-zA-Z0-9]{30})',
    'twitter_access_secret': r'TWITTER_ACCESS_SECRET\s*=\s*([a-zA-Z0-9]{50})',
    'mixpanel_token': r'MIXPANEL_TOKEN\s*=\s*([a-f0-9]{32})',
    'twitter_consumer_key': r'twitter_consumer_key\s*=\s*([a-z0-9]{35})',
    'twitter_consumer_secret': r'twitter_consumer_secret\s*=\s*([a-z0-9]{50})',
    'twitter_access_key': r'twitter_access_key\s*=\s*([0-9]{8}-[a-z0-9]{30})',
    'twitter_access_secret': r'twitter_access_secret\s*=\s*([a-z0-9]{50})',
    'mixpanel_token': r'mixpanel_token\s*=\s*([a-f0-9]{32})',
    'twitter_consumer_key': r'\btwitter_consumer_key\b|\bTWITTER_CONSUMER_KEY\b',
    'twitter_consumer_secret': r'\btwitter_consumer_secret\b|\bTWITTER_CONSUMER_SECRET\b',
    'twitter_access_key': r'\btwitter_access_key\b|\bTWITTER_ACCESS_KEY\b',
    'twitter_access_secret': r'\btwitter_access_secret\b|\bTWITTER_ACCESS_SECRET\b',
    'mixpanel_token': r'\bmixpanel_token\b|\bMIXPANEL_TOKEN\b',

    'api_secret': r'\b(api_secret|API_SECRET)\b',
    'apidocs': r'\b(apidocs|APIDOCS)\b',
    'apiSecret': r'\b(apiSecret|APISECRET)\b',
    'app_key': r'\b(app_key|APP_KEY)\b',
    'app_secret': r'\b(app_secret|APP_SECRET)\b',
    'appkey': r'\b(appkey|APPKEY)\b',
    'appkeysecret': r'\b(appkeysecret|APPKEYSECRET)\b',
    'application_key': r'\b(application_key|APPLICATION_KEY)\b',
    'appsecret': r'\b(appsecret|APPSECRET)\b',
    'authorizationToken': r'\b(authorizationToken|AUTHORIZATIONTOKEN)\b',
    'bashrc_password': r'\b(bashrc_password|BASHRC_PASSWORD)\b',
    'bucket_password': r'\b(bucket_password|BUCKET_PASSWORD)\b',
    'codecov_token': r'\b(codecov_token|CODECOV_TOKEN)\b',
    'gmail_password': r'\b(gmail_password|GMAIL_PASSWORD)\b',
    'gmail_username': r'\b(gmail_username|GMAIL_USERNAME)\b',
    'herokuapp': r'\b(herokuapp|HEROKUAPP)\b',
    'jekyll_github_token': r'\b(JEKYLL_GITHUB_TOKEN|jekyll_github_token)\b',
    'ldap_password': r'\b(ldap_password|LDAP_PASSWORD)\b',
    'ldap_username': r'\b(ldap_username|LDAP_USERNAME)\b',
    'npmrc_auth': r'\b(npmrc _auth|NPMRC _AUTH)\b',
    'oauth_token': r'\b(oauth_token|OAUTH_TOKEN)\b',
    'slack_api': r'\b(slack_api|SLACK_API)\b',
    'slack_token': r'\b(slack_token|SLACK_TOKEN)\b',
    'sql_password': r'\b(sql_password|SQL_PASSWORD)\b',
    'ssh': r'\b(ssh|SSH)\b',
    'ssh2_auth_password': r'\b(ssh2_auth_password|SSH2_AUTH_PASSWORD)\b',
    'xoxb': r'\b(xoxb|XOXB)\b',
    'xoxp': r'\b(xoxp|XOXP)\b',
    'aws_secret_key': r'\b(aws_secret_key|AWS_SECRET_KEY)\b',
    'bucket_name': r'\b(bucket_name|BUCKET_NAME)\b',
    's3_access_key_id': r'\b(S3_ACCESS_KEY_ID|s3_access_key_id)\b',
    's3_bucket': r'\b(S3_BUCKET|s3_bucket)\b',
    's3_endpoint': r'\b(S3_ENDPOINT|s3_endpoint)\b',
    's3_secret_access_key': r'\b(S3_SECRET_ACCESS_KEY|s3_secret_access_key)\b',
    'wordpress_db_password': r'\b(WORDPRESS_DB_PASSWORD|wordpress_db_password)\b',
    'redis_password': r'\b(redis_password|REDIS_PASSWORD)\b',
    'root_password': r'\b(root_password|ROOT_PASSWORD)\b',
    'homebrew_github_api_token': r'\b(HOMEBREW_GITHUB_API_TOKEN|homebrew_github_api_token)\b',
    'huggingface_token': r'login\("your_huggingface_token_here"\)',
    'api_access_token': r'api\.set_access_token\("your_api_key_here"\)',
    'hf_api_token_env': r'os\.environ\["HF_API_TOKEN"\]\s*=\s*"your_api_key_here"',
    'hf_api_token_assignment': r'HF_API_TOKEN\s*=\s*"your_api_key_here"',
    'hf_api_token_assignment_no_quotes': r'HF_API_TOKEN\s*=\s*your_api_key_here',
    'hf_api_token_getenv': r'token\s*=\s*os\.getenv\("HF_API_TOKEN"\)',
    'use_auth_token': r'use_auth_token\s*=\s*"your_api_key_here"',


    'ipstack_api_key': r'\/[a-zA-Z0-9._%+-]+?\?access_key=([a-zA-Z0-9]{32})',
    'appcenter_api_token': r'X-Api-Token:\s*([a-zA-Z0-9-_]{40})',
    'facebook_access_token': r'access_token=([a-zA-Z0-9%_]{100,})',
    'hubspot_api_key': r'hapikey=([a-zA-Z0-9]{32})',
    'infura_api_key': r'infura\.io/v[0-9]+/([a-fA-F0-9]{32})',
    'npm_token': r'NPM_TOKEN="([a-f0-9-]{36})"',
    'youtube_api_key': r'https:\/\/www\.googleapis\.com\/youtube\/v3\/[^\s?&]+(?:\?[^&]+)?&key=AIza[A-Za-z0-9_-]{33}',
    'linkedin_oauth_url': r'https:\/\/www\.linkedin\.com\/oauth\/v2\/accessToken\?code=([a-zA-Z0-9_-]+)&redirect_uri=([^&]+)&client_id=([^&]+)&client_secret=([^&]+)',
    'shodan_api_key': r'https:\/\/api\.shodan\.io\/shodan\/host\/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\?key=([a-zA-Z0-9]{32})',
    'bazaarvoice_passkey': r'\?conversationspasskey=([a-zA-Z0-9]{32})',
    'weblate_secret_key': r'"WEBLATE_SECRET_KEY",\s?"([a-zA-Z0-9!#%&=+_-]{50,})"',
    'access_key_secret': r'access-key-secret\s*=\s*<([a-zA-Z0-9_-]+)>',
    'access_key_id': r'access-key-id\s*=\s*<([a-zA-Z0-9_-]+)>',
    'password': r'password\s*[:=]?\s*([A-Za-z0-9!@#$%^&*(),.?":{}|<>_\-+=~;`/\\[\]<>]*?)',
    'token': r'"token"\s*:\s*"([A-Za-z0-9-_]+)"',
    'password': r'"password"\s*:\s*["\']?([^\s]+)["\']?',
    'pwd': r'"pwd"\s*:\s*["\']?([^\s]+)["\']?',
    'pword': r'"pword"\s*:\s*["\']?([^\s]+)["\']?',
    'mail_host': r'MAIL_HOST\s*=\s*["\']?([^\s]+)["\']?',
    'mail_username': r'MAIL_USERNAME\s*=\s*["\']?([^\s]+)["\']?',
    'mail_password': r'MAIL_PASSWORD\s*=\s*["\']?([^\s]+)["\']?',

    'pusher_app_id': r'PUSHER_APP_ID\s*=\s*["\']?([^\s]+)["\']?',
    'pusher_app_key': r'PUSHER_APP_KEY\s*=\s*["\']?([^\s]+)["\']?',
    'pusher_app_secret': r'PUSHER_APP_SECRET\s*=\s*["\']?([^\s]+)["\']?',

    'mix_pusher_app_key': r'MIX_PUSHER_APP_KEY\s*=\s*["\']?([^\s]+)["\']?',


    'database_host': r'"DATABASE_HOST"\s*:\s*"([A-Za-z0-9.-]+)"',
    'database_user': r'"DATABASE_USER"\s*:\s*"([A-Za-z0-9_]+)"',
    'database_password': r'"DATABASE_PASSWORD"\s*:\s*"([A-Za-z0-9!@#$%^&*()_+={}\[\]:;,.<>?/~`|\\-]+)"',
    'database_name': r'"DATABASE_NAME"\s*:\s*"([A-Za-z0-9_]+)"',
    'database_host': r'"DB_HOST"\s*:\s*"([A-Za-z0-9.-]+)"',
    'database_user': r'"DB_USER"\s*:\s*"([A-Za-z0-9_]+)"',
    'database_password': r'"DB_PASSWORD"\s*:\s*"([A-Za-z0-9!@#$%^&*()_+={}\[\]:;,.<>?/~`|\\-]+)"',
    'database_name': r'"DB_NAME"\s*:\s*"([A-Za-z0-9_]+)"',
    'mysql_db_port': r'DATABASE_PORT\s*=\s*(\d{4,5})',
    'mysql_db_port': r'DB_PORT\s*=\s*(\d{4,5})',
    'mysql_connection_string': r'mysql://([a-zA-Z0-9_-]+):([a-zA-Z0-9!@#$%^&*()_+={}:;,.?<>~-]+)@([a-zA-Z0-9.-]+):(\d{4,5})/([a-zA-Z0-9_-]+)',
    'mysql_access_key': r'mysql_access_key\s*=\s*["\']?([a-zA-Z0-9_-]+)["\']?',
    'mysql_secret_key': r'mysql_secret_key\s*=\s*["\']?([a-zA-Z0-9!@#$%^&*()_+={}:;,.?<>~-]+)["\']?',
    

    'oauth_token': r'"OAUTH_TOKEN"\s*:\s*"([A-Za-z0-9-_]{30,100})"',
    'username': r'"username"\s*:\s*"([A-Za-z0-9_]+)"',
    'api_secret': r"api_secret\s*=\s*'([A-Za-z0-9_!@#$%^&*()\-+=<>]+)'",
    'owner_id': r'"owner_id"\s*:\s*"[a-zA-Z0-9_\.\-]*"',
    'repo_access_token': r'"repo_access_token"\s*:\s*"[a-zA-Z0-9_\.\-]*"',
    'project_access_token': r'"project_access_token"\s*:\s*"[a-zA-Z0-9_\.\-]*"',
    'workspace_access_token': r'"workspace_access_token"\s*:\s*"[a-zA-Z0-9_\.\-]*"',
    'bitbucket_repo_access': r'bitbucket\.com/credential/[a-zA-Z0-9_\.\-]*',
    'bitbucket_project': r'bitbucket\.com/project/\{[a-f0-9\-]{36}\}',
    'bitbucket_workspace': r'bitbucket\.com/workspace/\{[a-f0-9\-]{36}\}',


    'email': r'<email>\s*([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,})\s*</email>',
    'password': r'<password>\s*([A-Za-z0-9!@#$%^&*()_+={}\[\]:;,.<>?/~`|\\-]+)\s*</password>',
    'api_key': r'<api_key>\s*([A-Za-z0-9-_]{32,64})\s*</api_key>',
    'access_token': r'<access_token>\s*([A-Za-z0-9-_]{40})\s*</access_token>',
    'secret_key': r'<secret_key>\s*([A-Za-z0-9!@#$%^&*()_+={}\[\]:;,.<>?/~`|\\-]+)\s*</secret_key>',
    'ssh_key': r'<ssh_key>\s*([A-Za-z0-9+/=]{100,})\s*</ssh_key>',
    'api_secret': r'<api_secret>\s*([A-Za-z0-9!@#$%^&*()_+={}\[\]:;,.<>?/~`|\\-]+)\s*</api_secret>',
    'oauth_token': r'<oauth_token>\s*([A-Za-z0-9-_]{30,100})\s*</oauth_token>',
    'db_password': r'<db_password>\s*([A-Za-z0-9!@#$%^&*()_+={}\[\]:;,.<>?/~`|\\-]+)\s*</db_password>',
    'jwt_token': r'<jwt_token>\s*([A-Za-z0-9-_]{30,500})\s*</jwt_token>',
    'private_key': r'<private_key>\s*([A-Za-z0-9+/=]{200,})\s*</private_key>',
    'public_key': r'<public_key>\s*([A-Za-z0-9+/=]{200,})\s*</public_key>',
    'credit_card': r'<credit_card>\s*(\d{16})\s*</credit_card>',
    'ssn': r'<ssn>\s*(\d{3}-\d{2}-\d{4})\s*</ssn>',
    'phone_number': r'<phone_number>\s*(\+?\d{1,2}[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,4})\s*</phone_number>',
    'bank_account_number': r'<bank_account_number>\s*(\d{9,18})\s*</bank_account_number>',
    'card_number': r'<card_number>\s*(\d{13,19})\s*</card_number>',
    'license_key': r'<license_key>\s*([A-Za-z0-9-]+)\s*</license_key>',
    'user_token': r'<user_token>\s*([A-Za-z0-9-_]{20,50})\s*</user_token>',
    'session_id': r'<session_id>\s*([A-Za-z0-9]{16,64})\s*</session_id>',
    'api_url': r'<api_url>\s*(https?://[A-Za-z0-9.-]+(?:\.[A-Za-z]{2,6})?[^"\s]*)\s*</api_url>',
    'email_address': r'<email_address>\s*([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,})\s*</email_address>',
    'security_code': r'<security_code>\s*(\d{3,4})\s*</security_code>',
    'auth_token': r'<auth_token>\s*([A-Za-z0-9-_]{40,})\s*</auth_token>',
    'customer_id': r'<customer_id>\s*([A-Za-z0-9]{8,32})\s*</customer_id>',
    'credit_card_expiry': r'<credit_card_expiry>\s*(\d{2}/\d{2})\s*</credit_card_expiry>',
    'auth_code': r'<auth_code>\s*([A-Za-z0-9]{6,10})\s*</auth_code>',
    'otp_code': r'<otp_code>\s*(\d{6})\s*</otp_code>',
    'email_password': r'<email_password>\s*([A-Za-z0-9!@#$%^&*()_+={}\[\]:;,.<>?/~`|\\-]+)\s*</email_password>',
    'user_secret': r'<user_secret>\s*([A-Za-z0-9!@#$%^&*()_+={}\[\]:;,.<>?/~`|\\-]+)\s*</user_secret>',
    'private_key_data': r'<private_key_data>\s*([A-Za-z0-9+/=]{100,})\s*</private_key_data>',
    'public_key_data': r'<public_key_data>\s*([A-Za-z0-9+/=]{100,})\s*</public_key_data>',
    'server_password': r'<server_password>\s*([A-Za-z0-9!@#$%^&*()_+={}\[\]:;,.<>?/~`|\\-]+)\s*</server_password>',
    'login_token': r'<login_token>\s*([A-Za-z0-9-_]{30,100})\s*</login_token>',
    'api_auth_key': r'<api_auth_key>\s*([A-Za-z0-9!@#$%^&*()_+={}\[\]:;,.<>?/~`|\\-]+)\s*</api_auth_key>',
    'database_url': r'<database_url>\s*(https?://[A-Za-z0-9.-]+(?:\.[A-Za-z]{2,6})?[^"\s]*)\s*</database_url>',
    'firebase_key': r'<firebase_key>\s*([A-Za-z0-9-_]{40,})\s*</firebase_key>',
    'paypal_client_secret': r'<paypal_client_secret>\s*([A-Za-z0-9-_]{40,})\s*</paypal_client_secret>',
    'google_client_id': r'<google_client_id>\s*([A-Za-z0-9-.]{25,})\s*</google_client_id>',
    'google_client_secret': r'<google_client_secret>\s*([A-Za-z0-9-_]{30,})\s*</google_client_secret>',
    'stripe_api_key': r'<stripe_api_key>\s*([A-Za-z0-9]{24,45})\s*</stripe_api_key>',
    'aws_access_key': r'<aws_access_key>\s*([A-Za-z0-9]{20})\s*</aws_access_key>',
    'aws_secret_key': r'<aws_secret_key>\s*([A-Za-z0-9+/=]{40})\s*</aws_secret_key>',
    'discord_token': r'<discord_token>\s*([A-Za-z0-9-_]{24,36})\s*</discord_token>',
    'linkedin_api_key': r'<linkedin_api_key>\s*([A-Za-z0-9-_]{30,50})\s*</linkedin_api_key>',
    'zoom_api_key': r'<zoom_api_key>\s*([A-Za-z0-9]{32})\s*</zoom_api_key>',
    'paypal_api_key': r'<paypal_api_key>\s*([A-Za-z0-9]{24,45})\s*</paypal_api_key>',
    'azure_subscription_key': r'<azure_subscription_key>\s*([A-Za-z0-9]{32})\s*</azure_subscription_key>',
    'gitlab_token': r'<gitlab_token>\s*([A-Za-z0-9]{20,40})\s*</gitlab_token>',
    'salesforce_api_key': r'<salesforce_api_key>\s*([A-Za-z0-9]{32})\s*</salesforce_api_key>',
    'telegram_bot_token': r'<telegram_bot_token>\s*([A-Za-z0-9]{45})\s*</telegram_bot_token>',
    'bitcoin_private_key': r'<bitcoin_private_key>\s*([A-Za-z0-9]{51})\s*</bitcoin_private_key>',
    'bitbucket_api_key': r'<bitbucket_api_key>\s*([A-Za-z0-9-_]{36})\s*</bitbucket_api_key>',
    'webhook_secret': r'<webhook_secret>\s*([A-Za-z0-9]{32})\s*</webhook_secret>',
    'vpn_key': r'<vpn_key>\s*([A-Za-z0-9-_]{64})\s*</vpn_key>',
    'github_personal_access_token': r'<github_personal_access_token>\s*([A-Za-z0-9]{40})\s*</github_personal_access_token>',


    'asana_access_token': r'Authorization:\s*Bearer\s+([a-zA-Z0-9-_]{32,64})',
    'applicationinsights_api_key': r'x-api-key:\s*([a-zA-Z0-9-_]{32})',
    'bazaarvoice_passkey': r'conversationspasskey=([a-zA-Z0-9]{32})',
    'bitly_access_token': r'access_token=([a-zA-Z0-9]{32})',
    'branch_io_key': r'v1/app/([a-zA-Z0-9]{16})\?branch_secret=',
    'branch_io_secret': r'branch_secret=([a-zA-Z0-9]{32})',
    'buildkite_access_token': r'https://api\.buildkite\.com/v2/access-token',
    'contentful_space_id': r'https://cdn\.contentful\.com/spaces/([a-zA-Z0-9]{36})/entries',
    'contentful_access_token': r'access_token=([a-zA-Z0-9]{32,64})',
    'circleci_api_token': r'circle-token=([a-zA-Z0-9]{32})',
    'cypress_record_key': r'"recordKey":"([a-zA-Z0-9]{32})"',
    'cypress_project_id': r'"projectId":"([a-zA-Z0-9]{32})"',
    'flowdock_api_token': r'"flowdock_api_token"\s*:\s*"([a-f0-9]{32})"',
    'ethereum_private_key': r'ETHEREUM_PRIVATE_KEY\s*[:=]?\s*([a-f0-9]{64})',


    'MailChimp API Key': r"(?i)[0-9a-f]{32}-us[0-9]{1,2}",
    'DataDog API Key': r"(?i)datadog_api_key[:=]\s*['\"]?([a-zA-Z0-9]{32})['\"]?",
    'Heroku API Key': r"(?i)heroku_api_key[:=]\s*['\"]?([a-zA-Z0-9]{32})['\"]?",
    'Dropbox API Key': r"(?i)dropbox_api_key[:=]\s*['\"]?([a-zA-Z0-9]{15})['\"]?",
    'discord_bot_token_pattern' : r'[A-Za-z]{24}\.[A-Za-z]{6}\.[A-Za-z0-9_-]{27}',
    'dropbox_access_token_pattern' : r'sl\.[a-zA-Z0-9_-]{15,}',


    'CircleCI Token': r"(?i)circleci_token[:=]\s*['\"]?([a-zA-Z0-9]{20,40})['\"]?",
    'Travis CI Token': r"(?i)travis_token[:=]\s*['\"]?([a-zA-Z0-9]{40})['\"]?",
    'GitLab Personal Access Token': r"(?i)glpat-[a-zA-Z0-9-_]{20,40}",


    'rsa_private_key' : r'-----BEGIN RSA PRIVATE KEY-----',
    'ssh_dsa_private_key' : r'-----BEGIN DSA PRIVATE KEY-----',
    'ssh_dc_private_key' : r'-----BEGIN EC PRIVATE KEY-----',
    'pgp_private_block' : r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
    'Diffie-Hellman Parameters': r'-----BEGIN DH PARAMETERS-----',
    'PEM Certificate': r'-----BEGIN CERTIFICATE-----',

    #'json_web_token' : r'ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$',
    'slack_token' : r"\"api_token\":\"(xox[a-zA-Z]-[a-zA-Z0-9-]+)\"",
    'slack_webhook_pattern' : r'https://hooks.slack.com/services/[A-Za-z0-9]+/[A-Za-z0-9]+/[A-Za-z0-9]+',
    'slack_webhook_url': r'https:\/\/hooks\.slack\.com\/services\/([A-Z0-9]+\/[A-Z0-9]+\/[A-Z0-9]+)',
    'SSH_privKey' : r"([-]+BEGIN [^\s]+ PRIVATE KEY[-]+[\s]*[^-]*[-]+END [^\s]+ PRIVATE KEY[-]+)",
    
    #'Heroku API KEY' : r'\b(?:(?:heroku_)?[0-9a-fA-F]{32}|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\b',
    #'Heroku API KEY' : r'(?i)^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$',
    #'heroku_api_key_pattern' : r'(?i)heroku_[0-9a-fA-F]{32}',

    #'possible_Creds' : r"(?i)(" \
    #                r"password\s*[`=:\"]+\s*[^\s]+|" \
    #                r"password is\s*[`=:\"]*\s*[^\s]+|" \
    #                r"pwd\s*[`=:\"]*\s*[^\s]+|" \
    #                r"passwd\s*[`=:\"]+\s*[^\s]+)",
    #'password_pattern' : r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$',

    # encryption 
    #'Base64': r'^[A-Za-z0-9+/]+={0,2}$',

    # Variations of "key" in the context of secret keys or tokens
    'URL API Key': r"https?://[^\s]+[?&](api[-_]?key|key|token|access[-_]?token)=\"[^\"]+\"",
    # Passwords or other sensitive information in environment variables
    'Env_Var_Creds': r"(?i)(env\.(password|passwd|pwd|key|secret)\s*[:=]\s*[^\s]+)",
    # Email + Password combinations (often seen in user data dumps)
    # 'Email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?=\s|$)',
    'Email_Password': r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}:[^\s]+",

    # Custom patterns: e.g., secret keys
    #'Custom_Secret': r"(?i)(secret[-_]?(key)?|access[-_]?(key)?|secret\s*[:=]\s*[^\s]+)",
    # Common password patterns

    #'API_Key': r'(?i)(api_key|apikey|key|token|auth_token|access_token)[\s:=\'"]+\w{16,64}',
    'Bearer_Token': r'\bBearer\s+[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\b',
    
    # Common password hints or formats
    'Username_Password': r'\b(username|user|uname|login)[\s:=\'"]+[^\s]+[\s,;]+(pass|password|pwd|passwd)[\s:=\'"]+[^\s]+\b',
    
    # JWT Pattern (Common in CTFs for encoded data or tokens)
    'JWT': r'eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+',

    # cradit card  
    'Credit Card': r'^(?:4[0-9]{12}(?:[0-9]{3})?)$',


    'phone_number'           : r'^\+\d{1,3}\s?\d{4,14}$', # Matches international and US formats
    #'ipv4_address'           : r'\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\b', # Matches IPv4 addresses
    'http_true_client_ip'    : r'http_true_client_ip:\s*(\b(?:\d{1,3}\.){3}\d{1,3}\b)', # Custom header pattern for True-Client-IP
    'http_x_arr_log_id'      : r'http_x_arr_log_id:\s*[a-zA-Z0-9-]+', # Custom header pattern for X-ARR-LOG-ID


    'sha512_pattern' : r'\b[a-fA-F0-9]{128}\b',
    'sha512_base64_pattern' : r'\b[A-Za-z0-9+/]{86}==\b',
    'sha512_hex_pattern' : r'\b[a-fA-F0-9]{128}\b',
    'sha512_combined_pattern' : r'\b([a-fA-F0-9]{128}|[A-Za-z0-9+/]{86}==)\b',


    #'Hex_16': r'\b[0-9a-fA-F]{16}\b',
    #'Hex_24': r'\b[0-9a-fA-F]{24}\b',
    #'Hex_32': r'\b[0-9a-fA-F]{32}\b',
    #'Hex_40': r'\b[0-9a-fA-F]{40}\b',
    #'Hex_Encoded': r'\b[0-9a-fA-F]{32,}\b',
    #'Simple_Passphrase': r'\b(pass|password|pwd|passwd)[\s:=\'"]*\w+\b',
    #'sensitive_terms_pattern' : r"(?i)\b(api|access|auth|client|secret|key)[-_ ]?(token|id|key|secret|code)?\b",
    #'Hex_Encoded': r'\b[0-9a-fA-F]{32,}\b',
    #'API_Key': r"(?i)(api[-_]?key\s*[:=]\s*[^\s]+)",

    #'MD5': r'\b[a-fA-F0-9]{32}\b',
    #'Bcrypt': r'\$2[aby]?\$\d{2}\$[./A-Za-z0-9]{53}',
    #'SHA-1': r'\b[a-fA-F0-9]{40}\b',
    #'Bcrypt': r'\$2[aby]?\$\d{2}\$[./A-Za-z0-9]{53}',
}

def clone_and_scan_repo(repo_url):
    findings = []  # List to hold findings
    # Create a temporary directory to clone the repository
    with tempfile.TemporaryDirectory() as temp_dir:
        try:
            # Clone the repository
            git.Repo.clone_from(repo_url, temp_dir)
            print(f"Repository cloned to {temp_dir}")

            # Walk through the files in the cloned repository
            for root, dirs, files in os.walk(temp_dir):
                for file in files:
                    file_path = os.path.join(root, file)

                    # Only scan text-based files (skip binary files)
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            lines = f.readlines()

                            # Scan each line with regex patterns
                            for line_num, line in enumerate(lines, start=1):
                                for pattern_name, pattern in patterns.items():
                                    if re.search(pattern, line):
                                        findings.append({
                                            'pattern_name': pattern_name,
                                            'file_path': file_path,
                                            'line_num': line_num,
                                            'content': line.strip(),
                                        })
                    except (UnicodeDecodeError, IOError):
                        # Skip files that can't be read as text
                        continue
        except git.exc.GitError as e:
            print(f"Failed to clone repository: {e}")
    
    return findings
