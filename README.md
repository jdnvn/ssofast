# ssofast
Script to automate the aws sso process

## Setup
Clone this repo
```
git clone https://github.com/jdnvn/ssofast.git && cd ssofast
```

### Install dependencies
Install the requirements
```
pip install -r requirements.txt
```

Intall the AWS cli
https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html

### Okta credentials
Currently only supports SSO through Okta. There are two options for storing your credentials:

#### Dashlane
1. Make sure you have your Okta credentials stored in Dashlane under `okta.com`

2. Install the Dashlane CLI
https://dashlane.github.io/dashlane-cli/install

3. Sync Dashlane credentials
```
dcli sync
```

#### Add Okta credentials to .env (not recommended)
Add these environment variables to `.env`
```
OKTA_USERNAME=your-okta-username
OKTA_PASSWORD=your-okta-password
```

### Two-Factor Authentication
If your Okta login flow requires 2FA, you must provide a secret key in order for the script to retrieve your one-time password (OTP). You will only need to do this once.

This can be done by scanning the QR code generated from your authenticator application (ex: Google Authenticator) and reading the payload. I recommend the [QRBot app](https://qrbot.net/locale/en/), if you have an iPhone, as the iOS camera app does not give you the raw payload. The payload should be a URI that looks like this:
```
otpauth://totp/rando.okta.com%3Ajdnvn%40rando.com?secret=<your-secret-key>&issuer=rando.okta.com
```
Copy your secret key and store it as a variable in `.env`
```
OTP_SECRET_KEY=your-secret-key
```

## Usage
When running the script, you must provide either the AWS profile name or AWS SSO session name you want to log in with.

With --profile (or -p):
```
$ python run.py --profile joe
```

With --sso-session-name (or -s):
```
$ python run.py --sso-session-name sso
```

The script outputs logs by default. To silence the logs, add --quiet (or -q):
```
$ python run.py -q --sso-session-name sso
```
