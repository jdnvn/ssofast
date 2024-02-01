import pexpect
import os
import json
import argparse
import pyotp
import sys
from selenium import webdriver
from selenium.webdriver.common.by import By
from dotenv import load_dotenv

load_dotenv()

OTP_SECRET_KEY = os.environ.get('OTP_SECRET_KEY')
OKTA_USERNAME = os.environ.get('OKTA_USERNAME')
OKTA_PASSWORD = os.environ.get('OKTA_PASSWORD')

AWS_SSO_LOGIN_URL_REGEX = r"https://device\.sso\.us-east-1\.amazonaws\.com/\?user_code=.*"

class Logger:
  def __init__(self, quiet=False):
    self.quiet = quiet

  def log(self, info):
   if not self.quiet: print(f"\033[94m\033[1m{info}\033[0m")

  def error(self, error):
    print(f"\033[91m\033[1m{error}\033[0m")

def login(profile=None, sso_session_name=None, quiet=False):
  logger = Logger(quiet=quiet)

  if (not profile and not sso_session_name) or (profile and sso_session_name):
    logger.error('Must provide one of the following arguments [--profile, --sso-session-name]')
    sys.exit(1)
  if not OTP_SECRET_KEY:
    logger.error('Must have OTP_SECRET_KEY environment variable set')
    sys.exit(1)

  # run command and get the login url
  command = f"aws sso login {f'--profile {profile}' if profile else f'--sso-session {sso_session_name}'} --no-browser"
  logger.log(f"Running '{command}'")
  process = pexpect.spawn(command)
  process.expect(AWS_SSO_LOGIN_URL_REGEX)
  link = process.after.decode()

  logger.log("Starting up Chrome in headless mode...")
  options = webdriver.ChromeOptions()
  options.add_argument("--headless")
  driver = webdriver.Chrome(options=options)

  # open login url
  logger.log("Opening login URL...")
  driver.get(link)

  # Verify Button click - need to wait a bit before unless it can't find it
  driver.implicitly_wait(5)
  driver.find_element(By.ID, "cli_verification_btn").click()

  logger.log("Logging into Okta...")
  if OKTA_USERNAME and OKTA_PASSWORD:
    okta_username = OKTA_USERNAME
    okta_password = OKTA_PASSWORD
  else:
    # grab okta username and password from dashlane
    output = os.popen("dcli p okta.com -o json").read()
    okta_creds = json.loads(output)[0]
    okta_username = okta_creds["login"]
    okta_password = okta_creds["password"]

  # enter okta credentials
  driver.find_element(By.ID, "okta-signin-username").send_keys(okta_username)
  driver.find_element(By.ID, "okta-signin-password").send_keys(okta_password)
  driver.find_element(By.ID, "okta-signin-submit").click()

  # 2FA
  logger.log("2FA, kinda...")
  totp = pyotp.totp.TOTP(OTP_SECRET_KEY)
  otp = totp.now()

  # enter one time password
  otp_input_field = driver.find_element(By.NAME, "answer")
  otp_input_field.send_keys(otp)
  otp_verify_btn = driver.find_element(By.XPATH, "//input[contains(@value, 'Verify')]")
  otp_verify_btn.click()

  # Allow button click
  logger.log("Allowing AWS login...")
  driver.find_element(By.ID, "cli_login_button")
  driver.refresh()
  login_btn = driver.find_element(By.ID, "cli_login_button")
  login_btn.click()

  process.expect(pexpect.EOF)

  logger.log("\nDone.")

if __name__ == "__main__":
  parser = argparse.ArgumentParser()
  parser.add_argument("--profile", "-p", help="AWS profile name", required=False)
  parser.add_argument("--sso-session-name", "-s", help="AWS SSO session name", required=False)
  parser.add_argument("--quiet", "-q", help="Does not print steps", default=False, action='store_true')

  args, _ = parser.parse_known_args()
  login(profile=args.profile, sso_session_name=args.sso_session_name, quiet=args.quiet)
